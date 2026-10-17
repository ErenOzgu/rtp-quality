package synth

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Datagram is one UDP datagram with its capture time (ns since the epoch).
type Datagram struct {
	Time     int64
	Src, Dst netip.AddrPort
	Payload  []byte
}

// Codec is how a synthetic stream is packed.
type Codec struct {
	Name      string
	PT        uint8
	ClockRate int
	// bytes in one packet of ptime milliseconds
	bytes func(ptime int) int
}

// Codecs that gen can produce. Payload bytes are zeros or a ramp: the analyzer never listens.
var Codecs = map[string]Codec{
	"PCMU": {"PCMU", 0, 8000, func(p int) int { return p * 8 }},
	"PCMA": {"PCMA", 8, 8000, func(p int) int { return p * 8 }},
	"GSM":  {"GSM", 3, 8000, func(p int) int { return (p + 19) / 20 * 33 }},
	"G722": {"G722", 9, 8000, func(p int) int { return p * 8 }},
	"G729": {"G729", 18, 8000, func(p int) int { return (p + 9) / 10 * 10 }},
}

// CodecNames lists what gen accepts, sorted.
func CodecNames() string {
	var n []string
	for k := range Codecs {
		n = append(n, k)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// EventPT is the payload type used for telephone-event packets.
const EventPT = 101

// Stream describes one direction of a call.
type Stream struct {
	Src, Dst netip.AddrPort
	SSRC     uint32
	Codec    Codec
	PtimeMs  int
	// Start is the send time of the first packet, ns since the epoch.
	Start       int64
	DurationSec float64
	StartSeq    uint16
	StartTS     uint32

	// What the network does to it.
	DelayMs   float64 // fixed one-way delay
	JitterMs  float64 // extra delay, uniform in [0, JitterMs]
	LossPct   float64 // long-run packet loss
	MeanBurst float64 // average length of a loss run; 1 or less means random loss
	ReorderPc float64 // percent of packets held back
	ReorderMs float64 // how long a held-back packet is delayed
	DupPc     float64 // percent of packets delivered twice

	// DTMFAt lists send times (seconds from the start) of telephone-event digits.
	DTMFAt []float64

	Seed uint64
}

// Validate says what is wrong with a description, if anything.
func (s *Stream) Validate() error {
	switch {
	case s.Codec.Name == "":
		return fmt.Errorf("no codec")
	case s.PtimeMs < 5 || s.PtimeMs > 120:
		return fmt.Errorf("ptime %d ms is outside 5..120", s.PtimeMs)
	case s.DurationSec <= 0:
		return fmt.Errorf("duration must be positive")
	case s.LossPct < 0 || s.LossPct >= 100:
		return fmt.Errorf("loss %.1f%% is outside 0..100", s.LossPct)
	case s.ReorderPc < 0 || s.ReorderPc > 100 || s.DupPc < 0 || s.DupPc > 100:
		return fmt.Errorf("reorder and duplicate percentages must be within 0..100")
	case s.JitterMs < 0 || s.DelayMs < 0 || s.ReorderMs < 0:
		return fmt.Errorf("delays must not be negative")
	case !s.Src.IsValid() || !s.Dst.IsValid():
		return fmt.Errorf("source and destination addresses are required")
	}
	return nil
}

// Generate returns the datagrams the capture point sees, ordered by arrival.
func (s *Stream) Generate() ([]Datagram, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	rnd := NewRand(s.Seed ^ uint64(s.SSRC)<<17)
	n := int(s.DurationSec * 1000 / float64(s.PtimeMs))
	tsStep := uint32(s.PtimeMs * s.Codec.ClockRate / 1000)
	payload := make([]byte, s.Codec.bytes(s.PtimeMs))
	for i := range payload {
		payload[i] = byte(i)
	}

	// Gilbert loss model: a good and a bad state, packets in the bad state are lost.
	// The mean stay in the bad state is MeanBurst packets; the entry rate is chosen
	// so the long-run loss is LossPct.
	var pGB, pBG float64
	if s.LossPct > 0 {
		pBG = 1
		if s.MeanBurst > 1 {
			pBG = 1 / s.MeanBurst
		}
		l := s.LossPct / 100
		pGB = l * pBG / (1 - l)
		if pGB > 1 {
			pGB = 1
		}
	}
	bad := false

	var out []Datagram
	seq := s.StartSeq
	eventUntil := -1 // slot index up to which the current digit runs
	eventStartTS := uint32(0)
	eventPkts := 0
	nextDigit := 0
	afterEvent := false
	for i := 0; i < n; i++ {
		sendT := s.Start + int64(float64(i*s.PtimeMs)*1e6)
		sec := float64(i*s.PtimeMs) / 1000
		if eventUntil < i && nextDigit < len(s.DTMFAt) && sec >= s.DTMFAt[nextDigit] {
			// A digit lasts five packets: three while it is held, then the end packet three times.
			eventUntil = i + 4
			eventStartTS = s.StartTS + uint32(i)*tsStep
			eventPkts = 0
			nextDigit++
		}

		var hdr [12]byte
		hdr[0] = 0x80
		var body []byte
		if i <= eventUntil {
			eventPkts++
			hdr[1] = EventPT
			if eventPkts == 1 {
				hdr[1] |= 0x80
			}
			binary.BigEndian.PutUint32(hdr[4:], eventStartTS)
			end := byte(0)
			if eventPkts > 2 {
				end = 0x80
			}
			dur := uint16(eventPkts*s.PtimeMs) * uint16(s.Codec.ClockRate/1000)
			body = []byte{byte(1), end | 10, byte(dur >> 8), byte(dur)}
			afterEvent = true
		} else {
			hdr[1] = s.Codec.PT
			if i == 0 || afterEvent {
				hdr[1] |= 0x80 // marker: first packet of a talkspurt
				afterEvent = false
			}
			binary.BigEndian.PutUint32(hdr[4:], s.StartTS+uint32(i)*tsStep)
			body = payload
		}
		binary.BigEndian.PutUint16(hdr[2:], seq)
		binary.BigEndian.PutUint32(hdr[8:], s.SSRC)
		seq++

		// Loss decision (the packet still used up its sequence number).
		if bad {
			if rnd.Float64() < pBG {
				bad = false
			}
		} else if rnd.Float64() < pGB {
			bad = true
		}
		// A packet that enters the bad state is lost, and so is every one until it leaves.
		if bad {
			continue
		}

		delay := s.DelayMs + rnd.Float64()*s.JitterMs
		if s.ReorderPc > 0 && rnd.Float64()*100 < s.ReorderPc {
			delay += s.ReorderMs
		}
		pkt := append(append([]byte(nil), hdr[:]...), body...)
		arrive := sendT + int64(delay*1e6)
		out = append(out, Datagram{Time: arrive, Src: s.Src, Dst: s.Dst, Payload: pkt})
		if s.DupPc > 0 && rnd.Float64()*100 < s.DupPc {
			out = append(out, Datagram{Time: arrive + 1_000_000, Src: s.Src, Dst: s.Dst, Payload: pkt})
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Time < out[b].Time })
	return out, nil
}

// Merge combines several captures into one, ordered by time.
func Merge(parts ...[]Datagram) []Datagram {
	var all []Datagram
	for _, p := range parts {
		all = append(all, p...)
	}
	sort.SliceStable(all, func(a, b int) bool { return all[a].Time < all[b].Time })
	return all
}
