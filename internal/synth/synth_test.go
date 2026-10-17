package synth_test

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/synth"
)

func stream() synth.Stream {
	return synth.Stream{
		Src: netip.MustParseAddrPort("192.0.2.1:1000"), Dst: netip.MustParseAddrPort("192.0.2.2:2000"),
		SSRC: 1, Codec: synth.Codecs["PCMU"], PtimeMs: 20, Start: 1e18, DurationSec: 100, Seed: 3,
	}
}

func TestDeterministic(t *testing.T) {
	s := stream()
	s.LossPct, s.MeanBurst, s.JitterMs, s.ReorderPc, s.ReorderMs, s.DupPc = 5, 3, 20, 3, 30, 2
	a, _ := s.Generate()
	b, _ := s.Generate()
	if len(a) != len(b) {
		t.Fatal("different lengths")
	}
	for i := range a {
		if a[i].Time != b[i].Time || string(a[i].Payload) != string(b[i].Payload) {
			t.Fatalf("packet %d differs", i)
		}
	}
	s.Seed++
	c, _ := s.Generate()
	same := len(a) == len(c)
	for i := 0; same && i < len(a); i++ {
		same = a[i].Time == c[i].Time
	}
	if same {
		t.Error("another seed gave the same stream")
	}
}

func TestArrivalOrderAndSequenceNumbers(t *testing.T) {
	s := stream()
	s.JitterMs = 50
	d, _ := s.Generate()
	if !sort.SliceIsSorted(d, func(i, j int) bool { return d[i].Time < d[j].Time }) {
		t.Error("not ordered by arrival time")
	}
	seen := map[uint16]bool{}
	for _, p := range d {
		seen[binary.BigEndian.Uint16(p.Payload[2:])] = true
	}
	if len(seen) != 5000 {
		t.Errorf("%d distinct sequence numbers, want 5000", len(seen))
	}
}

func TestLossRateAndBurstLength(t *testing.T) {
	for _, burst := range []float64{1, 4} {
		s := stream()
		s.DurationSec = 1200 // 60000 packets: fewer than the sequence space, so no wrap
		s.LossPct, s.MeanBurst = 10, burst
		d, _ := s.Generate()
		got := make(map[uint16]bool, len(d))
		for _, p := range d {
			got[binary.BigEndian.Uint16(p.Payload[2:])] = true
		}
		total := int(s.DurationSec * 50)
		lost, runs, run := 0, 0, 0
		for i := 0; i < total; i++ {
			if !got[uint16(i)] {
				lost++
				if run == 0 {
					runs++
				}
				run++
			} else {
				run = 0
			}
		}
		pct := 100 * float64(lost) / float64(total)
		if pct < 9 || pct > 11 {
			t.Errorf("burst %v: loss %.2f %%, want about 10", burst, pct)
		}
		mean := float64(lost) / float64(runs)
		// random loss at 10 % has runs of 1/(1-0.1) = 1.11 on average
		want := burst
		if burst == 1 {
			want = 1.11
		}
		if mean < want*0.85 || mean > want*1.15 {
			t.Errorf("burst %v: mean run %.2f, want about %.2f", burst, mean, want)
		}
	}
}

func TestValidate(t *testing.T) {
	for name, mod := range map[string]func(*synth.Stream){
		"no codec":        func(s *synth.Stream) { s.Codec = synth.Codec{} },
		"ptime too small": func(s *synth.Stream) { s.PtimeMs = 1 },
		"ptime too big":   func(s *synth.Stream) { s.PtimeMs = 500 },
		"zero duration":   func(s *synth.Stream) { s.DurationSec = 0 },
		"loss 100":        func(s *synth.Stream) { s.LossPct = 100 },
		"negative jitter": func(s *synth.Stream) { s.JitterMs = -1 },
		"reorder 200":     func(s *synth.Stream) { s.ReorderPc = 200 },
		"no addresses":    func(s *synth.Stream) { s.Src = netip.AddrPort{} },
	} {
		s := stream()
		mod(&s)
		if _, err := s.Generate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPayloadSizes(t *testing.T) {
	for name, want := range map[string]int{"PCMU": 160, "PCMA": 160, "G722": 160, "G729": 20, "GSM": 33} {
		s := stream()
		s.Codec = synth.Codecs[name]
		s.DurationSec = 1
		d, _ := s.Generate()
		if got := len(d[0].Payload) - 12; got != want {
			t.Errorf("%s: %d payload bytes, want %d", name, got, want)
		}
	}
}

func TestChecksums(t *testing.T) {
	sum := func(b []byte) uint16 {
		var s uint32
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(b[i])<<8 | uint32(b[i+1])
		}
		for s>>16 != 0 {
			s = s&0xffff + s>>16
		}
		return uint16(s)
	}
	d := synth.Datagram{Src: netip.MustParseAddrPort("10.1.2.3:1111"), Dst: netip.MustParseAddrPort("10.4.5.6:2222"), Payload: []byte{1, 2, 3, 4, 5}}
	ip := synth.IPPacket(d)
	if sum(ip[:20]) != 0xffff {
		t.Errorf("IPv4 header checksum does not verify: %#04x", sum(ip[:20]))
	}
	// IPv6: the UDP checksum covers a pseudo-header and must verify to all ones.
	d6 := synth.Datagram{Src: netip.MustParseAddrPort("[2001:db8::1]:1111"), Dst: netip.MustParseAddrPort("[2001:db8::2]:2222"), Payload: []byte{1, 2, 3, 4, 5, 6}}
	ip6 := synth.IPPacket(d6)
	udp := ip6[40:]
	pseudo := append(append([]byte(nil), ip6[8:40]...), 0, 0, 0, byte(len(udp)), 0, 0, 0, 17)
	if got := sum(append(pseudo, udp...)); got != 0xffff {
		t.Errorf("IPv6 UDP checksum does not verify: %#04x", got)
	}
}

func TestWriteRejectsMixedVersions(t *testing.T) {
	d := synth.Datagram{Src: netip.MustParseAddrPort("10.0.0.1:1"), Dst: netip.MustParseAddrPort("[::1]:2")}
	if err := synth.Write(discard{}, []synth.Datagram{d}, synth.Options{}); err == nil {
		t.Error("mixed IP versions accepted")
	}
}

type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }
