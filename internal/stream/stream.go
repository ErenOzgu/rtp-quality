// Package stream turns RTP packets, in capture order, into per-stream quality
// figures: loss, duplicates, reordering, interarrival jitter (RFC 3550) and an
// E-model estimate of call quality.
package stream

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/ErenOzgu/rtp-quality/internal/capture"
	"github.com/ErenOzgu/rtp-quality/internal/codec"
	"github.com/ErenOzgu/rtp-quality/internal/emodel"
	"github.com/ErenOzgu/rtp-quality/internal/rtp"
)

// Sequence number bookkeeping constants from RFC 3550 appendix A.1.
const (
	maxDropout  = 3000
	maxMisorder = 100
	seqMod      = 1 << 16
	// A packet may arrive this far before the first one that was seen
	// (reordering at the very start of a stream).
	headroom = 128
	// Flows that have not yet proved to be RTP are remembered up to this many;
	// beyond that the list is dropped, which only happens on noisy captures.
	maxCandidates = 50000
	// How far apart, in sequence numbers, the first packets of a new flow may be.
	probationWindow = 100
)

// Config controls the analysis.
type Config struct {
	// Probation is how many packets with consecutive sequence numbers a flow
	// needs before it counts as RTP. Default 3.
	Probation int
	// PlayoutMs is the fixed jitter buffer assumed when deciding which packets
	// arrived too late to be played. 0 turns the simulation off.
	PlayoutMs float64
	// NetworkDelayMs is added to the one-way delay in the E-model.
	NetworkDelayMs float64
	// Payloads overrides the codec table (dynamic payload types).
	Payloads map[uint8]codec.Info
}

// DefaultConfig is what the command line starts from.
func DefaultConfig() Config { return Config{Probation: 3, PlayoutMs: 60} }

// Key identifies a stream: one direction of one media flow with one SSRC.
type Key struct {
	Src, Dst netip.AddrPort
	SSRC     uint32
}

// Analyzer collects streams from packets.
type Analyzer struct {
	cfg        Config
	candidates map[Key]*candidate
	active     map[Key]*state
	done       []*state
	segments   map[Key]int
	// NonRTP counts UDP datagrams that did not look like RTP at all.
	NonRTP int
	// Dropped counts packets ignored as sequence outliers (RFC 3550 A.1).
	Dropped int
}

type pending struct {
	h      rtp.Header
	t      int64
	udpLen int
	cut    bool
}

type candidate struct{ pkts []pending }

// New returns an empty analyzer.
func New(cfg Config) *Analyzer {
	if cfg.Probation < 1 {
		cfg.Probation = 1
	}
	return &Analyzer{
		cfg:        cfg,
		candidates: map[Key]*candidate{},
		active:     map[Key]*state{},
		segments:   map[Key]int{},
	}
}

// Add feeds one UDP datagram.
func (a *Analyzer) Add(p capture.Packet) {
	h, ok := rtp.Parse(p.Payload, p.UDPLen)
	if !ok {
		a.NonRTP++
		return
	}
	key := Key{p.Src, p.Dst, h.SSRC}
	pk := pending{h: h, t: p.Time, udpLen: p.UDPLen, cut: len(p.Payload) < p.UDPLen}
	if s, ok := a.active[key]; ok {
		a.feed(key, s, pk)
		return
	}
	c := a.candidates[key]
	if c == nil {
		if len(a.candidates) >= maxCandidates {
			a.candidates = map[Key]*candidate{}
		}
		c = &candidate{}
		a.candidates[key] = c
	}
	if !c.accept(pk) {
		c.pkts = c.pkts[:0]
	}
	c.pkts = append(c.pkts, pk)
	if c.distinct() >= a.cfg.Probation {
		s := a.open(key)
		for _, q := range c.pkts {
			s.add(q)
		}
		delete(a.candidates, key)
	}
}

// accept says whether a packet fits the flow candidate so far: its sequence number is close to
// the first one's, in either direction. Reordering at the start of a stream is normal, so unlike
// the receiver in RFC 3550 appendix A.1 this does not insist on arrival in sequence order.
func (c *candidate) accept(pk pending) bool {
	if len(c.pkts) == 0 {
		return true
	}
	d := pk.h.Seq - c.pkts[0].h.Seq
	return d <= probationWindow || d >= seqMod-probationWindow
}

// distinct counts the different sequence numbers seen; a duplicate does not prove a stream.
func (c *candidate) distinct() int {
	seen := make(map[uint16]struct{}, len(c.pkts))
	for _, p := range c.pkts {
		seen[p.h.Seq] = struct{}{}
	}
	return len(seen)
}

func (a *Analyzer) open(key Key) *state {
	a.segments[key]++
	s := newState(key, a.segments[key], a.cfg)
	a.active[key] = s
	return s
}

func (a *Analyzer) feed(key Key, s *state, pk pending) {
	switch s.add(pk) {
	case resultRestart:
		// The sender restarted its sequence numbers: close this stream, begin a new one.
		a.done = append(a.done, s)
		n := a.open(key)
		if s.hasStray { // the packet that raised the doubt is the first of the new segment
			a.Dropped--
			n.add(s.stray)
		}
		n.add(pk)
	case resultDropped:
		a.Dropped++
	}
}

// Results finishes the analysis and returns every stream that has at least
// minPackets packets, ordered by first packet, plus how many were left out.
func (a *Analyzer) Results(minPackets int) (out []Result, short int) {
	all := append([]*state(nil), a.done...)
	for _, s := range a.active {
		all = append(all, s)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].first != all[j].first {
			return all[i].first < all[j].first
		}
		return all[i].key.SSRC < all[j].key.SSRC
	})
	for _, s := range all {
		r := s.result()
		if r.Packets < minPackets {
			short++
			continue
		}
		out = append(out, r)
	}
	return out, short
}

type addResult int

const (
	resultOK addResult = iota
	resultRestart
	resultDropped
)

// ptState is the per-payload-type timing state. Speech and DTMF share an SSRC
// and a sequence space but not a timestamp rhythm, so they are timed apart.
type ptState struct {
	info  codec.Info
	count int

	havePrev bool
	prevArr  float64 // seconds since the stream's first packet
	prevTS   uint32
	tsExt    int64
	jitter   float64 // in timestamp units
	jitMax   float64
	jitSum   float64
	jitN     int

	intervalSum, intervalMax float64
	intervalN                int

	minTransit float64
	haveMin    bool

	deltas  map[int64]int
	lastSeq uint16
}

type state struct {
	cfg     Config
	key     Key
	segment int

	first, last int64
	started     bool

	stray          pending
	hasStray       bool
	cycles         int64
	maxSeq         uint16
	badSeq         int64
	firstExt       int64
	minExt, maxExt int64
	off            int64
	present        bitset
	usable         bitset

	received, dups, reordered, late, truncated int
	bytes                                      int64
	pts                                        map[uint8]*ptState
}

func newState(key Key, segment int, cfg Config) *state {
	return &state{cfg: cfg, key: key, segment: segment, badSeq: -1, pts: map[uint8]*ptState{}}
}

// add updates the stream with one packet and says whether it belongs to it.
func (s *state) add(pk pending) addResult {
	h := pk.h
	var ext int64
	if !s.started {
		s.started = true
		s.first = pk.t
		s.maxSeq = h.Seq
		ext = int64(h.Seq)
		s.firstExt, s.minExt, s.maxExt = ext, ext, ext
		s.off = ext - headroom
	} else {
		delta := h.Seq - s.maxSeq // uint16 arithmetic
		switch {
		case delta < maxDropout:
			if h.Seq < s.maxSeq {
				s.cycles += seqMod // the sequence number wrapped
			}
			s.maxSeq = h.Seq
			ext = s.cycles + int64(h.Seq)
		case delta <= seqMod-maxMisorder:
			// A big jump: a restart, or one stray packet. Two in a row mean a restart.
			if s.badSeq == int64(h.Seq) {
				return resultRestart
			}
			s.badSeq = int64(h.Seq+1) & (seqMod - 1)
			s.stray, s.hasStray = pk, true
			return resultDropped
		default:
			// A little behind the highest sequence number: reordering or a duplicate.
			if h.Seq > s.maxSeq {
				ext = s.cycles - seqMod + int64(h.Seq)
			} else {
				ext = s.cycles + int64(h.Seq)
			}
		}
		s.badSeq = -1
	}
	s.last = pk.t
	if pk.cut {
		s.truncated++
	}

	idx := int(ext - s.off)
	if idx < 0 { // arrived long before anything the stream has seen: cannot be placed
		s.reordered++
		return resultOK
	}
	if s.present.get(idx) {
		s.dups++
		return resultOK
	}
	s.present.set(idx)
	s.received++
	s.bytes += int64(h.PayloadLen)
	if ext < s.maxExt {
		s.reordered++
	}
	if ext > s.maxExt {
		s.maxExt = ext
	}
	if ext < s.minExt {
		s.minExt = ext
	}

	p := s.pts[h.PayloadType]
	if p == nil {
		info := codec.Lookup(h.PayloadType, s.cfg.Payloads)
		// A dynamic payload type nobody described: tiny packets are DTMF events or
		// comfort noise (RFC 4733 events are 4 bytes), anything bigger is speech.
		if !info.Known && h.PayloadLen <= 4 {
			info.Audio = false
		}
		p = &ptState{info: info, deltas: map[int64]int{}}
		s.pts[h.PayloadType] = p
	}
	p.count++
	late := s.timing(p, h, pk.t, ext)
	if late {
		s.late++
	} else {
		s.usable.set(idx)
	}
	return resultOK
}

// timing updates jitter and the playout simulation; it reports whether the
// packet arrived too late for the assumed jitter buffer.
func (s *state) timing(p *ptState, h rtp.Header, t int64, ext int64) bool {
	if !p.info.Audio {
		return false
	}
	rate := float64(p.info.ClockRate)
	arr := float64(t-s.first) / 1e9
	if !p.havePrev {
		p.havePrev = true
		p.prevArr, p.prevTS, p.lastSeq = arr, h.Timestamp, h.Seq
		p.minTransit, p.haveMin = arr, true
		return false
	}
	dts := int64(int32(h.Timestamp - p.prevTS)) // wraps correctly in both directions
	p.tsExt += dts

	// Interarrival jitter, RFC 3550 section 6.4.1. A packet that opens a talkspurt
	// (marker bit) has a timestamp jump that says nothing about the network.
	d := (arr-p.prevArr)*rate - float64(dts)
	if !h.Marker && math.Abs(d) < 3600*rate {
		p.jitter += (math.Abs(d) - p.jitter) / 16
		if p.jitter > p.jitMax {
			p.jitMax = p.jitter
		}
		p.jitSum += p.jitter
		p.jitN++
	}
	gap := arr - p.prevArr
	if gap >= 0 {
		p.intervalSum += gap
		p.intervalN++
		if gap > p.intervalMax {
			p.intervalMax = gap
		}
	}
	if h.Seq == p.lastSeq+1 && dts > 0 {
		p.deltas[dts]++
	}
	p.prevArr, p.prevTS, p.lastSeq = arr, h.Timestamp, h.Seq

	// Playout simulation: a fixed jitter buffer measured from the least delayed
	// packet seen so far.
	transit := arr - float64(p.tsExt)/rate
	if !p.haveMin || transit < p.minTransit {
		p.minTransit, p.haveMin = transit, true
	}
	return s.cfg.PlayoutMs > 0 && (transit-p.minTransit)*1000 > s.cfg.PlayoutMs
}

// Result is the finished picture of one stream.
type Result struct {
	Src, Dst string
	SSRC     uint32
	Segment  int // 2 and up when the same SSRC restarted its sequence numbers

	PayloadType int
	Codec       string
	ClockRate   int
	CodecKnown  bool

	First, Last time.Time
	DurationSec float64

	Packets       int // distinct packets received
	Expected      int // by sequence numbers, first to last
	Lost          int // never arrived
	Duplicates    int
	Reordered     int
	LateDiscarded int // arrived, but later than the assumed jitter buffer allows
	Truncated     int // captured shorter than they were on the wire
	OtherPackets  int // of another payload type than the main one (DTMF, comfort noise)

	LossPercent          float64 // Lost / Expected
	EffectiveLossPercent float64 // (Lost + LateDiscarded) / Expected: what the listener loses
	MeanBurst            float64 // average length of a run of lost packets
	MaxBurst             int
	BurstRatio           float64

	JitterMeanMs   float64
	JitterMaxMs    float64
	IntervalMeanMs float64
	IntervalMaxMs  float64
	PtimeMs        float64
	BitrateKbps    float64

	PlayoutMs float64
	RFactor   *float64 // nil when the codec has no published E-model values
	MOS       *float64
	Rating    string
	Note      string
}

func (s *state) result() Result {
	r := Result{
		Src: s.key.Src.String(), Dst: s.key.Dst.String(), SSRC: s.key.SSRC, Segment: s.segment,
		First: time.Unix(0, s.first).UTC(), Last: time.Unix(0, s.last).UTC(),
		Packets: s.received, Duplicates: s.dups, Reordered: s.reordered, LateDiscarded: s.late,
		Truncated: s.truncated, PlayoutMs: s.cfg.PlayoutMs,
	}
	r.DurationSec = float64(s.last-s.first) / 1e9
	r.Expected = int(s.maxExt-s.minExt) + 1
	r.Lost = r.Expected - s.received
	if r.Lost < 0 {
		r.Lost = 0
	}

	// Which payload type is the stream? The audio one with the most packets.
	var main *ptState
	var mainPT uint8
	for pt, p := range s.pts {
		better := main == nil ||
			(p.info.Audio && !main.info.Audio) ||
			(p.info.Audio == main.info.Audio && (p.count > main.count || (p.count == main.count && pt < mainPT)))
		if better {
			main, mainPT = p, pt
		}
	}
	if main == nil {
		return r
	}
	r.PayloadType, r.Codec, r.ClockRate, r.CodecKnown = int(mainPT), main.info.Name, main.info.ClockRate, main.info.Known
	r.OtherPackets = s.received - main.count
	if main.jitN > 0 {
		r.JitterMeanMs = tidy(main.jitSum / float64(main.jitN) / float64(main.info.ClockRate) * 1000)
	}
	r.JitterMaxMs = tidy(main.jitMax / float64(main.info.ClockRate) * 1000)
	if main.intervalN > 0 {
		r.IntervalMeanMs = main.intervalSum / float64(main.intervalN) * 1000
	}
	r.IntervalMaxMs = main.intervalMax * 1000
	var bestN int
	var bestDelta int64
	for d, n := range main.deltas {
		if n > bestN || (n == bestN && d < bestDelta) {
			bestDelta, bestN = d, n
		}
	}
	if bestN > 0 {
		r.PtimeMs = float64(bestDelta) / float64(main.info.ClockRate) * 1000
	}
	if r.DurationSec > 0 {
		r.BitrateKbps = float64(s.bytes) * 8 / r.DurationSec / 1000
	}

	// Loss as the listener sees it, and how bursty it is, from the packets that were usable.
	lostRuns, lostTotal, maxRun, run := 0, 0, 0, 0
	for e := s.minExt; e <= s.maxExt; e++ {
		if s.usable.get(int(e - s.off)) {
			run = 0
			continue
		}
		lostTotal++
		if run == 0 {
			lostRuns++
		}
		run++
		if run > maxRun {
			maxRun = run
		}
	}
	r.MaxBurst = maxRun
	r.BurstRatio = 1
	if r.Expected > 0 {
		r.LossPercent = 100 * float64(r.Lost) / float64(r.Expected)
		r.EffectiveLossPercent = 100 * float64(lostTotal) / float64(r.Expected)
	}
	if lostRuns > 0 {
		r.MeanBurst = float64(lostTotal) / float64(lostRuns)
		p := float64(lostTotal) / float64(r.Expected)
		if p < 1 {
			if br := r.MeanBurst * (1 - p); br > 1 { // random loss has bursts of 1/(1-p) on average
				r.BurstRatio = br
			}
		}
	}

	switch {
	case !main.info.HasModel:
		r.Note = fmt.Sprintf("no E-model values for %s, so no MOS", main.info.Name)
	case r.Expected < 2:
		r.Note = "too few packets for a quality estimate"
	default:
		ptime := r.PtimeMs
		if ptime == 0 {
			ptime = 20
		}
		delay := ptime + main.info.Lookahead + s.cfg.PlayoutMs + s.cfg.NetworkDelayMs
		rf := emodel.RFactor(emodel.Params{
			Ie: main.info.Ie, Bpl: main.info.Bpl, LossPercent: r.EffectiveLossPercent,
			BurstR: r.BurstRatio, DelayMs: delay,
		})
		mos := emodel.MOS(rf)
		r.RFactor, r.MOS, r.Rating = &rf, &mos, emodel.Rating(rf)
	}
	return r
}

// tidy turns the rounding noise of float arithmetic (1e-16 ms of "jitter" on a
// perfectly steady stream) into a clean zero.
func tidy(v float64) float64 {
	if math.Abs(v) < 1e-9 {
		return 0
	}
	return v
}
