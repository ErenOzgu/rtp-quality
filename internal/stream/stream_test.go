package stream_test

import (
	"math"
	"net/netip"
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/capture"
	"github.com/ErenOzgu/rtp-quality/internal/codec"
	"github.com/ErenOzgu/rtp-quality/internal/stream"
	"github.com/ErenOzgu/rtp-quality/internal/synth"
)

var (
	a = netip.MustParseAddrPort("10.0.0.1:10000")
	b = netip.MustParseAddrPort("10.0.0.2:20000")
)

func base() synth.Stream {
	return synth.Stream{
		Src: a, Dst: b, SSRC: 0x1234, Codec: synth.Codecs["PCMU"], PtimeMs: 20,
		Start: 1_700_000_000_000_000_000, DurationSec: 20, StartSeq: 100, StartTS: 4000, Seed: 7,
	}
}

func analyze(t *testing.T, cfg stream.Config, ds ...synth.Datagram) []stream.Result {
	t.Helper()
	an := stream.New(cfg)
	for _, d := range ds {
		an.Add(capture.Packet{Time: d.Time, Src: d.Src, Dst: d.Dst, Payload: d.Payload, UDPLen: len(d.Payload)})
	}
	res, _ := an.Results(1)
	return res
}

func run(t *testing.T, s synth.Stream, cfg stream.Config) stream.Result {
	t.Helper()
	ds, err := s.Generate()
	if err != nil {
		t.Fatal(err)
	}
	res := analyze(t, cfg, ds...)
	if len(res) != 1 {
		t.Fatalf("got %d streams, want 1", len(res))
	}
	return res[0]
}

func near(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %.4f, want %.4f ± %.4f", name, got, want, tol)
	}
}

func TestCleanCall(t *testing.T) {
	r := run(t, base(), stream.DefaultConfig())
	if r.Packets != 1000 || r.Expected != 1000 || r.Lost != 0 || r.Duplicates != 0 || r.Reordered != 0 || r.LateDiscarded != 0 {
		t.Fatalf("clean stream: %+v", r)
	}
	if r.Codec != "PCMU" || r.PayloadType != 0 || r.ClockRate != 8000 {
		t.Errorf("codec: %s pt=%d clock=%d", r.Codec, r.PayloadType, r.ClockRate)
	}
	near(t, "ptime", r.PtimeMs, 20, 1e-9)
	near(t, "jitter", r.JitterMeanMs, 0, 1e-6)
	near(t, "bitrate kbit/s", r.BitrateKbps, 64, 0.5)
	// 20 ms packets + 60 ms playout = 80 ms one way: R = 93.2 - 0.024*80.
	near(t, "R", *r.RFactor, 91.28, 0.01)
	near(t, "MOS", *r.MOS, 4.37, 0.01)
}

func TestLossIsCountedAndBursty(t *testing.T) {
	s := base()
	s.DurationSec = 200
	s.LossPct = 5
	s.MeanBurst = 4
	r := run(t, s, stream.DefaultConfig())
	near(t, "loss %", r.LossPercent, 5, 1.2)
	near(t, "mean burst", r.MeanBurst, 4, 1.0)
	if r.Lost+r.Packets != r.Expected {
		t.Errorf("lost %d + received %d != expected %d", r.Lost, r.Packets, r.Expected)
	}
	if r.BurstRatio <= 1.5 {
		t.Errorf("burst ratio %.2f for bursty loss", r.BurstRatio)
	}

	s.MeanBurst = 1
	random := run(t, s, stream.DefaultConfig())
	if *random.MOS <= *r.MOS {
		t.Errorf("random loss (MOS %.2f) should sound better than bursts (MOS %.2f) at the same rate", *random.MOS, *r.MOS)
	}
}

func TestDuplicatesAndReordering(t *testing.T) {
	s := base()
	s.DupPc = 10
	s.ReorderPc = 5
	s.ReorderMs = 30 // later than the next packet (20 ms), earlier than the one after (40 ms)
	r := run(t, s, stream.DefaultConfig())
	if r.Duplicates < 50 || r.Duplicates > 150 {
		t.Errorf("duplicates = %d, want ~100", r.Duplicates)
	}
	if r.Reordered < 20 || r.Reordered > 90 {
		t.Errorf("reordered = %d, want ~50", r.Reordered)
	}
	if r.Lost != 0 {
		t.Errorf("reordering and duplicates must not count as loss, got %d lost", r.Lost)
	}
	if r.Packets != 1000 {
		t.Errorf("distinct packets = %d, want 1000", r.Packets)
	}
}

func TestJitterMatchesTheModel(t *testing.T) {
	s := base()
	s.DurationSec = 100
	s.JitterMs = 30 // uniform 0..30 ms: mean |difference| of two draws is 10 ms
	r := run(t, s, stream.DefaultConfig())
	near(t, "mean jitter ms", r.JitterMeanMs, 10, 1.5)
	if r.JitterMaxMs < r.JitterMeanMs {
		t.Errorf("max jitter %.2f below mean %.2f", r.JitterMaxMs, r.JitterMeanMs)
	}
	if r.LateDiscarded != 0 {
		t.Errorf("30 ms of jitter fits a 60 ms buffer, but %d packets were called late", r.LateDiscarded)
	}
}

func TestLatePacketsCountAsLoss(t *testing.T) {
	s := base()
	s.DurationSec = 100
	s.JitterMs = 100 // a 60 ms buffer drops about 40 % of this
	r := run(t, s, stream.DefaultConfig())
	if r.Lost != 0 {
		t.Fatalf("nothing was lost on the wire, got %d", r.Lost)
	}
	near(t, "effective loss %", r.EffectiveLossPercent, 40, 8)

	cfg := stream.DefaultConfig()
	cfg.PlayoutMs = 0
	r0 := run(t, s, cfg)
	if r0.LateDiscarded != 0 || r0.EffectiveLossPercent != 0 {
		t.Errorf("playout simulation off, yet late=%d eff=%.1f", r0.LateDiscarded, r0.EffectiveLossPercent)
	}
}

func TestSequenceWrap(t *testing.T) {
	s := base()
	s.StartSeq = 65000 // wraps after 536 packets
	s.StartTS = 0xFFFFF000
	s.LossPct = 2
	r := run(t, s, stream.DefaultConfig())
	if r.Expected != 1000 {
		t.Errorf("expected = %d across a wrap, want 1000", r.Expected)
	}
	near(t, "jitter across timestamp wrap", r.JitterMeanMs, 0, 1e-6)
}

func TestDTMFDoesNotDisturbJitter(t *testing.T) {
	s := base()
	s.DTMFAt = []float64{2, 5, 9}
	r := run(t, s, stream.DefaultConfig())
	if r.OtherPackets != 15 {
		t.Errorf("event packets = %d, want 15", r.OtherPackets)
	}
	near(t, "jitter", r.JitterMeanMs, 0, 1e-6)
	if r.Lost != 0 || r.Codec != "PCMU" {
		t.Errorf("lost=%d codec=%s", r.Lost, r.Codec)
	}
}

func TestSilenceSuppressionIsNotJitter(t *testing.T) {
	// Marker-bit packets open a talkspurt after a pause; the timestamp gap is not network jitter.
	s := base()
	ds, _ := s.Generate()
	var out []synth.Datagram
	for i, d := range ds {
		if i >= 200 && i < 400 {
			continue // 4 s of silence without sequence gap: renumber below
		}
		out = append(out, d)
	}
	// Renumber so the sequence stays contiguous, and mark the packet after the pause.
	for i := range out {
		seq := uint16(100 + i)
		out[i].Payload[2], out[i].Payload[3] = byte(seq>>8), byte(seq)
		if i == 200 {
			out[i].Payload[1] |= 0x80
		}
	}
	res := analyze(t, stream.DefaultConfig(), out...)
	if len(res) != 1 {
		t.Fatalf("%d streams", len(res))
	}
	near(t, "jitter with a silence gap", res[0].JitterMeanMs, 0, 0.5)
}

func TestSequenceRestartMakesASecondSegment(t *testing.T) {
	s := base()
	s.DurationSec = 4
	first, _ := s.Generate()
	s.StartSeq = 40000
	s.Start += 5_000_000_000
	s.StartTS = 99999
	second, _ := s.Generate()
	res := analyze(t, stream.DefaultConfig(), append(first, second...)...)
	if len(res) != 2 {
		t.Fatalf("got %d segments, want 2", len(res))
	}
	if res[0].Segment != 1 || res[1].Segment != 2 {
		t.Errorf("segments %d, %d", res[0].Segment, res[1].Segment)
	}
	for _, r := range res {
		if r.Lost != 0 || r.Packets != 200 {
			t.Errorf("segment %d: packets=%d lost=%d", r.Segment, r.Packets, r.Lost)
		}
	}
}

func TestStrayPacketIsDropped(t *testing.T) {
	s := base()
	ds, _ := s.Generate()
	stray := ds[300]
	stray.Payload = append([]byte(nil), stray.Payload...)
	stray.Payload[2], stray.Payload[3] = 0x80, 0x00 // a sequence number from nowhere
	stray.Time++
	all := append(append(append([]synth.Datagram(nil), ds[:301]...), stray), ds[301:]...)
	an := stream.New(stream.DefaultConfig())
	for _, d := range all {
		an.Add(capture.Packet{Time: d.Time, Src: d.Src, Dst: d.Dst, Payload: d.Payload, UDPLen: len(d.Payload)})
	}
	res, _ := an.Results(1)
	if len(res) != 1 || res[0].Segment != 1 {
		t.Fatalf("one stray packet split the stream: %d results", len(res))
	}
	if an.Dropped != 1 {
		t.Errorf("dropped = %d, want 1", an.Dropped)
	}
	if res[0].Lost != 0 {
		t.Errorf("lost = %d", res[0].Lost)
	}
}

func TestProbationIgnoresNoise(t *testing.T) {
	// UDP traffic that happens to start with 0x80 and repeat a four-byte "SSRC", but whose
	// "sequence numbers" are all over the place.
	an := stream.New(stream.DefaultConfig())
	for i := 0; i < 200; i++ {
		p := make([]byte, 40)
		p[0], p[1] = 0x80, 0
		p[2], p[3] = byte(i*7919>>8), byte(i*7919)
		an.Add(capture.Packet{Time: int64(i) * 1_000_000, Src: a, Dst: b, Payload: p, UDPLen: 40})
	}
	if res, _ := an.Results(1); len(res) != 0 {
		t.Errorf("noise became %d streams", len(res))
	}
}

func TestEachDirectionIsItsOwnStream(t *testing.T) {
	fwd := base()
	rev := base()
	rev.Src, rev.Dst, rev.SSRC = b, a, 0x9999
	f, _ := fwd.Generate()
	r, _ := rev.Generate()
	res := analyze(t, stream.DefaultConfig(), synth.Merge(f, r)...)
	if len(res) != 2 {
		t.Fatalf("got %d streams, want 2", len(res))
	}
}

func TestCodecWithoutModelHasNoMOS(t *testing.T) {
	s := base()
	s.Codec = synth.Codecs["G722"]
	r := run(t, s, stream.DefaultConfig())
	if r.MOS != nil || r.Note == "" {
		t.Errorf("G.722 has no narrow-band E-model values, but MOS=%v note=%q", r.MOS, r.Note)
	}
	if r.Lost != 0 || r.Packets != 1000 {
		t.Errorf("stats still expected: %+v", r)
	}
}

func TestDynamicPayloadOverride(t *testing.T) {
	s := base()
	s.Codec = synth.Codec{Name: "opus", PT: 111, ClockRate: 48000}
	// The generator only knows its own codecs; borrow PCMU's shape with a different PT and clock.
	s.Codec = synth.Codecs["PCMU"]
	s.Codec.PT = 96
	ds, _ := s.Generate()
	cfg := stream.DefaultConfig()
	pt, info, err := codec.Parse("96=PCMU/8000")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Payloads = map[uint8]codec.Info{pt: info}
	res := analyze(t, cfg, ds...)
	if len(res) != 1 || res[0].Codec != "PCMU" {
		t.Fatalf("override ignored: %+v", res)
	}
}

func FuzzAnalyzer(f *testing.F) {
	s := base()
	s.DurationSec = 1
	ds, _ := s.Generate()
	for _, d := range ds[:5] {
		f.Add(d.Payload, int64(d.Time), 0)
	}
	f.Fuzz(func(t *testing.T, payload []byte, ts int64, extra int) {
		if extra < 0 || extra > 1<<16 {
			extra = 0
		}
		an := stream.New(stream.DefaultConfig())
		// Feed the same packet repeatedly with advancing sequence numbers and times:
		// the analyzer must survive any header bytes and any timestamps, including backwards ones.
		for i := 0; i < 40; i++ {
			p := append([]byte(nil), payload...)
			if len(p) >= 4 {
				p[2], p[3] = byte(i>>8), byte(i)
			}
			an.Add(capture.Packet{Time: ts + int64(i)*20_000_000*int64(1-2*(i%7/6)), Src: a, Dst: b, Payload: p, UDPLen: len(p) + extra})
		}
		res, _ := an.Results(1)
		for _, r := range res {
			if r.Lost < 0 || r.Expected < r.Packets || r.EffectiveLossPercent < 0 || r.EffectiveLossPercent > 100.0001 {
				t.Fatalf("impossible result: %+v", r)
			}
			if r.MOS != nil && (*r.MOS < 1 || *r.MOS > 4.5) {
				t.Fatalf("MOS out of range: %v", *r.MOS)
			}
		}
	})
}

func TestReorderingAtTheStartDoesNotCostPackets(t *testing.T) {
	s := base()
	s.DurationSec = 1
	ds, _ := s.Generate()
	// Swap the first two packets, so 101 arrives before 100; a naive probation would drop them.
	ds[0], ds[1] = ds[1], ds[0]
	res := analyze(t, stream.DefaultConfig(), ds...)
	if len(res) != 1 || res[0].Packets != 50 || res[0].Lost != 0 || res[0].Reordered != 1 {
		t.Errorf("%+v", res)
	}
}

func TestDuplicateDoesNotConfirmAStream(t *testing.T) {
	s := base()
	s.DurationSec = 1
	ds, _ := s.Generate()
	an := stream.New(stream.DefaultConfig())
	for i := 0; i < 5; i++ { // the same packet five times is not a stream
		an.Add(capture.Packet{Time: ds[0].Time + int64(i), Src: a, Dst: b, Payload: ds[0].Payload, UDPLen: len(ds[0].Payload)})
	}
	if res, _ := an.Results(1); len(res) != 0 {
		t.Errorf("%d streams from one repeated packet", len(res))
	}
}
