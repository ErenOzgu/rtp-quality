package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ErenOzgu/rtp-quality/internal/synth"
)

func runGen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rtp-quality gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, genUsage); fs.PrintDefaults() }
	var (
		outFile  = fs.String("o", "", "output file (required; - for stdout)")
		format   = fs.String("format", "pcap", "pcap or pcapng")
		nano     = fs.Bool("nano", false, "nanosecond timestamps")
		cname    = fs.String("codec", "PCMU", "codec: "+synth.CodecNames())
		ptime    = fs.Int("ptime", 20, "packetisation time in ms")
		duration = fs.Float64("duration", 10, "call length in seconds")
		loss     = fs.Float64("loss", 0, "packet loss in percent")
		burst    = fs.Float64("burst", 1, "mean length of a loss run in packets (1 = random loss)")
		jitter   = fs.Float64("jitter", 0, "network jitter in ms (uniform extra delay between 0 and this)")
		delay    = fs.Float64("delay", 0, "fixed network delay in ms")
		reorder  = fs.Float64("reorder", 0, "percent of packets held back so that they arrive out of order")
		reorderD = fs.Float64("reorder-delay", 30, "how long a held-back packet is delayed, in ms")
		dup      = fs.Float64("dup", 0, "percent of packets delivered twice")
		dtmf     = fs.String("dtmf", "", "comma-separated times in seconds at which a DTMF digit is sent (telephone-event, PT 101)")
		seed     = fs.Uint64("seed", 1, "random seed")
		both     = fs.Bool("both", false, "apply the impairments to the reverse direction too (with another random sequence); by default only caller to callee is impaired")
		oneway   = fs.Bool("oneway", false, "write only the caller to callee direction, which is what SIPp's play_pcap_audio plays")
		src      = fs.String("src", "192.0.2.10:10000", "caller media address")
		dst      = fs.String("dst", "192.0.2.20:20000", "callee media address")
	)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "rtp-quality gen: "+format+"\n", a...)
		return ExitUsage
	}
	if *outFile == "" || fs.NArg() != 0 {
		fs.Usage()
		return ExitUsage
	}
	c, ok := synth.Codecs[strings.ToUpper(*cname)]
	if !ok {
		return fail("unknown codec %q (have %s)", *cname, synth.CodecNames())
	}
	a, err := netip.ParseAddrPort(*src)
	if err != nil {
		return fail("-src: %v", err)
	}
	b, err := netip.ParseAddrPort(*dst)
	if err != nil {
		return fail("-dst: %v", err)
	}
	var digits []float64
	for _, f := range strings.Split(*dtmf, ",") {
		if f = strings.TrimSpace(f); f != "" {
			v, err := strconv.ParseFloat(f, 64)
			if err != nil || v < 0 {
				return fail("-dtmf: %q is not a time in seconds", f)
			}
			digits = append(digits, v)
		}
	}

	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).UnixNano()
	fwd := synth.Stream{
		Src: a, Dst: b, SSRC: 0x11111111, Codec: c, PtimeMs: *ptime, Start: start, DurationSec: *duration,
		StartSeq: 1000, StartTS: 160000, DelayMs: *delay, JitterMs: *jitter, LossPct: *loss, MeanBurst: *burst,
		ReorderPc: *reorder, ReorderMs: *reorderD, DupPc: *dup, DTMFAt: digits, Seed: *seed,
	}
	parts := [][]synth.Datagram{}
	d1, err := fwd.Generate()
	if err != nil {
		return fail("%v", err)
	}
	parts = append(parts, d1)
	if !*oneway {
		rev := fwd
		rev.Src, rev.Dst, rev.SSRC, rev.StartSeq, rev.StartTS, rev.DTMFAt = b, a, 0x22222222, 40000, 7000, nil
		rev.Seed = *seed + 1
		rev.Start = start + 3_000_000 // the callee's packets are not in lock step with the caller's
		if !*both {
			rev.LossPct, rev.JitterMs, rev.ReorderPc, rev.DupPc, rev.MeanBurst = 0, 0, 0, 0, 1
		}
		d2, err := rev.Generate()
		if err != nil {
			return fail("%v", err)
		}
		parts = append(parts, d2)
	}
	var buf bytes.Buffer
	if err := synth.Write(&buf, synth.Merge(parts...), synth.Options{Format: *format, Nano: *nano}); err != nil {
		return fail("%v", err)
	}
	if *outFile == "-" {
		_, err = stdout.Write(buf.Bytes())
	} else {
		err = os.WriteFile(*outFile, buf.Bytes(), 0o644)
	}
	if err != nil {
		return fail("%v", err)
	}
	return ExitOK
}
