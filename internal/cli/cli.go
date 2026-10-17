// Package cli is the command line of rtp-quality, separated from main so tests can run it.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ErenOzgu/rtp-quality/internal/capture"
	"github.com/ErenOzgu/rtp-quality/internal/codec"
	"github.com/ErenOzgu/rtp-quality/internal/report"
	"github.com/ErenOzgu/rtp-quality/internal/stream"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1 // a threshold was crossed, or nothing could be rated
	ExitUsage = 2 // bad flags, unreadable or unsupported file
)

const usage = `rtp-quality - RTP jitter, loss and MOS from a packet capture

Usage:
  rtp-quality [flags] CAPTURE      analyze a pcap or pcapng file ("-" reads stdin)
  rtp-quality gen [flags] -o FILE  write a synthetic call with known impairments
  rtp-quality -version

Flags:
`

const genUsage = `rtp-quality gen - write a synthetic two-way call as a pcap or pcapng file

Every impairment is optional; the same -seed gives the same file byte for byte.

Flags:
`

type ptFlags map[uint8]codec.Info

func (p ptFlags) String() string { return "" }
func (p ptFlags) Set(s string) error {
	pt, info, err := codec.Parse(s)
	if err != nil {
		return err
	}
	p[pt] = info
	return nil
}

// Run executes the command line and returns the exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	if len(args) > 0 && args[0] == "gen" {
		return runGen(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("rtp-quality", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage); fs.PrintDefaults() }
	var (
		format     = fs.String("format", "text", "output format: text, json or prometheus")
		out        = fs.String("o", "", "write the report to this file instead of stdout (replaced atomically)")
		minPackets = fs.Int("min-packets", 10, "leave out streams with fewer packets than this")
		failMOS    = fs.Float64("fail-mos", 0, "exit 1 if any stream's estimated MOS is below this (0 = off)")
		failLoss   = fs.Float64("fail-loss", -1, "exit 1 if any stream's loss as heard (percent, late packets included) is above this (negative = off)")
		failJitter = fs.Float64("fail-jitter", -1, "exit 1 if any stream's mean jitter in ms is above this (negative = off)")
		playout    = fs.Float64("playout-delay", 60, "jitter buffer in ms assumed for deciding which packets arrived too late (0 = do not simulate)")
		netDelay   = fs.Float64("network-delay", 0, "one-way network delay in ms to add to the E-model's delay")
		probation  = fs.Int("probation", 3, "consecutive sequence numbers a flow needs before it counts as RTP")
		showVer    = fs.Bool("version", false, "print the version and exit")
	)
	pts := ptFlags{}
	fs.Var(pts, "pt", "describe a dynamic payload type, PT=name/clockrate, e.g. 96=opus/48000 (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if *showVer {
		fmt.Fprintf(stdout, "rtp-quality %s\n", version)
		return ExitOK
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return ExitUsage
	}
	switch *format {
	case "text", "json", "prometheus":
	default:
		fmt.Fprintf(stderr, "rtp-quality: unknown -format %q (text, json or prometheus)\n", *format)
		return ExitUsage
	}
	if *minPackets < 1 || *probation < 1 || *playout < 0 || *netDelay < 0 {
		fmt.Fprintln(stderr, "rtp-quality: -min-packets and -probation must be at least 1; delays must not be negative")
		return ExitUsage
	}

	path := fs.Arg(0)
	var in io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(stderr, "rtp-quality: %v\n", err)
			return ExitUsage
		}
		defer f.Close()
		in = f
	}

	cfg := stream.DefaultConfig()
	cfg.Probation, cfg.PlayoutMs, cfg.NetworkDelayMs, cfg.Payloads = *probation, *playout, *netDelay, pts
	an := stream.New(cfg)
	st, err := capture.Read(in, func(p capture.Packet) { an.Add(p) })
	if err != nil {
		fmt.Fprintf(stderr, "rtp-quality: %s: %v\n", path, err)
		return ExitUsage
	}
	results, short := an.Results(*minPackets)
	meta := report.Meta{File: path, Capture: st, NonRTP: an.NonRTP, Dropped: an.Dropped, Short: short, MinPackets: *minPackets, Version: version}

	var buf strings.Builder
	switch *format {
	case "text":
		report.Text(&buf, meta, results)
	case "json":
		if err := report.JSON(&buf, meta, results); err != nil {
			fmt.Fprintf(stderr, "rtp-quality: %v\n", err)
			return ExitUsage
		}
	case "prometheus":
		report.Prometheus(&buf, meta, results)
	}
	if *out == "" {
		io.WriteString(stdout, buf.String())
	} else if err := writeAtomic(*out, buf.String()); err != nil {
		fmt.Fprintf(stderr, "rtp-quality: %v\n", err)
		return ExitUsage
	}

	gate := *failMOS > 0 || *failLoss >= 0 || *failJitter >= 0
	if !gate {
		return ExitOK
	}
	if len(results) == 0 {
		fmt.Fprintln(stderr, "rtp-quality: FAIL: no RTP streams found, so nothing could be checked")
		return ExitFail
	}
	failed := false
	for _, r := range results {
		who := report.Label(r)
		if *failMOS > 0 {
			switch {
			case r.MOS == nil:
				fmt.Fprintf(stderr, "rtp-quality: not checked: %s: %s\n", who, r.Note)
			case *r.MOS < *failMOS:
				fmt.Fprintf(stderr, "rtp-quality: FAIL: %s: MOS %.2f is below %.2f\n", who, *r.MOS, *failMOS)
				failed = true
			}
		}
		if *failLoss >= 0 && r.EffectiveLossPercent > *failLoss {
			fmt.Fprintf(stderr, "rtp-quality: FAIL: %s: loss %.2f %% is above %.2f %%\n", who, r.EffectiveLossPercent, *failLoss)
			failed = true
		}
		if *failJitter >= 0 && r.JitterMeanMs > *failJitter {
			fmt.Fprintf(stderr, "rtp-quality: FAIL: %s: mean jitter %.2f ms is above %.2f ms\n", who, r.JitterMeanMs, *failJitter)
			failed = true
		}
	}
	if failed {
		return ExitFail
	}
	return ExitOK
}

// writeAtomic replaces path with data so that a reader (the node_exporter
// textfile collector, for one) never sees a half-written file.
func writeAtomic(path, data string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
