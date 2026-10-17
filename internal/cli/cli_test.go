package cli_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/cli"
)

var update = flag.Bool("update", false, "rewrite the golden files")

type outcome struct {
	code        int
	stdout, err string
}

func run(t *testing.T, stdin string, args ...string) outcome {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(args, strings.NewReader(stdin), &out, &errb, "test")
	return outcome{code, out.String(), errb.String()}
}

// gen writes a synthetic call into dir and returns its path.
func gen(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	r := run(t, "", append([]string{"gen", "-o", path}, args...)...)
	if r.code != 0 {
		t.Fatalf("gen %v: exit %d: %s", args, r.code, r.err)
	}
	return path
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file (run go test ./internal/cli -update to accept):\n--- got\n%s", name, got)
	}
}

var impaired = []string{"-duration", "30", "-loss", "4", "-burst", "3", "-jitter", "25", "-reorder", "2", "-dup", "1", "-dtmf", "3,8", "-both", "-seed", "42"}

func TestGoldenReports(t *testing.T) {
	dir := t.TempDir()
	pcap := gen(t, dir, "call.pcap", impaired...)
	for _, c := range []struct{ file, format string }{
		{"call.txt", "text"}, {"call.json", "json"}, {"call.prom", "prometheus"},
	} {
		r := run(t, "", "-format", c.format, pcap)
		if r.code != 0 {
			t.Fatalf("%s: exit %d: %s", c.format, r.code, r.err)
		}
		// The temp directory differs from run to run.
		golden(t, c.file, strings.ReplaceAll(r.stdout, pcap, "call.pcap"))
	}
}

func TestJSONIsValid(t *testing.T) {
	pcap := gen(t, t.TempDir(), "c.pcap", impaired...)
	r := run(t, "", "-format", "json", pcap)
	var doc struct {
		Tool    string `json:"tool"`
		Streams []struct {
			SSRC string   `json:"ssrc"`
			MOS  *float64 `json:"mos"`
			Lost int      `json:"lost"`
		} `json:"streams"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("%v\n%s", err, r.stdout)
	}
	if doc.Tool != "rtp-quality" || len(doc.Streams) != 2 || doc.Streams[0].MOS == nil || doc.Streams[0].Lost == 0 {
		t.Errorf("%+v", doc)
	}
	// A capture with no RTP is an empty list, not null.
	empty := run(t, "", "-format", "json", gen(t, t.TempDir(), "e.pcap", "-duration", "0.1"))
	if !strings.Contains(empty.stdout, `"streams": []`) {
		t.Errorf("empty result: %s", empty.stdout)
	}
}

var (
	promLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-z_]+="([^"\\\n]|\\.)*",?)+\})? -?[0-9.e+-]+$`)
	promHelp = regexp.MustCompile(`^# (HELP|TYPE) ([a-zA-Z_:][a-zA-Z0-9_:]*) .+$`)
)

func TestPrometheusFormat(t *testing.T) {
	pcap := gen(t, t.TempDir(), "c.pcap", impaired...)
	r := run(t, "", "-format", "prometheus", pcap)
	declared := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		if strings.HasPrefix(line, "#") {
			m := promHelp.FindStringSubmatch(line)
			if m == nil {
				t.Fatalf("bad comment line %q", line)
			}
			if m[1] == "TYPE" {
				declared[m[2]] = true
			}
			continue
		}
		if !promLine.MatchString(line) {
			t.Fatalf("bad sample line %q", line)
		}
		name := line[:strings.IndexAny(line, "{ ")]
		if !declared[name] {
			t.Errorf("%s has samples before its TYPE line", name)
		}
	}
	for _, want := range []string{`rtp_streams 2`, `rtp_stream_mos{src="192.0.2.10:10000",dst="192.0.2.20:20000",ssrc="0x11111111",segment="1",codec="PCMU"}`, "rtp_stream_jitter_seconds"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestExitCodesAsAGate(t *testing.T) {
	dir := t.TempDir()
	clean := gen(t, dir, "clean.pcap", "-duration", "10")
	lossy := gen(t, dir, "lossy.pcap", "-duration", "20", "-loss", "12", "-burst", "4", "-seed", "5")
	jittery := gen(t, dir, "jittery.pcap", "-duration", "20", "-jitter", "60")
	noRTP := gen(t, dir, "none.pcap", "-duration", "0.05")
	g722 := gen(t, dir, "g722.pcap", "-duration", "10", "-codec", "G722")

	for _, c := range []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"no gate, lossy call", []string{lossy}, 0, ""},
		{"MOS gate, clean call", []string{"-fail-mos", "4", clean}, 0, ""},
		{"MOS gate, lossy call", []string{"-fail-mos", "4", lossy}, 1, "MOS"},
		{"loss gate, clean call", []string{"-fail-loss", "0", clean}, 0, ""},
		{"loss gate, lossy call", []string{"-fail-loss", "5", lossy}, 1, "loss"},
		{"jitter gate, jittery call", []string{"-fail-jitter", "10", jittery}, 1, "jitter"},
		{"jitter gate, clean call", []string{"-fail-jitter", "10", clean}, 0, ""},
		{"gate with nothing to check", []string{"-fail-mos", "4", noRTP}, 1, "no RTP streams"},
		{"MOS gate on a codec without a model", []string{"-fail-mos", "4", g722}, 0, "not checked"},
		{"unknown file", []string{filepath.Join(dir, "missing.pcap")}, 2, "no such file"},
		{"not a capture", []string{writeFile(t, dir, "x.txt", "hello")}, 2, "not a pcap"},
		{"no argument", nil, 2, "Usage"},
		{"two arguments", []string{clean, lossy}, 2, "Usage"},
		{"bad format", []string{"-format", "xml", clean}, 2, "unknown -format"},
		{"bad flag", []string{"-nope"}, 2, "not defined"},
		{"bad -pt", []string{"-pt", "banana", clean}, 2, "PT=name/clockrate"},
		{"bad -probation", []string{"-probation", "0", clean}, 2, "at least 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, "", c.args...)
			if r.code != c.code {
				t.Errorf("exit %d, want %d\nstderr: %s", r.code, c.code, r.err)
			}
			if !strings.Contains(r.err, c.msg) {
				t.Errorf("stderr %q does not mention %q", r.err, c.msg)
			}
		})
	}
}

func writeFile(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStdinAndVersion(t *testing.T) {
	dir := t.TempDir()
	data, _ := os.ReadFile(gen(t, dir, "c.pcap", "-duration", "5"))
	r := run(t, string(data), "-")
	if r.code != 0 || !strings.Contains(r.stdout, "stdin:") || !strings.Contains(r.stdout, "PCMU") {
		t.Errorf("exit %d\n%s%s", r.code, r.stdout, r.err)
	}
	if v := run(t, "", "-version"); v.code != 0 || strings.TrimSpace(v.stdout) != "rtp-quality test" {
		t.Errorf("%+v", v)
	}
	if h := run(t, "", "-h"); h.code != 0 || !strings.Contains(h.err, "-fail-mos") {
		t.Errorf("-h: %+v", h)
	}
}

func TestOutputFileIsReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	pcap := gen(t, dir, "c.pcap", "-duration", "5")
	out := writeFile(t, dir, "rtp.prom", "old contents\n")
	r := run(t, "", "-format", "prometheus", "-o", out, pcap)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("exit %d stdout %q err %q", r.code, r.stdout, r.err)
	}
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "# HELP rtp_streams") {
		t.Errorf("file not replaced: %q", b)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".rtp.prom.tmp*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
	// An unwritable destination is a usage error, not a panic.
	if r := run(t, "", "-o", filepath.Join(dir, "no", "such", "dir", "x"), pcap); r.code != 2 {
		t.Errorf("exit %d", r.code)
	}
}

func TestDynamicPayloadFlag(t *testing.T) {
	dir := t.TempDir()
	pcap := gen(t, dir, "c.pcap", "-duration", "5")
	// Rewrite the payload type of every packet to 96 by patching the file: PT is the 2nd RTP byte.
	data, _ := os.ReadFile(pcap)
	// ethernet(14)+ip(20)+udp(8)+1 into each record; walk the records.
	for off := 24; off+16 <= len(data); {
		n := int(data[off+8]) | int(data[off+9])<<8 | int(data[off+10])<<16
		data[off+16+14+20+8+1] = 96
		off += 16 + n
	}
	patched := writeFile(t, dir, "dyn.pcap", string(data))
	plain := run(t, "", patched)
	if !strings.Contains(plain.stdout, "PT96") || !strings.Contains(plain.stdout, "not in the static table") || !strings.Contains(plain.stdout, "no E-model values") {
		t.Errorf("unknown dynamic type:\n%s", plain.stdout)
	}
	described := run(t, "", "-pt", "96=PCMU/8000", patched)
	if !strings.Contains(described.stdout, "PCMU, payload type 96") {
		t.Errorf("-pt ignored:\n%s", described.stdout)
	}
}

func TestPlayoutDelayChangesTheVerdict(t *testing.T) {
	pcap := gen(t, t.TempDir(), "j.pcap", "-oneway", "-duration", "20", "-jitter", "90")
	big := run(t, "", "-playout-delay", "200", "-format", "json", pcap)
	small := run(t, "", "-playout-delay", "30", "-format", "json", pcap)
	if big.code != 0 || small.code != 0 {
		t.Fatal(big.err, small.err)
	}
	mos := func(s string) float64 {
		var d struct{ Streams []struct{ MOS float64 } }
		if err := json.Unmarshal([]byte(s), &d); err != nil || len(d.Streams) == 0 {
			t.Fatalf("%v: %s", err, s)
		}
		return d.Streams[0].MOS
	}
	if mos(small.stdout) >= mos(big.stdout) {
		t.Errorf("a 30 ms buffer should sound worse than a 200 ms one at 90 ms of jitter: %.2f vs %.2f", mos(small.stdout), mos(big.stdout))
	}
}

func TestGenIsDeterministicAndValidated(t *testing.T) {
	dir := t.TempDir()
	read := func(name string, args ...string) []byte {
		b, err := os.ReadFile(gen(t, dir, name, args...))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a1 := read("a1.pcap", impaired...)
	a2 := read("a2.pcap", impaired...)
	if !bytes.Equal(a1, a2) {
		t.Error("same seed, different bytes")
	}
	other := append(append([]string(nil), impaired...), "-seed", "43")
	if bytes.Equal(a1, read("b.pcap", other...)) {
		t.Error("different seeds, same bytes")
	}
	if ng := read("c.pcapng", "-format", "pcapng", "-nano"); !bytes.HasPrefix(ng, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		t.Error("pcapng requested, not written")
	}
	if one := read("one.pcap", "-oneway", "-duration", "2"); len(one) >= len(read("two.pcap", "-duration", "2")) {
		t.Error("-oneway is not smaller than a two-way call")
	}

	for _, bad := range [][]string{
		{"-codec", "OPUS"}, {"-loss", "100"}, {"-loss", "-1"}, {"-ptime", "1"}, {"-duration", "0"},
		{"-src", "nonsense"}, {"-dst", "1.2.3.4"}, {"-dtmf", "a"}, {"-format", "xml"}, {"-jitter", "-5"},
	} {
		r := run(t, "", append([]string{"gen", "-o", filepath.Join(dir, "bad.pcap")}, bad...)...)
		if r.code != 2 {
			t.Errorf("gen %v: exit %d, want 2", bad, r.code)
		}
	}
	if r := run(t, "", "gen"); r.code != 2 || !strings.Contains(r.err, "-o") {
		t.Errorf("gen without -o: %+v", r)
	}
	// "-" writes the capture to stdout so it can be piped into the analyzer.
	g := run(t, "", "gen", "-o", "-", "-duration", "3")
	if g.code != 0 {
		t.Fatal(g.err)
	}
	if a := run(t, g.stdout, "-"); a.code != 0 || !strings.Contains(a.stdout, "PCMU") {
		t.Errorf("piped: %+v", a)
	}
}
