package report_test

import (
	"strings"
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/report"
	"github.com/ErenOzgu/rtp-quality/internal/stream"
)

func TestPrometheusEscapesLabelValues(t *testing.T) {
	mos, r := 4.2, 90.0
	var b strings.Builder
	report.Prometheus(&b, report.Meta{}, []stream.Result{{
		Src: "10.0.0.1:1", Dst: "10.0.0.2:2", SSRC: 7, Segment: 1,
		Codec: "a\"b\\c\nd", MOS: &mos, RFactor: &r,
	}})
	if !strings.Contains(b.String(), `codec="a\"b\\c\nd"`) {
		t.Errorf("label not escaped:\n%s", b.String())
	}
	if strings.Count(b.String(), "\n") != strings.Count(strings.TrimRight(b.String(), "\n"), "\n")+1 {
		t.Error("output does not end with exactly one newline")
	}
}

func TestPrometheusLeavesOutMOSWhenThereIsNone(t *testing.T) {
	var b strings.Builder
	report.Prometheus(&b, report.Meta{}, []stream.Result{{Src: "a:1", Dst: "b:2", Codec: "G722", Segment: 1}})
	if strings.Contains(b.String(), "rtp_stream_mos") || strings.Contains(b.String(), "rtp_stream_r_factor") {
		t.Errorf("a stream without a model must not report MOS:\n%s", b.String())
	}
}

func TestTextWithoutStreams(t *testing.T) {
	var b strings.Builder
	report.Text(&b, report.Meta{File: "x.pcap", Short: 2, MinPackets: 10}, nil)
	if !strings.Contains(b.String(), "No RTP streams found with at least 10 packets (2 shorter ones ignored).") {
		t.Errorf("%s", b.String())
	}
}
