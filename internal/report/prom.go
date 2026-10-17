package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ErenOzgu/rtp-quality/internal/stream"
)

// labelEscaper escapes a label value as the Prometheus text format requires.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

type metric struct {
	name, help string
	value      func(stream.Result) (float64, bool)
}

// fnum prints 9 significant digits: more is noise for these quantities.
func fnum(v float64) string { return strconv.FormatFloat(v, 'g', 9, 64) }

func ratio(percent float64) float64 { return percent / 100 }

var streamMetrics = []metric{
	{"rtp_stream_packets", "Distinct RTP packets received.", func(r stream.Result) (float64, bool) { return float64(r.Packets), true }},
	{"rtp_stream_expected_packets", "RTP packets expected from the sequence numbers.", func(r stream.Result) (float64, bool) { return float64(r.Expected), true }},
	{"rtp_stream_lost_packets", "RTP packets that never arrived.", func(r stream.Result) (float64, bool) { return float64(r.Lost), true }},
	{"rtp_stream_duplicate_packets", "RTP packets received more than once.", func(r stream.Result) (float64, bool) { return float64(r.Duplicates), true }},
	{"rtp_stream_reordered_packets", "RTP packets that arrived after a higher sequence number.", func(r stream.Result) (float64, bool) { return float64(r.Reordered), true }},
	{"rtp_stream_late_packets", "RTP packets that arrived too late for the assumed jitter buffer.", func(r stream.Result) (float64, bool) { return float64(r.LateDiscarded), true }},
	{"rtp_stream_loss_ratio", "Fraction of expected packets lost on the wire (0 to 1).", func(r stream.Result) (float64, bool) { return ratio(r.LossPercent), true }},
	{"rtp_stream_effective_loss_ratio", "Fraction of expected packets lost or too late to play (0 to 1).", func(r stream.Result) (float64, bool) { return ratio(r.EffectiveLossPercent), true }},
	{"rtp_stream_max_loss_burst_packets", "Longest run of consecutive lost or late packets.", func(r stream.Result) (float64, bool) { return float64(r.MaxBurst), true }},
	{"rtp_stream_jitter_seconds", "Mean interarrival jitter (RFC 3550).", func(r stream.Result) (float64, bool) { return r.JitterMeanMs / 1000, true }},
	{"rtp_stream_jitter_max_seconds", "Highest interarrival jitter value reached (RFC 3550).", func(r stream.Result) (float64, bool) { return r.JitterMaxMs / 1000, true }},
	{"rtp_stream_duration_seconds", "Time from the first to the last packet.", func(r stream.Result) (float64, bool) { return r.DurationSec, true }},
	{"rtp_stream_bitrate_bits_per_second", "RTP payload bit rate.", func(r stream.Result) (float64, bool) { return r.BitrateKbps * 1000, true }},
	{"rtp_stream_r_factor", "E-model transmission rating factor R (only for codecs with published parameters).", func(r stream.Result) (float64, bool) {
		if r.RFactor == nil {
			return 0, false
		}
		return *r.RFactor, true
	}},
	{"rtp_stream_mos", "Estimated mean opinion score from the E-model (only for codecs with published parameters).", func(r stream.Result) (float64, bool) {
		if r.MOS == nil {
			return 0, false
		}
		return *r.MOS, true
	}},
}

// Prometheus writes the results in the text exposition format, suitable for
// node_exporter's textfile collector. Every value is a gauge: a capture is a
// finished measurement, not a counter that keeps growing.
func Prometheus(w io.Writer, m Meta, rs []stream.Result) {
	fmt.Fprintln(w, "# HELP rtp_streams RTP streams reported from the capture.")
	fmt.Fprintln(w, "# TYPE rtp_streams gauge")
	fmt.Fprintf(w, "rtp_streams %d\n", len(rs))
	fmt.Fprintln(w, "# HELP rtp_capture_non_rtp_datagrams UDP datagrams in the capture that were not RTP.")
	fmt.Fprintln(w, "# TYPE rtp_capture_non_rtp_datagrams gauge")
	fmt.Fprintf(w, "rtp_capture_non_rtp_datagrams %d\n", m.NonRTP)

	labels := make([]string, len(rs))
	for i, r := range rs {
		labels[i] = fmt.Sprintf(`{src="%s",dst="%s",ssrc="0x%08x",segment="%d",codec="%s"}`,
			labelEscaper.Replace(r.Src), labelEscaper.Replace(r.Dst), r.SSRC, r.Segment, labelEscaper.Replace(r.Codec))
	}
	for _, mt := range streamMetrics {
		var lines []string
		for i, r := range rs {
			if v, ok := mt.value(r); ok {
				lines = append(lines, mt.name+labels[i]+" "+fnum(v))
			}
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", mt.name, mt.help, mt.name)
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
	}
}
