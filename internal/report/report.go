// Package report prints analysis results as text, JSON or Prometheus metrics.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/ErenOzgu/rtp-quality/internal/capture"
	"github.com/ErenOzgu/rtp-quality/internal/stream"
)

// Meta is what is known about the run besides the streams themselves.
type Meta struct {
	File       string
	Capture    capture.Stats
	NonRTP     int // UDP datagrams that were not RTP
	Dropped    int // RTP packets ignored as sequence outliers
	Short      int // streams left out for having fewer than MinPackets
	MinPackets int
	Version    string
}

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
func f2(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// Label names a stream the way a person would.
func Label(r stream.Result) string {
	s := fmt.Sprintf("%s -> %s ssrc 0x%08x", r.Src, r.Dst, r.SSRC)
	if r.Segment > 1 {
		s += fmt.Sprintf(" (restart %d)", r.Segment)
	}
	return s
}

// Text writes the human-readable report.
func Text(w io.Writer, m Meta, rs []stream.Result) {
	name := m.File
	if name == "" || name == "-" {
		name = "stdin"
	}
	fmt.Fprintf(w, "%s: %s, %d frames, %d UDP datagrams\n", name, m.Capture.Format, m.Capture.Frames, m.Capture.UDP)
	if len(rs) == 0 {
		fmt.Fprintf(w, "\nNo RTP streams found")
		if m.Short > 0 {
			fmt.Fprintf(w, " with at least %d packets (%d shorter ones ignored)", m.MinPackets, m.Short)
		}
		fmt.Fprintln(w, ".")
	}
	for i, r := range rs {
		fmt.Fprintf(w, "\nStream %d  %s\n", i+1, Label(r))
		codecName := r.Codec
		if !r.CodecKnown {
			codecName += " (not in the static table; use -pt to describe it)"
		}
		fmt.Fprintf(w, "  codec      %s, payload type %d, clock %d Hz\n", codecName, r.PayloadType, r.ClockRate)
		fmt.Fprintf(w, "  packets    %d of %d expected over %s s, %s kbit/s, ptime %s ms\n",
			r.Packets, r.Expected, f1(r.DurationSec), f1(r.BitrateKbps), trimZero(f1(r.PtimeMs)))
		fmt.Fprintf(w, "  loss       %s %% on the wire (%d lost), %s %% heard (%d arrived too late for a %s ms buffer)\n",
			f2(r.LossPercent), r.Lost, f2(r.EffectiveLossPercent), r.LateDiscarded, trimZero(f1(r.PlayoutMs)))
		if r.Lost > 0 {
			fmt.Fprintf(w, "  bursts     mean %s packets, longest %d\n", f1(r.MeanBurst), r.MaxBurst)
		}
		fmt.Fprintf(w, "  order      %d duplicates, %d out of order", r.Duplicates, r.Reordered)
		if r.OtherPackets > 0 {
			fmt.Fprintf(w, ", %d other payload type (events, comfort noise)", r.OtherPackets)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  jitter     mean %s ms, max %s ms; packet spacing mean %s ms, max %s ms\n",
			f2(r.JitterMeanMs), f2(r.JitterMaxMs), f1(r.IntervalMeanMs), f1(r.IntervalMaxMs))
		if r.MOS != nil {
			fmt.Fprintf(w, "  quality    MOS %s, R %s (%s)\n", f2(*r.MOS), f1(*r.RFactor), r.Rating)
		} else {
			fmt.Fprintf(w, "  quality    %s\n", r.Note)
		}
		if r.Truncated > 0 {
			fmt.Fprintf(w, "  note       %d packets were captured shorter than they were on the wire (snap length); sizes come from the UDP header\n", r.Truncated)
		}
	}
	fmt.Fprintln(w)
	if m.Short > 0 && len(rs) > 0 {
		fmt.Fprintf(w, "%d streams with fewer than %d packets left out.\n", m.Short, m.MinPackets)
	}
	if m.NonRTP > 0 {
		fmt.Fprintf(w, "%d UDP datagrams were not RTP (SIP, DNS, RTCP, ...).\n", m.NonRTP)
	}
	if m.Dropped > 0 {
		fmt.Fprintf(w, "%d RTP packets with implausible sequence numbers were ignored.\n", m.Dropped)
	}
	st := m.Capture
	if st.Fragments > 0 {
		fmt.Fprintf(w, "%d IP fragments were skipped; a capture of fragmented RTP cannot be analyzed.\n", st.Fragments)
	}
	if st.Malformed > 0 {
		fmt.Fprintf(w, "%d frames were too short or inconsistent to decode.\n", st.Malformed)
	}
	if st.NoTime > 0 {
		fmt.Fprintf(w, "%d pcapng simple packet blocks have no timestamp and were skipped.\n", st.NoTime)
	}
	for link, n := range st.Unsupported {
		fmt.Fprintf(w, "%d frames with link type %d are not supported.\n", n, link)
	}
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }

type jsonStream struct {
	Src           string   `json:"src"`
	Dst           string   `json:"dst"`
	SSRC          string   `json:"ssrc"`
	Segment       int      `json:"segment"`
	Codec         string   `json:"codec"`
	PayloadType   int      `json:"payload_type"`
	ClockRate     int      `json:"clock_rate"`
	CodecKnown    bool     `json:"codec_known"`
	First         string   `json:"first"`
	Last          string   `json:"last"`
	DurationSec   float64  `json:"duration_seconds"`
	Packets       int      `json:"packets"`
	Expected      int      `json:"expected"`
	Lost          int      `json:"lost"`
	Duplicates    int      `json:"duplicates"`
	Reordered     int      `json:"reordered"`
	LateDiscarded int      `json:"late_discarded"`
	Truncated     int      `json:"truncated"`
	OtherPackets  int      `json:"other_payload_packets"`
	LossPercent   float64  `json:"loss_percent"`
	EffLossPct    float64  `json:"effective_loss_percent"`
	MeanBurst     float64  `json:"mean_loss_burst"`
	MaxBurst      int      `json:"max_loss_burst"`
	JitterMeanMs  float64  `json:"jitter_mean_ms"`
	JitterMaxMs   float64  `json:"jitter_max_ms"`
	IntervalMs    float64  `json:"interval_mean_ms"`
	IntervalMaxMs float64  `json:"interval_max_ms"`
	PtimeMs       float64  `json:"ptime_ms"`
	BitrateKbps   float64  `json:"bitrate_kbps"`
	PlayoutMs     float64  `json:"playout_ms"`
	RFactor       *float64 `json:"r_factor"`
	MOS           *float64 `json:"mos"`
	Rating        string   `json:"rating,omitempty"`
	Note          string   `json:"note,omitempty"`
}

type jsonDoc struct {
	Tool    string       `json:"tool"`
	Version string       `json:"version"`
	File    string       `json:"file"`
	Format  string       `json:"capture_format"`
	Frames  int          `json:"frames"`
	UDP     int          `json:"udp_datagrams"`
	NonRTP  int          `json:"non_rtp_datagrams"`
	Dropped int          `json:"ignored_packets"`
	Short   int          `json:"short_streams_left_out"`
	Streams []jsonStream `json:"streams"`
}

func rounded(p *float64, places int) *float64 {
	if p == nil {
		return nil
	}
	v := round(*p, places)
	return &v
}

// JSON writes the results as one JSON document.
func JSON(w io.Writer, m Meta, rs []stream.Result) error {
	doc := jsonDoc{
		Tool: "rtp-quality", Version: m.Version, File: m.File, Format: m.Capture.Format,
		Frames: m.Capture.Frames, UDP: m.Capture.UDP, NonRTP: m.NonRTP, Dropped: m.Dropped, Short: m.Short,
		Streams: []jsonStream{},
	}
	for _, r := range rs {
		doc.Streams = append(doc.Streams, jsonStream{
			Src: r.Src, Dst: r.Dst, SSRC: fmt.Sprintf("0x%08x", r.SSRC), Segment: r.Segment,
			Codec: r.Codec, PayloadType: r.PayloadType, ClockRate: r.ClockRate, CodecKnown: r.CodecKnown,
			First: r.First.Format("2006-01-02T15:04:05.000000Z07:00"), Last: r.Last.Format("2006-01-02T15:04:05.000000Z07:00"),
			DurationSec: round(r.DurationSec, 3), Packets: r.Packets, Expected: r.Expected, Lost: r.Lost,
			Duplicates: r.Duplicates, Reordered: r.Reordered, LateDiscarded: r.LateDiscarded,
			Truncated: r.Truncated, OtherPackets: r.OtherPackets,
			LossPercent: round(r.LossPercent, 3), EffLossPct: round(r.EffectiveLossPercent, 3),
			MeanBurst: round(r.MeanBurst, 2), MaxBurst: r.MaxBurst,
			JitterMeanMs: round(r.JitterMeanMs, 3), JitterMaxMs: round(r.JitterMaxMs, 3),
			IntervalMs: round(r.IntervalMeanMs, 3), IntervalMaxMs: round(r.IntervalMaxMs, 3),
			PtimeMs: round(r.PtimeMs, 3), BitrateKbps: round(r.BitrateKbps, 2), PlayoutMs: r.PlayoutMs,
			RFactor: rounded(r.RFactor, 2), MOS: rounded(r.MOS, 3), Rating: r.Rating, Note: r.Note,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
