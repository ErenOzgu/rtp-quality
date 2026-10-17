// Package codec knows the static RTP payload types (RFC 3551) and the few
// E-model parameters (ITU-T G.113) that are published for them.
package codec

import "fmt"

// Info describes a payload type.
type Info struct {
	Name      string
	ClockRate int
	// Audio is false for payload types that share a stream with speech but
	// carry something else (comfort noise, DTMF events).
	Audio bool
	// Known is false for dynamic payload types nobody told us about.
	Known bool
	// E-model parameters; HasModel is false when no values are published
	// for this codec, in which case no MOS is computed.
	HasModel  bool
	Ie        float64 // equipment impairment factor
	Bpl       float64 // packet-loss robustness factor
	Lookahead float64 // algorithmic delay beyond the packet, in ms
}

var static = map[uint8]Info{
	0:  {Name: "PCMU", ClockRate: 8000, Audio: true, HasModel: true, Ie: 0, Bpl: 25.1},
	3:  {Name: "GSM", ClockRate: 8000, Audio: true, HasModel: true, Ie: 20, Bpl: 10},
	4:  {Name: "G723", ClockRate: 8000, Audio: true, HasModel: true, Ie: 15, Bpl: 16.1, Lookahead: 7.5},
	5:  {Name: "DVI4", ClockRate: 8000, Audio: true},
	6:  {Name: "DVI4", ClockRate: 16000, Audio: true},
	7:  {Name: "LPC", ClockRate: 8000, Audio: true},
	8:  {Name: "PCMA", ClockRate: 8000, Audio: true, HasModel: true, Ie: 0, Bpl: 25.1},
	9:  {Name: "G722", ClockRate: 8000, Audio: true}, // 16 kHz audio, 8 kHz RTP clock (RFC 3551)
	10: {Name: "L16", ClockRate: 44100, Audio: true},
	11: {Name: "L16", ClockRate: 44100, Audio: true},
	12: {Name: "QCELP", ClockRate: 8000, Audio: true},
	13: {Name: "CN", ClockRate: 8000},
	15: {Name: "G728", ClockRate: 8000, Audio: true},
	16: {Name: "DVI4", ClockRate: 11025, Audio: true},
	17: {Name: "DVI4", ClockRate: 22050, Audio: true},
	18: {Name: "G729", ClockRate: 8000, Audio: true, HasModel: true, Ie: 11, Bpl: 19, Lookahead: 5},
}

func init() {
	for pt, i := range static {
		i.Known = true
		static[pt] = i
	}
}

// Lookup returns what is known about a payload type. Overrides (from the
// command line) win over the static table. Unknown payload types get an
// 8 kHz clock, which is right for nearly every telephony codec, and Known=false.
func Lookup(pt uint8, overrides map[uint8]Info) Info {
	if i, ok := overrides[pt]; ok {
		return i
	}
	if i, ok := static[pt]; ok {
		return i
	}
	return Info{Name: fmt.Sprintf("PT%d", pt), ClockRate: 8000, Audio: pt >= 96}
}

// Parse reads a "name/clock" mapping such as "96=opus/48000" or "101=telephone-event/8000".
func Parse(spec string) (uint8, Info, error) {
	var pt int
	var name string
	var clock int
	n, err := fmt.Sscanf(replaceSeps(spec), "%d %s %d", &pt, &name, &clock)
	if err != nil || n != 3 || pt < 0 || pt > 127 || clock <= 0 {
		return 0, Info{}, fmt.Errorf("%q: want PT=name/clockrate, for example 96=opus/48000", spec)
	}
	info := Info{Name: name, ClockRate: clock, Known: true, Audio: true}
	switch name {
	case "telephone-event", "CN", "cn", "TELEPHONE-EVENT":
		info.Audio = false
	}
	if base, ok := static[uint8(pt)]; ok && base.Name == name && base.ClockRate == clock {
		info = base
	}
	return uint8(pt), info, nil
}

func replaceSeps(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '=' || c == '/' {
			b[i] = ' '
		}
	}
	return string(b)
}
