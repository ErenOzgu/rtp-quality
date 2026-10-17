// Package emodel estimates call quality from loss, delay and codec with the
// simplified ITU-T G.107 E-model, the way VoIP monitoring tools do.
//
// It is an estimate of conversational quality for narrow-band codecs. It is not
// a listening test: nothing here hears the audio.
package emodel

import "math"

// Params are the inputs of the model.
type Params struct {
	Ie, Bpl float64 // codec: equipment impairment and loss robustness (G.113)
	// LossPercent is the packet loss the listener experiences, in percent,
	// late packets included.
	LossPercent float64
	// BurstR is 1 for random loss and larger when losses come in runs.
	BurstR float64
	// DelayMs is the mouth-to-ear delay: packetisation, codec look-ahead,
	// jitter buffer and network.
	DelayMs float64
}

// R0Is is the basic signal-to-noise ratio minus simultaneous impairment with
// every G.107 input at its default: 93.2.
const R0Is = 93.2

// RFactor returns the transmission rating factor R (0 to 100).
func RFactor(p Params) float64 {
	return R0Is - delayImpairment(p.DelayMs) - effectiveEquipmentImpairment(p)
}

// delayImpairment is Id as a function of the one-way delay Ta, using the
// closed-form approximation of Cole and Rosenbluth (2001):
// Id = 0.024 Ta + 0.11 (Ta - 177.3) H(Ta - 177.3).
func delayImpairment(ta float64) float64 {
	id := 0.024 * ta
	if ta > 177.3 {
		id += 0.11 * (ta - 177.3)
	}
	return id
}

// effectiveEquipmentImpairment is Ie,eff = Ie + (95 - Ie) * Ppl / (Ppl/BurstR + Bpl).
func effectiveEquipmentImpairment(p Params) float64 {
	burst := p.BurstR
	if burst < 1 {
		burst = 1
	}
	if p.LossPercent <= 0 {
		return p.Ie
	}
	return p.Ie + (95-p.Ie)*p.LossPercent/(p.LossPercent/burst+p.Bpl)
}

// MOS maps R to the mean opinion score (1.0 to 4.5), G.107 Annex B.
func MOS(r float64) float64 {
	switch {
	case r <= 0:
		return 1
	case r >= 100:
		return 4.5
	}
	// For R below about 6.5 the polynomial dips under 1; the scale starts at 1.
	return math.Max(1, 1+0.035*r+r*(r-60)*(100-r)*7e-6)
}

// Rating names the user-satisfaction category of an R value (G.109).
func Rating(r float64) string {
	switch {
	case r >= 90:
		return "very satisfied"
	case r >= 80:
		return "satisfied"
	case r >= 70:
		return "some users dissatisfied"
	case r >= 60:
		return "many users dissatisfied"
	case r >= 50:
		return "nearly all users dissatisfied"
	}
	return "not recommended"
}

// Round to one decimal for display.
func Round1(v float64) float64 { return math.Round(v*10) / 10 }
