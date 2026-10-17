package emodel_test

import (
	"math"
	"testing"

	"github.com/ErenOzgu/rtp-quality/internal/emodel"
)

func near(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %.4f, want %.4f ± %g", name, got, want, tol)
	}
}

// The R to MOS conversion is G.107 Annex B; these points are hand-computed from it.
func TestMOSFromR(t *testing.T) {
	for _, c := range []struct{ r, mos float64 }{
		{0, 1}, {-5, 1}, {100, 4.5}, {120, 4.5},
		{93.2, 4.409}, {80, 4.024}, {70, 3.597}, {60, 3.1}, {50, 2.575}, {30, 1.0 + 1.05 + 30*-30*70*7e-6},
	} {
		near(t, "MOS", emodel.MOS(c.r), c.mos, 0.001)
	}
}

func TestMOSIsMonotonicInR(t *testing.T) {
	prev := emodel.MOS(0)
	for r := 1.0; r <= 100; r += 0.5 {
		m := emodel.MOS(r)
		if m < prev-1e-9 {
			t.Fatalf("MOS fell from %.4f to %.4f at R=%.1f", prev, m, r)
		}
		prev = m
	}
}

func TestCleanG711(t *testing.T) {
	// 20 ms packet + 60 ms jitter buffer = 80 ms: Id = 0.024 * 80 = 1.92.
	r := emodel.RFactor(emodel.Params{Ie: 0, Bpl: 25.1, DelayMs: 80, BurstR: 1})
	near(t, "R", r, 91.28, 0.001)
	near(t, "MOS", emodel.MOS(r), 4.37, 0.01)
}

func TestDelayKnee(t *testing.T) {
	// Above 177.3 ms the delay impairment grows faster.
	lo := emodel.RFactor(emodel.Params{Bpl: 25.1, DelayMs: 150, BurstR: 1})
	hi := emodel.RFactor(emodel.Params{Bpl: 25.1, DelayMs: 250, BurstR: 1})
	near(t, "R at 150 ms", lo, 93.2-0.024*150, 1e-9)
	near(t, "R at 250 ms", hi, 93.2-0.024*250-0.11*(250-177.3), 1e-9)
}

func TestRandomLossOnG711(t *testing.T) {
	// Ie,eff = 95 * 5 / (5 + 25.1) = 15.781
	r := emodel.RFactor(emodel.Params{Ie: 0, Bpl: 25.1, LossPercent: 5, BurstR: 1, DelayMs: 80})
	near(t, "R", r, 93.2-1.92-95*5/30.1, 0.001)
}

func TestBurstsHurtMoreThanRandomLoss(t *testing.T) {
	p := emodel.Params{Ie: 0, Bpl: 25.1, LossPercent: 5, BurstR: 1, DelayMs: 80}
	random := emodel.RFactor(p)
	p.BurstR = 3
	if bursty := emodel.RFactor(p); bursty >= random {
		t.Errorf("bursty R %.1f not below random R %.1f", bursty, random)
	}
	p.BurstR = 0.2 // below 1 is not meaningful and is treated as random
	near(t, "R with BurstR<1", emodel.RFactor(p), random, 1e-9)
}

func TestCodecImpairmentCountsEvenWithoutLoss(t *testing.T) {
	g729 := emodel.RFactor(emodel.Params{Ie: 11, Bpl: 19, DelayMs: 85, BurstR: 1})
	near(t, "R", g729, 93.2-0.024*85-11, 1e-9)
}

func TestRating(t *testing.T) {
	for r, want := range map[float64]string{95: "very satisfied", 85: "satisfied", 75: "some users dissatisfied", 65: "many users dissatisfied", 55: "nearly all users dissatisfied", 20: "not recommended"} {
		if got := emodel.Rating(r); got != want {
			t.Errorf("Rating(%v) = %q, want %q", r, got, want)
		}
	}
}
