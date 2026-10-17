// Package synth builds synthetic RTP captures with known impairments, for tests
// and for trying the analyzer without a PBX. It is deterministic: the same
// seed gives the same bytes.
package synth

// Rand is splitmix64: small, fast, and identical on every platform and Go version,
// which math/rand does not promise.
type Rand struct{ s uint64 }

// NewRand returns a generator for seed.
func NewRand(seed uint64) *Rand { return &Rand{s: seed} }

// Uint64 returns the next 64 random bits.
func (r *Rand) Uint64() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// Float64 returns a value in [0, 1).
func (r *Rand) Float64() float64 { return float64(r.Uint64()>>11) / (1 << 53) }
