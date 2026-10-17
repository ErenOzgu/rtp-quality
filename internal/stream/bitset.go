package stream

// bitset is a growable set of small non-negative integers.
type bitset struct{ w []uint64 }

func (b *bitset) set(i int) {
	for i>>6 >= len(b.w) {
		n := len(b.w) * 2
		if n < 16 {
			n = 16
		}
		b.w = append(b.w, make([]uint64, n-len(b.w))...)
	}
	b.w[i>>6] |= 1 << (uint(i) & 63)
}

func (b *bitset) get(i int) bool {
	if i < 0 || i>>6 >= len(b.w) {
		return false
	}
	return b.w[i>>6]&(1<<(uint(i)&63)) != 0
}
