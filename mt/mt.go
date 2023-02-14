package mt

const w, n, m, r = 32, 624, 397, 31
const a, f = 0x9908B0DF, 1812433253
const u, d = 11, 0xFFFFFFFF
const s, b = 7, 0x9D2C5680
const t, c = 15, 0xEFC60000
const l = 18
const fullMask = 0xFFFFFFFF
const lowerMask = (1 << r) - 1
const upperMask = fullMask & (^lowerMask)

type MTRNG struct {
	mt   [n]int
	idx  int
	seed int
}

func NewMTRNG(seed int) *MTRNG {
	mt := MTRNG{seed: seed, idx: n}
	mt.mt[0] = seed
	for i := 1; i < n; i++ {
		mt.mt[i] = fullMask & (f*(mt.mt[i-1]^mt.mt[i-1]>>(w-2)) + i)
	}
	return &mt
}

func NewMTRNGWithState(state [n]int, idx int) *MTRNG {
	mt := MTRNG{}
	mt.mt = state
	mt.idx = idx
	return &mt
}

func (mt *MTRNG) Int() int {
	if mt.idx == n {
		mt.twist()
	}
	y := mt.mt[mt.idx]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	mt.idx++
	return y & fullMask
}

func (mt *MTRNG) IntWithOriginal() (int, int) {
	if mt.idx == n {
		mt.twist()
	}
	y := mt.mt[mt.idx]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	mt.idx++
	return y & fullMask, mt.mt[mt.idx-1] & fullMask
}

func (mt *MTRNG) twist() {
	for i := 0; i < n; i++ {
		x := (mt.mt[i] & upperMask) | (mt.mt[(i+1)%n] & lowerMask)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA ^ a
		}
		mt.mt[i] = mt.mt[(i+m)%n] ^ xA
	}
	mt.idx = 0
}
