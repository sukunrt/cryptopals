package crypto

import (
	"math/rand"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/utils"
)

func RandPrime() bi.Int {
	for {
		x := utils.RandBytes(128)
		n := bi.FromBytes(x)
		if MillerRabin(n) {
			return n
		}
	}
}

func RandPrimeN(numBytes int) bi.Int {
	for {
		b := utils.RandBytes(numBytes)
		b[len(b)-1] |= 1
		b[0] |= 0x80
		r := bi.FromBytes(b)
		if MillerRabin(r) {
			return r
		}
	}
}

func gcd(a, b bi.Int) bi.Int {
	if a.Equal(bi.Zero) {
		return b
	}
	return gcd(b.Mod(a), a)
}

func egcd(a, b bi.Int) (bi.Int, bi.Int) {
	if a.Equal(bi.Zero) {
		return bi.Zero, bi.One
	} else {
		x, y := egcd(b.Mod(a), a)
		m := b.Div(a).Mul(x)
		m = y.Sub(m)
		return m, x
	}
}

func ModInv(a, n bi.Int) bi.Int {
	x, _ := egcd(a, n)
	x = x.Mod(n)
	for x.Cmp(bi.Zero) < 0 {
		x = x.Add(n).Mod(n)
	}
	return x
}

func CRT(c, n []bi.Int) bi.Int {
	N := bi.FromInt(1)
	for _, nn := range n {
		N = N.Mul(nn)
	}
	ni := make([]bi.Int, len(n))
	mi := make([]bi.Int, len(n))
	for i := 0; i < len(ni); i++ {
		ni[i] = N.Div(n[i])
		mi[i] = ModInv(ni[i], n[i])
	}
	z := bi.Zero
	for i := 0; i < len(ni); i++ {
		zi := mi[i].Mul(ni[i]).Mul(c[i])
		z = z.Add(zi)
	}
	return z.Mod(N)
}

func MillerRabinRounds(n bi.Int, rounds int) bool {
	if n.IsInt64() && n.Int() < 20 {
		nn := n.Int()
		for i := 2; i < nn-1; i++ {
			if nn%i == 0 {
				return false
			}
		}
		return true
	}

	if n.Mod(bi.Two).Equal(bi.Zero) {
		return false
	}
	s, d := 0, n.Sub(bi.One)
	for d.Mod(bi.Two).Equal(bi.One) {
		s++
		d = d.Div(bi.Two)
	}
	mx := 1 << 60
	if n.IsInt64() {
		mx = n.Int() - 4
	}
outer:
	for i := 0; i < rounds; i++ {
		a := bi.FromInt(rand.Intn(mx) + 2)
		st := bi.Exp(a, d, n)
		if st.Equal(n.Sub(bi.One)) || st.Equal(bi.One) {
			continue
		}
		for j := 0; j < s-1; j++ {
			st = st.Mul(st).Mod(n)
			if st.Equal(bi.One) {
				return false
			} else if st.Equal(n.Sub(bi.One)) {
				continue outer
			}
		}
		st = st.Mul(st).Mod(n)
		if !st.Equal(bi.One) {
			return false
		}
	}
	return true
}

func MillerRabin(n bi.Int) bool {
	return MillerRabinRounds(n, 5)
}
