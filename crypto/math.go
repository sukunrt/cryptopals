package crypto

import (
	"errors"
	"fmt"
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

// PollardKangarooDiscreteLog finds y such that g^y = target mod p and a <= y <= b
func PollardKangarooDiscreteLog(target, a, b, g, p bi.Int) (bi.Int, error) {
	tries := 5
	for i := 0; i < tries; i++ {
		fmt.Println(i)
		cache := make(map[string]bi.Int)
		rv := func(y, k, m bi.Int) bi.Int {
			s := fmt.Sprintf("%s|%s", y.Mod(k), m)
			if v, ok := cache[s]; ok {
				return v
			}
			ii := bi.FromInt(i)
			cache[s] = (bi.Exp(bi.Two, y.Mod(k), m).Add(ii)).Mod(m).Add(bi.One)
			return cache[s]
		}
		jump := b.Sub(a).Sqrt()
		magic := jump.Mul(bi.FromInt((i + 1) * (i + 1)))
		N := jump.Mul(bi.FromInt(4))
		y := bi.Exp(g, b, p)
		x := bi.Zero
		fmt.Println(N)
		for i := bi.Zero; i.Cmp(N) < 0; i = i.Add(bi.One) {
			j := rv(y, magic, jump)
			x = x.Add(j)
			y = y.Mul(bi.Exp(g, j, p)).Mod(p)
		}
		ty := target
		tx := bi.Zero
		fmt.Println(N)
		for {
			j := rv(ty, magic, jump)
			if tx.Add(j).Cmp(b.Sub(a).Add(x)) > 0 || ty.Equal(y) {
				break
			}
			tx = tx.Add(j)
			ty = ty.Mul(bi.Exp(g, j, p)).Mod(p)
		}
		if ty.Equal(y) {
			return b.Add(x).Sub(tx).Mod(p.Sub(bi.One)), nil
		}
	}
	return bi.Zero, errors.New("pollard kangaroo failed")
}
