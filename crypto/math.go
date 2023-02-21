package crypto

import (
	"math/big"
	"math/rand"

	"github.com/sukunrt/cryptopals/utils"
)

var zero = big.NewInt(0)

type BInt = *big.Int

func BI(x int) BInt {
	return big.NewInt(int64(x))
}

func FromBytes(b []byte) BInt {
	return BI(0).SetBytes(b)
}

func Clone(x BInt) BInt {
	return BI(0).Set(x)
}

// CheckPrime checks primality of n using miller-rabin test
func CheckPrime(n *big.Int) bool {
	if n.Cmp(one) == 0 {
		return false
	}
	if n.Cmp(two) == 0 || n.Cmp(three) == 0 {
		return true
	}
	a := big.NewInt(0)
	a.Mod(n, big.NewInt(2))
	if a.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	n1 := big.NewInt(0).Sub(n, one)
	s, d := big.NewInt(0), copyBigInt(n1)
	for a.Mod(d, two).Cmp(one) != 0 {
		s.Add(s, one)
		d.Div(d, two)
	}

	maxWitness := 1000000
	rounds := 5
	for i := 0; i < rounds; i++ {
		a.Sub(n, big.NewInt(4))
		nn := rand.Intn(maxWitness) + 2
		if a.IsInt64() && int(a.Int64()) < maxWitness {
			nn = rand.Intn(int(a.Int64())) + 2
		}
		ni := big.NewInt(int64(nn))
		x := big.NewInt(0).Exp(ni, d, n)
		if x.Cmp(one) == 0 || x.Cmp(n1) == 0 {
			continue
		}
		witness := true
		for j := 0; big.NewInt(int64(j)).Cmp(s) < 0; j++ {
			x = big.NewInt(0).Mul(x, x)
			x.Mod(x, n)
			if x.Cmp(n1) == 0 {
				witness = false
				break
			}
		}
		if witness {
			return false
		}
	}
	return true
}

func RandPrime() *big.Int {
	for {
		x := utils.RandBytes(128)
		n := big.NewInt(0).SetBytes(x)
		if CheckPrime(n) {
			return n
		}
	}
}

func RandPrimeN(numBytes int) *big.Int {
	for {
		b := utils.RandBytes(numBytes)
		if b[0] == 0 {
			continue
		}
		r := big.NewInt(0).SetBytes(b)
		if CheckPrime(r) {
			return r
		}
	}
}

func gcd(a, b BInt) BInt {
	if a.Cmp(zero) == 0 {
		return b
	}
	return gcd(BI(0).Mod(b, a), a)
}

func egcd(a, b *big.Int) (*big.Int, *big.Int) {
	if a.Cmp(zero) == 0 {
		return BI(0), BI(1)
	} else {
		x, y := egcd(BI(0).Mod(b, a), a)
		m := BI(0).Div(b, a)
		m.Mul(m, x)
		m.Sub(y, m)
		return m, x
	}
}

func ModInv(a, n *big.Int) *big.Int {
	x, _ := egcd(a, n)
	x = x.Mod(x, n)
	for x.Cmp(zero) < 0 {
		x.Add(x, n)
		x.Mod(x, n)
	}
	return x
}

func CRT(c, n []BInt) BInt {
	N := BI(1)
	for _, nn := range n {
		N.Mul(N, nn)
	}
	ni := make([]BInt, len(n))
	mi := make([]BInt, len(n))
	for i := 0; i < len(ni); i++ {
		ni[i] = BI(0)
		ni[i].Div(N, n[i])
		mi[i] = ModInv(ni[i], n[i])
	}
	z := BI(0)
	for i := 0; i < len(ni); i++ {
		zi := BI(0).Mul(mi[i], ni[i])
		zi.Mul(zi, c[i])
		z.Add(z, zi)
	}
	return BI(0).Mod(z, N)
}
