package crypto

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"math/rand"

	"github.com/sukunrt/cryptopals/utils"
)

// DH represents a Diffie Hellman structure.
// P is a prime
// G is the random generator for the public key
// A is the public key
type DH struct {
	P  *big.Int
	G  *big.Int
	PA *big.Int
	A  *big.Int
}

func copyBigInt(x *big.Int) *big.Int {
	return big.NewInt(0).Set(x)
}

// randBigInt returns a random integer between x and y
func randBigInt(x, y *big.Int) *big.Int {
	maxInt := 1 << 62
	minInt := 1 << 50
	g := rand.Intn(maxInt-minInt) + minInt
	d := big.NewInt(0).Sub(y, x)
	if d.IsInt64() {
		g = rand.Intn(int(d.Int64()))
	}
	return big.NewInt(0).Add(big.NewInt(int64(g)), x)
}

var (
	zero  = big.NewInt(0)
	two   = big.NewInt(2)
	one   = big.NewInt(1)
	three = big.NewInt(3)
)

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
		if a.IsInt64() {
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

// NewDH returns a new Diffie Hellman
func NewDH() DH {
	var P *big.Int
	for {
		x := utils.RandBytes(128)
		n := big.NewInt(0).SetBytes(x)
		if CheckPrime(n) {
			P = n
			break
		}
	}
	G := randBigInt(big.NewInt(1000), big.NewInt(1000000))
	A := randBigInt(big.NewInt(1), P)
	PA := big.NewInt(0).Exp(G, A, P)
	return DH{P: P, A: A, G: G, PA: PA}
}

// NewDGBytes returns a new DH withing n bytes
func NewDHBytes(n int) DH {
	var P *big.Int
	for {
		x := utils.RandBytes(n)
		n := big.NewInt(0).SetBytes(x)
		if CheckPrime(n) {
			P = n
			break
		}
	}
	minVal := big.NewInt(50)
	if P.Cmp(minVal) < 0 {
		minVal = P
	}
	G := randBigInt(big.NewInt(1), minVal)
	A := randBigInt(big.NewInt(1), P)
	PA := big.NewInt(0).Exp(G, A, P)
	return DH{P: P, A: A, G: G, PA: PA}

}

// NewDGFromPAndG gives new DH struct with P = P and G = G
func NewDHFromPAndG(p, g *big.Int) DH {
	A := randBigInt(big.NewInt(1), p)
	PA := big.NewInt(0).Exp(g, A, p)
	return DH{P: copyBigInt(p), A: A, G: copyBigInt(g), PA: PA}
}

// Make SessionKey takes the peers public key and adds our public key to it
func (dh DH) MakeSessionKey(X *big.Int) *big.Int {
	sk := big.NewInt(0).Exp(X, dh.A, dh.P)
	return sk
}

func SRPServer(password []byte) (*big.Int, *big.Int, *big.Int, func(inputCh, outputCh chan []byte)) {
	dh := NewDH()
	k := big.NewInt(3)
	salt := utils.RandBytes(16)
	shaHF := sha256.New()
	shaHF.Write(salt)
	shaHF.Write(password)
	x := big.NewInt(0).SetBytes(shaHF.Sum(nil))
	v := big.NewInt(0).Exp(dh.G, x, dh.P)
	return dh.P, dh.G, k, func(inputCh, outputCh chan []byte) {
		dhN := NewDHFromPAndG(dh.P, dh.G)
		A := <-inputCh

		outputCh <- salt
		B := big.NewInt(0)
		B.Mul(k, v)
		B.Mod(B, dh.P)
		B.Add(B, dhN.PA)
		B.Mod(B, dh.P)
		outputCh <- B.Bytes()

		shaHF := sha256.New()
		shaHF.Write(A)
		shaHF.Write(B.Bytes())
		u := big.NewInt(0).SetBytes(shaHF.Sum(nil))
		S := big.NewInt(0).Mul(big.NewInt(0).SetBytes(A), big.NewInt(0).Exp(v, u, dh.P))
		S.Exp(S, dhN.A, dh.P)
		shaHF.Reset()
		shaHF.Write(S.Bytes())
		K := shaHF.Sum(nil)
		KK := <-inputCh
		if bytes.Equal(K, KK) {
			outputCh <- []byte("true")
		} else {
			outputCh <- []byte("false")
		}
	}
}
