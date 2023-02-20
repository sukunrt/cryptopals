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
	two   = big.NewInt(2)
	one   = big.NewInt(1)
	three = big.NewInt(3)
)

// NewDH returns a new Diffie Hellman
func NewDH() DH {
	P := RandPrime()
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
