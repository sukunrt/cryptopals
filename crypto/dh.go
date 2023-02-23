package crypto

import (
	"bytes"
	"crypto/sha256"

	bi "github.com/sukunrt/cryptopals/bigint"
	"github.com/sukunrt/cryptopals/utils"
)

// DH represents a Diffie Hellman structure.
// P is a prime
// G is the random generator for the public key
// A is the public key
type DH struct {
	P  bi.BInt
	G  bi.BInt
	PA bi.BInt
	A  bi.BInt
}

// randBigInt returns a random integer between x and y
func randBigInt(x, y bi.BInt) bi.BInt {
	return bi.RandBInt(y.Sub(x)).Add(x)
}

// NewDH returns a new Diffie Hellman
func NewDH() DH {
	P := RandPrime()
	G := randBigInt(bi.Two, P)
	A := randBigInt(bi.One, P)
	PA := bi.Exp(G, A, P)
	return DH{P: P, A: A, G: G, PA: PA}
}

// NewDGBytes returns a new DH withing n bytes
func NewDHBytes(n int) DH {
	P := RandPrimeN(n)
	minVal := bi.FromInt(50)
	if P.Cmp(minVal) < 0 {
		minVal = P
	}
	G := randBigInt(bi.Two, minVal)
	A := randBigInt(bi.One, P)
	PA := bi.Exp(G, A, P)
	return DH{P: P, A: A, G: G, PA: PA}

}

// NewDGFromPAndG gives new DH struct with P = P and G = G
func NewDHFromPAndG(p, g bi.BInt) DH {
	A := randBigInt(bi.One, p)
	PA := bi.Exp(g, A, p)
	return DH{P: p, A: A, G: g, PA: PA}
}

// Make SessionKey takes the peers public key and adds our public key to it
func (dh DH) MakeSessionKey(X bi.BInt) bi.BInt {
	sk := bi.Exp(X, dh.A, dh.P)
	return sk
}

func SRPServer(password []byte) (bi.BInt, bi.BInt, bi.BInt, func(inputCh, outputCh chan []byte)) {
	dh := NewDH()
	k := bi.FromInt(3)
	salt := utils.RandBytes(16)
	shaHF := sha256.New()
	shaHF.Write(salt)
	shaHF.Write(password)
	x := bi.FromBytes(shaHF.Sum(nil))
	v := bi.Exp(dh.G, x, dh.P)
	return dh.P, dh.G, k, func(inputCh, outputCh chan []byte) {
		dhN := NewDHFromPAndG(dh.P, dh.G)
		A := <-inputCh

		outputCh <- salt
		B := k.Mul(v).Mod(dh.P).Add(dhN.PA).Mod(dh.P)
		outputCh <- B.Bytes()

		shaHF := sha256.New()
		shaHF.Write(A)
		shaHF.Write(B.Bytes())
		u := bi.FromBytes(shaHF.Sum(nil))
		S := bi.FromBytes(A).Mul(bi.Exp(v, u, dh.P))
		S = bi.Exp(S, dhN.A, dh.P)
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
