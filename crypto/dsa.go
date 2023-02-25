package crypto

import (
	"crypto/sha256"
	"errors"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/utils"
)

var ErrInvalidLen = errors.New("invalid bit length")

type DSAParams struct {
	P, Q, G bi.Int
}

type DSAPerUserParams struct {
	DSAParams
	X bi.Int // private key
	Y bi.Int // public key
}

func (d DSAParams) GenKey() DSAPerUserParams {
	x := bi.RandInt(d.Q.Sub(bi.One))
	y := bi.Exp(d.G, x, d.P)
	return DSAPerUserParams{DSAParams: d, X: x, Y: y}
}

func (d DSAPerUserParams) Sign(b []byte) (bi.Int, bi.Int) {
	sha := sha256.New()
	sha.Write(b)
	h := sha.Sum(nil)
	hi := bi.FromBytes(h)
	var r, s bi.Int
	for {
		k := bi.RandInt(d.Q.Sub(bi.One))
		r = bi.Exp(d.G, k, d.P).Mod(d.Q)
		if r.Equal(bi.Zero) {
			continue
		}
		s = ModInv(k, d.Q).Mul(hi.Add(d.X.Mul(r))).Mod(d.Q)
		if s.Equal(bi.Zero) {
			continue
		}
		break
	}
	return r, s
}

func (d DSAPerUserParams) Verify(b []byte, r, s bi.Int) bool {
	sha := sha256.New()
	sha.Write(b)
	h := sha.Sum(nil)
	hi := bi.FromBytes(h)
	w := ModInv(s, d.Q)
	u1 := hi.Mul(w).Mod(d.Q)
	u2 := r.Mul(w).Mod(d.Q)
	v := bi.Exp(d.G, u1, d.P).Mul(bi.Exp(d.Y, u2, d.P)).Mod(d.Q)
	return v.Equal(r)
}

// GenerateDSAPrimes generates p, q and g for DSA with SHA256 as the has function
func GenerateDSAPrimes(L, N int) (DSAParams, error) {
	if N >= L || N > 256 {
		return DSAParams{}, ErrInvalidLen
	}

	var p, q, g bi.Int

	// First generate q
	q = RandPrimeN(N / 8)

	for {
		b := utils.RandBytes(L / 8)
		b[0] |= 0x80
		b[len(b)-1] |= 1

		p = bi.FromBytes(b)
		rem := p.Mod(q).Sub(bi.One)
		p = p.Sub(rem)
		if p.BitLen() < L {
			continue
		}
		if MillerRabin(p) {
			break
		}
	}

	h := bi.Two
	for {
		e := p.Sub(bi.One).Div(q)
		g = bi.Exp(h, e, p)
		if !g.Equal(bi.One) {
			break
		}
		h = h.Add(bi.One)
	}
	return DSAParams{P: p, Q: q, G: g}, nil
}
