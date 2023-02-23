package crypto

import (
	bi "github.com/sukunrt/cryptopals/bigint"
	"github.com/sukunrt/cryptopals/utils"
)

type RSA struct {
	Sz                int
	P, Q, N, ET, E, D bi.BInt
}

type RSAKey struct {
	E, N bi.BInt
	Sz   int
}

func (r RSA) Encrypt(b []byte) []byte {
	return EncryptRSA(b, r)
}

func (r RSA) Decrypt(b []byte) []byte {
	return DecryptRSA(b, r)
}

func (r RSA) PubKey() RSAKey {
	return RSAKey{E: r.E, N: r.N, Sz: r.Sz}
}

func NewRSAN(n int) RSA {
	for {
		p, q := RandPrimeN(n), RandPrimeN(n)
		nn := p.Mul(q)
		p1, q1 := p.Sub(bi.One), q.Sub(bi.One)
		et := p1.Mul(q1)
		e := bi.FromInt(3)

		if !gcd(e, et).Equal(bi.One) {
			continue
		}
		d := ModInv(e, et)
		return RSA{2 * n, p, q, nn, et, e, d}
	}
}

func EncryptRSA(b []byte, r RSA) []byte {
	i := bi.FromBytes(b)
	if i.Cmp(r.N) > 0 {
		return nil
	}
	return bi.Exp(i, r.E, r.N).Bytes()
}

func DecryptRSA(b []byte, r RSA) []byte {
	i := bi.FromBytes(b)
	if i.Cmp(r.N) > 0 {
		return nil
	}
	return bi.Exp(i, r.D, r.N).Bytes()
}

func UnPaddedRSAOracle(m string) string {
	r := NewRSAN(128)
	p := r.PubKey()
	c := r.Encrypt([]byte(m))
	oracle := func(b []byte) []byte {
		return r.Decrypt(b)
	}
	s := utils.RandBytes(r.Sz - 1)
	si := bi.FromBytes(s)
	sinv := ModInv(si, p.N)
	se := bi.Exp(si, p.E, p.N)
	cc := bi.FromBytes(c).Mul(se).Mod(p.N)
	pc := oracle(cc.Bytes())
	pi := bi.FromBytes(pc).Mul(sinv).Mod(p.N)
	mm := pi.Bytes()
	return string(mm)
}
