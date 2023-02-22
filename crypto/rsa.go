package crypto

import (
	"github.com/sukunrt/cryptopals/utils"
)

type RSA struct {
	Sz                int
	P, Q, N, ET, E, D BInt
}

type RSAKey struct {
	E, N BInt
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
		nn := BI(0).Mul(p, q)
		p1, q1 := BI(0).Sub(p, BI(1)), BI(0).Sub(q, BI(1))
		et := BI(0).Mul(p1, q1)
		e := BI(3)

		if gcd(e, et).Cmp(BI(1)) != 0 {
			continue
		}
		d := ModInv(e, et)
		return RSA{2 * n, p, q, nn, et, e, d}
	}
}

func EncryptRSA(b []byte, r RSA) []byte {
	bi := FromBytes(b)
	if bi.Cmp(r.N) > 0 {
		return nil
	}
	return BI(0).Exp(bi, r.E, r.N).Bytes()

}

func DecryptRSA(b []byte, r RSA) []byte {
	bi := FromBytes(b)
	if bi.Cmp(r.N) > 0 {
		return nil
	}
	return BI(0).Exp(bi, r.D, r.N).Bytes()
}

func UnPaddedRSAOracle(m string) string {
	r := NewRSAN(20)
	p := r.PubKey()
	c := r.Encrypt([]byte(m))
	oracle := func(b []byte) []byte {
		return r.Decrypt(b)
	}
	s := utils.RandBytes(r.Sz - 1)
	si := FromBytes(s)
	sinv := ModInv(si, p.N)
	se := BI(0).Exp(si, p.E, p.N)
	cc := FromBytes(c)
	cc.Mul(cc, se)
	cc.Mod(cc, p.N)
	pc := oracle(cc.Bytes())
	pi := FromBytes(pc)
	pi.Mul(pi, sinv)
	pi.Mod(pi, p.N)
	mm := pi.Bytes()
	return string(mm)
}
