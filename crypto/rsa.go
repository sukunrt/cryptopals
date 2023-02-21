package crypto

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
	res := make([]byte, 0)
	for i := 0; i < len(b); i++ {
		a := BI(0).SetBytes(b[i : i+1])
		a.Exp(a, r.E, r.N)
		x := a.Bytes()
		for j := 0; j < r.Sz-len(x); j++ {
			res = append(res, 0)
		}
		res = append(res, x...)
	}
	return res
}

func DecryptRSA(b []byte, r RSA) []byte {
	res := make([]byte, 0)
	for i := 0; i < len(b); i += r.Sz {
		a := BI(0).SetBytes(b[i : i+r.Sz])
		a.Exp(a, r.D, r.N)
		res = append(res, a.Bytes()[0])
	}
	return res
}
