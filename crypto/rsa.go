package crypto

import (
	"bytes"
	"crypto/sha256"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/utils"
)

type RSA struct {
	Sz                int
	P, Q, N, ET, E, D bi.Int
}

type RSAKey struct {
	E, N bi.Int
	Sz   int
}

func (r RSA) Encrypt(b []byte) []byte {
	return EncryptRSAWithPublicKey(b, r)
}

func (r RSA) Decrypt(b []byte) []byte {
	return DecryptRSAWithPrivateKey(b, r)
}

func (r RSA) Sign(msg []byte) []byte {
	sha := sha256.New()
	sha.Write(msg)
	digest := sha.Sum(nil)
	padLen := r.Sz - len(digest) - 2 - 2 - 1 // 2 prefix, 2 hashId, 1 suffix
	i := 0
	block := make([]byte, r.Sz)
	block[i] = 0
	i++
	block[1] = 1
	i++
	for j := 0; j < padLen; i, j = i+1, j+1 {
		block[i] = 0xFF
	}
	block[i] = 00
	i++
	block[i] = 0xA
	i++
	block[i] = 0xB
	i++
	copy(block[i:], digest)
	return EncryptRSA(block, r.D, r.N, r.Sz)
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

func EncryptRSAWithPublicKey(b []byte, r RSA) []byte {
	return EncryptRSA(b, r.E, r.N, r.Sz)
}

func DecryptRSAWithPrivateKey(b []byte, r RSA) []byte {
	return EncryptRSA(b, r.D, r.N, r.Sz)
}

func EncryptRSA(b []byte, exp, N bi.Int, sz int) []byte {
	i := bi.FromBytes(b)
	if i.Cmp(N) > 0 {
		return nil
	}
	bytes := bi.Exp(i, exp, N).Bytes()
	bytes = append(utils.RepBytes(0, sz-len(bytes)), bytes...)
	return bytes
}

func VerifyRSASignatureCorrect(msg []byte, signature []byte, r RSA) bool {
	block := r.Encrypt(signature)
	i := 0
	if block[i] != 0 {
		return false
	}
	i++
	if block[i] != 1 {
		return false
	}
	i++
	for ; i < len(block); i++ {
		if block[i] != 0xFF {
			break
		}
	}
	if i == len(block) {
		return false
	}

	if block[i] != 0 {
		return false
	}
	i++

	if i+32+2 != len(block) {
		return false
	}
	i += 2

	sha := sha256.New()
	sha.Write(msg)
	return bytes.Equal(block[i:], sha.Sum(nil))
}

func VerifyRSASignatureInCorrect(msg []byte, signature []byte, r RSA) bool {
	block := r.Encrypt(signature)
	i := 0
	if block[i] != 0 {
		return false
	}
	i++
	if block[i] != 1 {
		return false
	}
	i++
	for ; i < len(block); i++ {
		if block[i] != 0xFF {
			break
		}
	}
	if i == len(block) {
		return false
	}
	if block[i] != 0 {
		return false
	}
	i++
	i += 2
	sha := sha256.New()
	sha.Write(msg)
	return bytes.Equal(block[i:i+32], sha.Sum(nil))
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
