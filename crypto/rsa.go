package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"

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

func EncryptRSAWithPadding(b []byte, r RSA) []byte {
	return r.Encrypt(PadBlock(b, r))
}

func ValidPadding(b []byte, r RSA) bool {
	blk := r.Decrypt(b)
	return blk[0] == 0 && blk[1] == 2
}

func RemovePadding(b []byte) []byte {
	for i := 2; i < len(b); i++ {
		if b[i] == 0 {
			return b[i+1:]
		}
	}
	return nil
}

func PadBlock(b []byte, r RSA) []byte {
	res := make([]byte, r.Sz)
	res[0] = 0
	res[1] = 2
	padSize := r.Sz - len(b) - 3
	res[2+padSize] = 0
	copy(res[3+padSize:], b)
	rb := utils.RandBytes(padSize)
	for i := 0; i < padSize; i++ {
		for rb[i] == 0 {
			rb[i] = byte(rand.Intn(1 << 8))
		}
		res[2+i] = rb[i]
	}
	return res
}

func CeilDiv(a, b bi.Int) bi.Int {
	return a.Add(b.Sub(bi.One)).Div(b)
}

func FloorDiv(a, b bi.Int) bi.Int {
	return a.Div(b)
}

type interval struct {
	a, b bi.Int
}

func (i interval) String() string {
	return fmt.Sprintf("interval{%s, %s}", i.a.String(), i.b.String())
}

func BreakRSAWithPaddingOracle(c []byte, oracle func([]byte) bool, r RSA) []byte {
	B := bi.Exp(bi.Two, bi.FromInt(r.Sz*8-16), bi.Zero)
	B2 := B.Mul(bi.Two)
	B3 := B.Mul(bi.Three)
	B31 := B3.Sub(bi.One)
	ci := bi.FromBytes(c)
	M := []interval{{B.Mul(bi.Two), B.Mul(bi.Three).Sub(bi.One)}}
	N := r.N
	i := 0
	var s bi.Int
	for {
		switch {
		case i == 0:
			i++
			for s = CeilDiv(N, B3); s.Cmp(N) < 0; s = s.Add(bi.One) {
				se := bi.FromBytes(r.Encrypt(s.Bytes()))
				valid := oracle(ci.Mul(se).Mod(N).Bytes())
				if valid {
					break
				}
			}
		case len(M) > 1:
			for s = s.Add(bi.One); s.Cmp(N) < 0; s = s.Add(bi.One) {
				se := bi.FromBytes(r.Encrypt(s.Bytes()))
				valid := oracle(ci.Mul(se).Mod(N).Bytes())
				if valid {
					break
				}
			}
		default:
			if M[0].b.Sub(M[0].a).Equal(bi.Zero) {
				return M[0].b.Bytes()
			}
			a, b := M[0].a, M[0].b
			sprev := s
		outer:
			for ri := bi.Two.Mul(b.Mul(sprev).Sub(B2)).Div(N); ; ri = ri.Add(bi.One) {
				sst := CeilDiv(B2.Add(ri.Mul(N)), b)
				sed := FloorDiv(B3.Add(ri.Mul(N)), a)
				for s = sst; s.Cmp(sed) <= 0; s = s.Add(bi.One) {
					se := bi.FromBytes(r.Encrypt(s.Bytes()))
					valid := oracle(ci.Mul(se).Mod(N).Bytes())
					if valid {
						break outer
					}
				}
			}
		}

		var NM []interval
		for _, ival := range M {
			a, b := ival.a, ival.b
			rst := CeilDiv(a.Mul(s).Sub(B31), N)
			red := FloorDiv(b.Mul(s).Sub(B2), N)
			for ri := rst; ri.Cmp(red) <= 0; ri = ri.Add(bi.One) {
				ist := CeilDiv(B2.Add(ri.Mul(N)), s)
				ied := FloorDiv(B31.Add(ri.Mul(N)), s)
				if ist.Cmp(a) < 0 {
					ist = a
				}
				if ied.Cmp(b) > 0 {
					ied = b
				}
				if ist.Cmp(B31) > 0 || ied.Cmp(B2) < 0 || ied.Cmp(ist) < 0 {
					continue
				}
				nival := interval{a: ist, b: ied}
				found := false
				for _, iival := range NM {
					if nival.a.Equal(iival.a) && nival.b.Equal(iival.b) {
						found = true
						break
					}
				}
				if !found {
					NM = append(NM, nival)
				}
			}
		}
		M = NM
	}
}
