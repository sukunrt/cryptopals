package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	bi "github.com/sukunrt/bigint"
	"github.com/sukunrt/cryptopals/utils"
)

// DH represents a Diffie Hellman structure.
// P is a prime
// G is the random generator for the public key
// A is the public key
type DH struct {
	P  bi.Int
	G  bi.Int
	PA bi.Int
	A  bi.Int
}

// randBigInt returns a random integer between x and y
func randBigInt(x, y bi.Int) bi.Int {
	return bi.RandInt(y.Sub(x)).Add(x)
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
func NewDHFromPAndG(p, g bi.Int) DH {
	A := randBigInt(bi.One, p)
	PA := bi.Exp(g, A, p)
	return DH{P: p, A: A, G: g, PA: PA}
}

// Make SessionKey takes the peers public key and adds our public key to it
func (dh DH) MakeSessionKey(X bi.Int) bi.Int {
	sk := bi.Exp(X, dh.A, dh.P)
	return sk
}

func SRPServer(password []byte) (bi.Int, bi.Int, bi.Int, func(inputCh, outputCh chan []byte)) {
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

type DHGroup struct {
	P bi.Int
	G bi.Int
	O bi.Int
}

func DHSmallSubgroup(p bi.Int, o bi.Int, mx int) chan DHGroup {
	resCh := make(chan DHGroup)
	go func() {
		p1 := p.Sub(bi.One)
		j := p1.Div(o)
		for r := bi.Two; r.Int() < mx; r = r.Add(bi.One) {
			if j.Mod(r).Equal(bi.Zero) && !j.Div(r).Mod(r).Equal(bi.Zero) {
				double := false
				for x := bi.Two; x.Mul(x).Cmp(r) <= 0; x = x.Add(bi.One) {
					if r.Mod(x).Equal(bi.Zero) && r.Div(x).Mod(x).Equal(bi.Zero) {
						double = true
						break
					}
				}
				if double {
					continue
				}
				m := p1.Div(r)
				// We want h such that h^r = 1 => h ^ m != 1
				for {
					h := bi.RandInt(p1.Sub(bi.Two)).Add(bi.One)
					h = bi.Exp(h, m, p)
					if !h.Equal(bi.One) && !h.Equal(bi.Zero) {
						resCh <- DHGroup{P: p, G: h, O: r}
						break
					}
				}
			}
		}
		close(resCh)
	}()
	return resCh
}

type HandshakeMsg struct {
	Msg string
	Mac []byte
	PK  bi.Int
}

func DHSmallSubgroupAttack(p bi.Int, g bi.Int, o bi.Int, handshake func(bi.Int) HandshakeMsg) (bi.Int, bi.Int) {
	var rs []bi.Int
	var ks []bi.Int // y = k mod r
	rp := bi.One
	hash := sha256.New()
OUTER:
	for g := range DHSmallSubgroup(p, o, 1<<24) {
		for _, r := range rs {
			if !gcd(r, g.O).Equal(bi.One) {
				continue OUTER
			}
		}
		hm := handshake(g.G)
		found := false
		for i := bi.Zero; i.Cmp(g.O) < 0; i = i.Add(bi.One) {
			k := bi.Exp(g.G, i, p)
			b := append(k.Bytes(), []byte(hm.Msg)...)
			hash.Reset()
			_, err := hash.Write(b)
			if err != nil {
				panic(err)
			}
			mac := hash.Sum(nil)
			if bytes.Equal(mac, hm.Mac) {
				found = true
				rs = append(rs, g.O)
				ks = append(ks, i)
				rp = rp.Mul(g.O)
				if rp.Cmp(o) > 0 {
					break OUTER
				}
				break
			}
		}
		if !found {
			panic("failed")
		}
	}
	fmt.Println(rp, o)
	y := CRT(ks, rs)
	return y.Mod(p), rp
}

func DHSmallSubgroupWithPollardKangarooAttack(p bi.Int, g bi.Int, o bi.Int, handshake func(bi.Int) HandshakeMsg) bi.Int {
	var rs []bi.Int
	var ks []bi.Int // y = k mod r
	rp := bi.One
	hash := sha256.New()
	var Y bi.Int
OUTER:
	for g := range DHSmallSubgroup(p, o, 1<<20) {
		for _, r := range rs {
			if !gcd(r, g.O).Equal(bi.One) {
				continue OUTER
			}
		}
		hm := handshake(g.G)
		Y = hm.PK
		found := false
		for i := bi.Zero; i.Cmp(g.O) < 0; i = i.Add(bi.One) {
			k := bi.Exp(g.G, i, p)
			b := append(k.Bytes(), []byte(hm.Msg)...)
			hash.Reset()
			_, err := hash.Write(b)
			if err != nil {
				panic(err)
			}
			mac := hash.Sum(nil)
			if bytes.Equal(mac, hm.Mac) {
				found = true
				rs = append(rs, g.O)
				ks = append(ks, i)
				rp = rp.Mul(g.O)
				if o.Div(rp).Cmp(bi.FromInt(1<<36)) <= 0 {
					fmt.Println(rp, o)
					break OUTER
				}
				break
			}
		}
		if !found {
			panic("failed")
		}
	}
	k := CRT(ks, rs)
	// g ^ y = k + m*rp
	yy := Y.Mul(bi.Exp(g, p.Sub(bi.One).Sub(k), p)).Mod(p)
	gg := bi.Exp(g, rp, p)
	yt := bi.Zero
	if !yy.Equal(bi.One) {
		var err error
		fmt.Println(yy, o.Div(rp))
		yt, err = PollardKangarooDiscreteLog(yy, bi.Zero, o.Div(rp).Add(bi.Ten), gg, p)
		if err != nil {
			panic(err)
		}
	}
	return k.Add(yt.Mul(rp)).Mod(o)
}
