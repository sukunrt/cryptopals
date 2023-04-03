package wangmd

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/md4"
)

var rotL = bits.RotateLeft32

type WangMD4 struct {
	m              [16]uint32
	a, b, c, d     [16]uint32
	aa, bb, cc, dd uint32
	temp           uint32
	st             int
}

func pb(x uint32, y int) uint32 {
	return x & (1 << (y - 1))
}

func rotR(x uint32, y uint32) uint32 {
	return bits.RotateLeft32(x, -int(y))
}

func ob(x int) uint32 {
	return (1 << (x - 1))
}

func (wmd *WangMD4) applyTransform(st int) bool {
	var transforms = map[int]func() bool{
		17: func() bool {
			restart := false
			tf := func(x int) {
				om := wmd.m[0]
				wmd.m[0] = om + (ob(x - 3))
				v := phi2(wmd.temp, wmd.bb, wmd.cc, wmd.dd, wmd.m[0], shift[1][0])
				if pb(wmd.a[5], x) == pb(v, x) {
					wmd.m[0] = om - (ob(x - 3))
				}
				wmd.a[1] = phi1(wmd.a[0], wmd.b[0], wmd.c[0], wmd.d[0], wmd.m[0], shift[0][0])
				wmd.m[1] = rotR(wmd.d[1], 7) - wmd.d[0] - ff(wmd.a[1], wmd.b[0], wmd.c[0])
				wmd.m[2] = rotR(wmd.c[1], 11) - wmd.c[0] - ff(wmd.d[1], wmd.a[1], wmd.b[0])
				wmd.m[3] = rotR(wmd.b[1], 19) - wmd.b[0] - ff(wmd.c[1], wmd.d[1], wmd.a[1])
				wmd.m[4] = rotR(wmd.a[2], 3) - wmd.a[1] - ff(wmd.b[1], wmd.c[1], wmd.d[1])
			}

			if pb(wmd.a[5], 19) != pb(wmd.c[4], 19) {
				tf(19)
				restart = true
			}
			if pb(wmd.a[5], 26) != ob(26) {
				tf(26)
				restart = true
			}
			if pb(wmd.a[5], 27) != 0 {
				tf(27)
				restart = true
			}
			if pb(wmd.a[5], 29) != ob(29) {
				tf(29)
				restart = true
			}
			if pb(wmd.a[5], 32) != ob(32) {
				tf(32)
				restart = true
			}
			return restart
		},
		18: func() bool {
			restart := false
			tf := func(x int) {
				om := wmd.m[4]
				wmd.m[4] = om + (ob(x - 5))
				v := phi2(wmd.temp, wmd.aa, wmd.bb, wmd.cc, wmd.m[4], shift[1][1])
				if pb(wmd.d[5], x) == pb(v, x) {
					wmd.m[4] = om - (ob(x - 5))
				}
				wmd.a[2] = phi1(wmd.a[1], wmd.b[1], wmd.c[1], wmd.d[1], wmd.m[4], shift[0][0])
				wmd.m[5] = rotR(wmd.d[2], 7) - wmd.d[1] - ff(wmd.a[2], wmd.b[1], wmd.c[1])
				wmd.m[6] = rotR(wmd.c[2], 11) - wmd.c[1] - ff(wmd.d[2], wmd.a[2], wmd.b[1])
				wmd.m[7] = rotR(wmd.b[2], 19) - wmd.b[1] - ff(wmd.c[2], wmd.d[2], wmd.a[2])
				wmd.m[8] = rotR(wmd.a[3], 3) - wmd.a[2] - ff(wmd.b[2], wmd.c[2], wmd.d[2])
			}
			if pb(wmd.d[5], 19) != pb(wmd.a[5], 19) {
				tf(19)
				restart = true
			}
			if pb(wmd.d[5], 26) != pb(wmd.b[4], 26) {
				tf(26)
				restart = true
			}
			if pb(wmd.d[5], 27) != pb(wmd.b[4], 27) {
				tf(27)
				restart = true
			}
			if pb(wmd.d[5], 29) != pb(wmd.b[4], 29) {
				tf(29)
				restart = true
			}
			if pb(wmd.d[5], 32) != pb(wmd.b[4], 32) {
				tf(32)
				restart = true
			}
			return restart
		},
	}
	f, ok := transforms[st]
	if ok {
		return f()
	}
	return false
}

func (wmd *WangMD4) applySingleTransform() {
	switch wmd.st {
	case 1:
		wmd.a[1] = wmd.a[1] ^ pb(wmd.a[1], 7) ^ pb(wmd.b[0], 7)
	case 2:
		wmd.d[1] = wmd.d[1] ^ pb(wmd.d[1], 7) ^ pb(wmd.d[1], 8) ^ pb(wmd.a[1], 8) ^ pb(wmd.d[1], 11) ^ pb(wmd.a[1], 11)
	case 3:
		wmd.c[1] = wmd.c[1] ^ pb(wmd.c[1], 7) ^ ob(7) ^ pb(wmd.c[1], 8) ^ ob(8) ^ pb(wmd.c[1], 11) ^ pb(wmd.c[1], 26) ^ pb(wmd.d[1], 26)
	case 4:
		wmd.b[1] = wmd.b[1] ^ pb(wmd.b[1], 7) ^ ob(7) ^ pb(wmd.b[1], 8) ^ pb(wmd.b[1], 11) ^ pb(wmd.b[1], 26)
	case 5:
		wmd.a[2] = wmd.a[2] ^ pb(wmd.a[2], 8) ^ ob(8) ^ pb(wmd.a[2], 11) ^ ob(11) ^ pb(wmd.a[2], 26) ^ pb(wmd.a[2], 14) ^ pb(wmd.b[1], 14)
	case 6:
		wmd.d[2] = wmd.d[2] ^ pb(wmd.d[2], 14) ^ pb(wmd.d[2], 19) ^ pb(wmd.a[2], 19) ^ pb(wmd.d[2], 20) ^ pb(wmd.a[2], 20) ^ pb(wmd.d[2], 21) ^ pb(wmd.a[2], 21) ^ pb(wmd.d[2], 22) ^ pb(wmd.a[2], 22) ^ pb(wmd.d[2], 26) ^ ob(26)
	case 7:
		wmd.c[2] = wmd.c[2] ^ pb(wmd.c[2], 13) ^ pb(wmd.d[2], 13) ^ pb(wmd.c[2], 14) ^ pb(wmd.c[2], 15) ^ pb(wmd.d[2], 15) ^ pb(wmd.c[2], 19) ^ pb(wmd.c[2], 20) ^ pb(wmd.c[2], 21) ^ ob(21) ^ pb(wmd.c[2], 22)
	case 8:
		wmd.b[2] = wmd.b[2] ^ pb(wmd.b[2], 13) ^ ob(13) ^ pb(wmd.b[2], 14) ^ ob(14) ^ pb(wmd.b[2], 15) ^ pb(wmd.b[2], 17) ^ pb(wmd.c[2], 17) ^ pb(wmd.b[2], 19) ^ pb(wmd.b[2], 20) ^ pb(wmd.b[2], 21) ^ pb(wmd.b[2], 22)
	case 9:
		wmd.a[3] = wmd.a[3] ^ pb(wmd.a[3], 13) ^ ob(13) ^ pb(wmd.a[3], 14) ^ ob(14) ^ pb(wmd.a[3], 15) ^ ob(15) ^ pb(wmd.a[3], 17) ^ pb(wmd.a[3], 19) ^ pb(wmd.a[3], 20) ^ pb(wmd.a[3], 21) ^ pb(wmd.a[3], 23) ^ pb(wmd.b[2], 23) ^ pb(wmd.a[3], 22) ^ ob(22) ^ pb(wmd.a[3], 26) ^ pb(wmd.b[2], 26)
	case 10:
		wmd.d[3] = wmd.d[3] ^ pb(wmd.d[3], 13) ^ ob(13) ^ pb(wmd.d[3], 14) ^ ob(14) ^ pb(wmd.d[3], 15) ^ ob(15) ^ pb(wmd.d[3], 17) ^ pb(wmd.d[3], 20) ^ pb(wmd.d[3], 21) ^ ob(21) ^ pb(wmd.d[3], 22) ^ ob(22) ^ pb(wmd.d[3], 23) ^ pb(wmd.d[3], 26) ^ ob(26) ^ pb(wmd.d[3], 30) ^ pb(wmd.a[3], 30)
	case 11:
		wmd.c[3] = wmd.c[3] ^ pb(wmd.c[3], 17) ^ ob(17) ^ pb(wmd.c[3], 20) ^ pb(wmd.c[3], 21) ^ pb(wmd.c[3], 22) ^ pb(wmd.c[3], 23) ^ pb(wmd.c[3], 26) ^ pb(wmd.c[3], 30) ^ ob(30) ^ pb(wmd.c[3], 32) ^ pb(wmd.d[3], 32)
	case 12:
		wmd.b[3] = wmd.b[3] ^ pb(wmd.b[3], 20) ^ pb(wmd.b[3], 21) ^ ob(21) ^ pb(wmd.b[3], 22) ^ ob(22) ^ pb(wmd.b[3], 23) ^ pb(wmd.c[3], 23) ^ pb(wmd.b[3], 26) ^ ob(26) ^ pb(wmd.b[3], 30) ^ pb(wmd.b[3], 32)
	case 13:
		wmd.a[4] = wmd.a[4] ^ pb(wmd.a[4], 23) ^ pb(wmd.a[4], 26) ^ pb(wmd.a[4], 27) ^ pb(wmd.b[3], 27) ^ pb(wmd.a[4], 29) ^ pb(wmd.b[3], 29) ^ pb(wmd.a[4], 30) ^ ob(30) ^ pb(wmd.a[4], 32)
	case 14:
		wmd.d[4] = wmd.d[4] ^ pb(wmd.d[4], 23) ^ pb(wmd.d[4], 26) ^ pb(wmd.d[4], 27) ^ ob(27) ^ pb(wmd.d[4], 29) ^ ob(29) ^ pb(wmd.d[4], 30) ^ pb(wmd.d[4], 32) ^ ob(32)
	case 15:
		wmd.c[4] = wmd.c[4] ^ pb(wmd.c[4], 19) ^ pb(wmd.d[4], 19) ^ pb(wmd.c[4], 23) ^ ob(23) ^ pb(wmd.c[4], 26) ^ ob(26) ^ pb(wmd.c[4], 27) ^ pb(wmd.c[4], 29) ^ pb(wmd.c[4], 30)
	case 16:
		wmd.b[4] = wmd.b[4] ^ pb(wmd.b[4], 19) ^ pb(wmd.b[4], 26) ^ ob(26) ^ pb(wmd.b[4], 27) ^ ob(27) ^ pb(wmd.b[4], 29) ^ ob(29) ^ pb(wmd.b[4], 30)
	}

}

func ff(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func gf(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func phi1(a, b, c, d, m, s uint32) uint32 {
	return rotL(a+ff(b, c, d)+m, int(s))
}

func phi1Inv(an, ao, b, c, d, s uint32) uint32 {
	return rotR(an, s) - ao - ff(b, c, d)
}

func phi2(a, b, c, d, m, s uint32) uint32 {
	return rotL(a+gf(b, c, d)+m+0x5A827999, int(s))
}

func unpack(msg []byte) [16]uint32 {
	var m [16]uint32
	j := 0
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint32(msg[j : j+4])
		j += 4
	}
	return m
}

func pack(m [16]uint32) []byte {
	msg := make([]byte, 0)
	for i := 0; i < 16; i++ {
		msg = binary.LittleEndian.AppendUint32(msg, m[i])
	}
	return msg
}

var shift = [][4]uint32{{3, 7, 11, 19}, {3, 5, 9, 11}}

func (wmd *WangMD4) GenCollision() ([]byte, []byte, error) {
	cnt := 0
	m1 := make([]byte, 512/8)
	for {
		cnt++
		if cnt > 1000000 {
			return nil, nil, errors.New("failed")
		}
		rand.Read(m1)
		wmd.m = unpack(m1)
	START:

		wmd.a[0] = uint32(0x67452301)
		wmd.b[0] = uint32(0xEFCDAB89)
		wmd.c[0] = uint32(0x98BADCFE)
		wmd.d[0] = uint32(0x10325476)

		wmd.st = 0
		for j := 0; j < 4; j++ {
			wmd.st++
			wmd.a[j+1] = phi1(wmd.a[j], wmd.b[j], wmd.c[j], wmd.d[j], wmd.m[wmd.st-1], shift[0][0])
			wmd.applySingleTransform()
			wmd.m[wmd.st-1] = phi1Inv(wmd.a[j+1], wmd.a[j], wmd.b[j], wmd.c[j], wmd.d[j], shift[0][0])

			wmd.st++
			wmd.d[j+1] = phi1(wmd.d[j], wmd.a[j+1], wmd.b[j], wmd.c[j], wmd.m[wmd.st-1], shift[0][1])
			wmd.applySingleTransform()
			wmd.m[wmd.st-1] = phi1Inv(wmd.d[j+1], wmd.d[j], wmd.a[j+1], wmd.b[j], wmd.c[j], shift[0][1])

			wmd.st++
			wmd.c[j+1] = phi1(wmd.c[j], wmd.d[j+1], wmd.a[j+1], wmd.b[j], wmd.m[wmd.st-1], shift[0][2])
			wmd.applySingleTransform()
			wmd.m[wmd.st-1] = phi1Inv(wmd.c[j+1], wmd.c[j], wmd.d[j+1], wmd.a[j+1], wmd.b[j], shift[0][2])

			wmd.st++
			wmd.b[j+1] = phi1(wmd.b[j], wmd.c[j+1], wmd.d[j+1], wmd.a[j+1], wmd.m[wmd.st-1], shift[0][3])
			wmd.applySingleTransform()
			wmd.m[wmd.st-1] = phi1Inv(wmd.b[j+1], wmd.b[j], wmd.c[j+1], wmd.d[j+1], wmd.a[j+1], shift[0][3])
		}

		wmd.a[5] = phi2(wmd.a[4], wmd.b[4], wmd.c[4], wmd.d[4], wmd.m[0], shift[1][0])
		wmd.st++
		if ok := wmd.applyTransform(wmd.st); ok {
			goto START
		}

		wmd.temp = wmd.dd
		wmd.d[5] = phi2(wmd.d[4], wmd.a[5], wmd.b[4], wmd.c[4], wmd.m[4], shift[1][1])
		wmd.st++
		if ok := wmd.applyTransform(wmd.st); ok {
			goto START
		}

		msg1 := pack(wmd.m)
		m2 := wmd.getM2()
		msg2 := pack(m2)

		md := md4.New()
		md.Write(msg1)
		h1 := md.Sum(nil)

		md.Reset()
		md.Write(msg2)
		h2 := md.Sum(nil)

		if !bytes.Equal(h1, h2) {
			continue
		}

		return msg1, msg2, nil
	}
}

func (wmd *WangMD4) getM2() [16]uint32 {
	var m2 = wmd.m

	m2[1] = m2[1] + ob(32)

	m2[2] = m2[2] + ob(32) - ob(29)

	m2[12] = m2[12] - ob(17)
	return m2
}
