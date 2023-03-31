package wangmd

import (
	"bytes"
	"encoding/binary"
	"math/bits"

	"github.com/sukunrt/cryptopals/hashing/md4"
	"github.com/sukunrt/cryptopals/utils"
)

var rotL = bits.RotateLeft32

type WangMD4 struct {
	transforms map[int]func(a, b, c, d [16]uint32, m [16]uint32) ([16]uint32, bool)
	m          [16]uint32
	a, b, c, d [16]uint32
}

func pb(x uint32, y int) uint32 {
	return x & (1 << (y - 1))
}

func rotR(x uint32, y uint32) uint32 {
	return x >> y
}

var transforms = map[int]func(a, b, c, d, m [16]uint32) ([16]uint32, bool){
	1: func(a, b, c, d, m [16]uint32) ([16]uint32, bool) {
		//a1,7 = b0,7
		an := a[1] ^ (pb(a[1], 7) ^ pb(b[0], 7))
		m[0] = rotR(an, shift[0][0]) - a[0] - ff(b[0], c[0], d[0])
		return m, false
	},
	2: func(a, b, c, d, m [16]uint32) ([16]uint32, bool) {
		//d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
		dn := d[1] ^ (pb(d[1], 7)) ^ (pb(d[1], 8) ^ pb(a[1], 8)) ^ (pb(d[1], 11) ^ pb(a[1], 11))
		m[1] = rotR(dn, shift[0][1]) - d[0] - ff(a[0], b[0], c[0])
		return m, false
	},
	// 3: func(a, b, c, d, m [16]uint32) ([16]uint32, bool) {
	// 	//c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
	// 	cn := d[1] ^ (pb(d[1], 7)) ^ (pb(d[1], 8) ^ pb(a[1], 8)) ^ (pb(d[1], 11) ^ pb(a[1], 11))
	// 	m[0] = rotR(dn, shift[0][1]) - d[0] - ff(a[0], b[0], c[0])
	// 	return m, false
	// },
	// 4: func(a, b, c, d, m [16]uint32) ([16]uint32, bool) {
	// 	//d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
	// 	dn := d[1] ^ (pb(d[1], 7)) ^ (pb(d[1], 8) ^ pb(a[1], 8)) ^ (pb(d[1], 11) ^ pb(a[1], 11))
	// 	m[0] = rotR(dn, shift[0][1]) - d[0] - ff(a[0], b[0], c[0])
	// 	return m, false
	// },
	// 2: func(a, b, c, d, m [16]uint32) ([16]uint32, bool) {
	// 	//d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
	// 	dn := d[1] ^ (pb(d[1], 7)) ^ (pb(d[1], 8) ^ pb(a[1], 8)) ^ (pb(d[1], 11) ^ pb(a[1], 11))
	// 	m[0] = rotR(dn, shift[0][1]) - d[0] - ff(a[0], b[0], c[0])
	// 	return m, false
	// },
}

func ff(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func gf(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func hf(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func phi1(a, b, c, d, m, s uint32) uint32 {
	return rotL(a+ff(b, c, d)+m, int(s))
}

func phi2(a, b, c, d, m, s uint32) uint32 {
	return rotL(a+gf(b, c, d)+m+0x5A827999, int(s))
}

func phi3(a, b, c, d, m, s uint32) uint32 {
	return rotL(a+hf(b, c, d)+m+0x6ED9EBA1, int(s))
}

func setBit(x uint32, i int) uint32 {
	return x | (1 << (i - 1))
}

func unsetBit(x uint32, i int) uint32 {
	return x & (^uint32(1 << (i - 1)))
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

var shift = [][4]uint32{{3, 7, 11, 19}, {3, 5, 9, 13}, {3, 9, 11, 15}}

func (wmd *WangMD4) GenHash() ([]byte, []byte) {
	for {
		m1 := utils.RandBytes(64)
		wmd.m = unpack(m1)
		wmd.getM2()

	START:
		aa := uint32(0x67452301)
		bb := uint32(0xEFCDAB89)
		cc := uint32(0x98BADCFE)
		dd := uint32(0x10325476)

		wmd.a[0] = aa

		wmd.b[0] = bb

		wmd.c[0] = cc

		wmd.d[0] = dd

		a, b, c, d := aa, bb, cc, dd
		st := 0

		//round 0 begins here
		round := 0

		a = phi1(a, b, c, d, wmd.m[st], shift[0][st%4])
		wmd.a[1] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi1(d, a, b, c, wmd.m[st], shift[0][st%4])
		wmd.d[1] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi1(c, d, a, b, wmd.m[st], shift[0][st%4])
		wmd.c[1] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi1(b, c, d, a, wmd.m[st], shift[0][st%4])
		wmd.b[1] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi1(a, b, c, d, wmd.m[st], shift[0][st%4])
		wmd.a[2] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi1(d, a, b, c, wmd.m[st], shift[0][st%4])
		wmd.d[2] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi1(c, d, a, b, wmd.m[st], shift[0][st%4])
		wmd.c[2] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi1(b, c, d, a, wmd.m[st], shift[0][st%4])
		wmd.b[2] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi1(a, b, c, d, wmd.m[st], shift[0][st%4])
		wmd.a[3] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi1(d, a, b, c, wmd.m[st], shift[0][st%4])
		wmd.d[3] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi1(c, d, a, b, wmd.m[st], shift[0][st%4])
		wmd.c[3] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi1(b, c, d, a, wmd.m[st], shift[0][st%4])
		wmd.b[3] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi1(a, b, c, d, wmd.m[st], shift[0][st%4])
		wmd.a[4] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi1(d, a, b, c, wmd.m[st], shift[0][st%4])
		wmd.d[4] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi1(c, d, a, b, wmd.m[st], shift[0][st%4])
		wmd.c[4] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi1(b, c, d, a, wmd.m[st], shift[0][st%4])
		wmd.b[4] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		//round 1 begins here
		round = 1
		a = phi2(a, b, c, d, wmd.m[0], shift[round][st%4])
		wmd.a[5] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi2(d, a, b, c, wmd.m[4], shift[round][st%4])
		wmd.d[5] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi2(c, d, a, b, wmd.m[8], shift[round][st%4])
		wmd.c[5] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi2(b, c, d, a, wmd.m[12], shift[round][st%4])
		wmd.b[5] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi2(a, b, c, d, wmd.m[1], shift[round][st%4])
		wmd.a[6] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi2(d, a, b, c, wmd.m[5], shift[round][st%4])
		wmd.d[6] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi2(c, d, a, b, wmd.m[9], shift[round][st%4])
		wmd.c[6] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi2(b, c, d, a, wmd.m[13], shift[round][st%4])
		wmd.b[6] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi2(a, b, c, d, wmd.m[2], shift[round][st%4])
		wmd.a[7] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi2(d, a, b, c, wmd.m[6], shift[round][st%4])
		wmd.d[7] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi2(c, d, a, b, wmd.m[10], shift[round][st%4])
		wmd.c[7] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi2(b, c, d, a, wmd.m[14], shift[round][st%4])
		wmd.b[7] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi2(a, b, c, d, wmd.m[3], shift[round][st%4])
		wmd.a[8] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi2(d, a, b, c, wmd.m[7], shift[round][st%4])
		wmd.d[8] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi2(c, d, a, b, wmd.m[11], shift[round][st%4])
		wmd.c[8] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi2(b, c, d, a, wmd.m[15], shift[round][st%4])
		wmd.b[8] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		// round 2 begins here
		round = 2

		a = phi3(a, b, c, d, wmd.m[0], shift[round][st%4])
		wmd.a[9] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi3(d, a, b, c, wmd.m[8], shift[round][st%4])
		wmd.d[9] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi3(c, d, a, b, wmd.m[4], shift[round][st%4])
		wmd.c[9] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi3(b, c, d, a, wmd.m[12], shift[round][st%4])
		wmd.b[9] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi3(a, b, c, d, wmd.m[2], shift[round][st%4])
		wmd.a[10] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi3(d, a, b, c, wmd.m[10], shift[round][st%4])
		wmd.d[10] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi3(c, d, a, b, wmd.m[6], shift[round][st%4])
		wmd.c[10] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi3(b, c, d, a, wmd.m[14], shift[round][st%4])
		wmd.b[10] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi3(a, b, c, d, wmd.m[1], shift[round][st%4])
		wmd.a[11] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi3(d, a, b, c, wmd.m[9], shift[round][st%4])
		wmd.d[11] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi3(c, d, a, b, wmd.m[5], shift[round][st%4])
		wmd.c[11] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi3(b, c, d, a, wmd.m[13], shift[round][st%4])
		wmd.b[11] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		a = phi3(a, b, c, d, wmd.m[3], shift[round][st%4])
		wmd.a[12] = a
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		d = phi3(d, a, b, c, wmd.m[11], shift[round][st%4])
		wmd.d[12] = d
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		c = phi3(c, d, a, b, wmd.m[7], shift[round][st%4])
		wmd.c[12] = c
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		b = phi3(b, c, d, a, wmd.m[15], shift[round][st%4])
		wmd.b[12] = b
		st++
		if wmd.checkStep(st + 1) {
			goto START
		}

		msg1 := pack(wmd.m)
		msg2 := pack(wmd.getM2())

		md := md4.New()
		md.Write(msg1)
		h1 := md.Sum(nil)

		md.Reset()
		md.Write(msg2)
		h2 := md.Sum(nil)

		if !bytes.Equal(h1, h2) {
			continue
		}

		return msg1, msg2
	}
}

func (wmd *WangMD4) getM2() [16]uint32 {
	var m2 = wmd.m

	wmd.m[1] = unsetBit(wmd.m[1], 32)
	m2[1] = setBit(m2[1], 32)

	wmd.m[2] = unsetBit(wmd.m[2], 32)
	m2[2] = setBit(m2[2], 32)
	wmd.m[2] = setBit(wmd.m[2], 28)
	m2[2] = unsetBit(m2[2], 28)

	wmd.m[12] = setBit(wmd.m[12], 17)
	m2[12] = unsetBit(m2[12], 17)
	return m2
}

func (wmd *WangMD4) checkStep(st int) bool {
	_, ok := wmd.transforms[st+1]
	if ok {
		wmd.m, ok = wmd.transforms[st+1](wmd.a, wmd.b, wmd.c, wmd.d, wmd.m)
		return ok
	}
	return false
}
