package wangmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/sukunrt/cryptopals/hashing/md4"
	"github.com/sukunrt/cryptopals/utils"
)

var rotL = bits.RotateLeft32

type WangMD4 struct {
	m              [16]uint32
	a, b, c, d     [16]uint32
	aa, bb, cc, dd uint32
	temp           uint32
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
	update := func(cc byte, v uint32, step int) {
		switch cc {
		case 'a':
			wmd.m[(step-1)*4] = rotR(v, shift[0][0]) - wmd.a[step-1] - ff(wmd.b[step-1], wmd.c[step-1], wmd.d[step-1])
			wmd.a[step] = v
			wmd.aa = v
		case 'd':
			wmd.m[(step-1)*4+1] = rotR(v, shift[0][1]) - wmd.d[step-1] - ff(wmd.a[step], wmd.b[step-1], wmd.c[step-1])
			wmd.d[step] = v
			wmd.dd = v
		case 'c':
			wmd.m[(step-1)*4+2] = rotR(v, shift[0][2]) - wmd.c[step-1] - ff(wmd.d[step], wmd.a[step], wmd.b[step-1])
			wmd.c[step] = v
			wmd.cc = v
		case 'b':
			wmd.m[(step-1)*4+3] = rotR(v, shift[0][3]) - wmd.b[step-1] - ff(wmd.c[step], wmd.d[step], wmd.a[step])
			wmd.b[step] = v
			wmd.bb = v
		}
	}
	var transforms = map[int]func() bool{
		1: func() bool {
			an := wmd.a[1] ^ pb(wmd.a[1], 7) ^ pb(wmd.b[0], 7)
			update('a', an, 1)
			return false
		},
		2: func() bool {
			dn := wmd.d[1] ^ pb(wmd.d[1], 7) ^ pb(wmd.d[1], 8) ^ pb(wmd.a[1], 8) ^ pb(wmd.d[1], 11) ^ pb(wmd.a[1], 11)
			update('d', dn, 1)
			return false

		},
		3: func() bool {
			cn := wmd.c[1] ^ pb(wmd.c[1], 7) ^ ob(7) ^ pb(wmd.c[1], 8) ^ ob(8) ^ pb(wmd.c[1], 11) ^ pb(wmd.c[1], 26) ^ pb(wmd.d[1], 26)
			update('c', cn, 1)
			return false

		},
		4: func() bool {
			bn := wmd.b[1] ^ pb(wmd.b[1], 7) ^ ob(7) ^ pb(wmd.b[1], 8) ^ pb(wmd.b[1], 11) ^ pb(wmd.b[1], 26)
			update('b', bn, 1)
			return false

		},
		5: func() bool {
			an := wmd.a[2] ^ pb(wmd.a[2], 8) ^ ob(8) ^ pb(wmd.a[2], 11) ^ ob(11) ^ pb(wmd.a[2], 26) ^ pb(wmd.a[2], 14) ^ pb(wmd.b[1], 14)
			update('a', an, 2)
			return false

		},
		6: func() bool {
			dn := wmd.d[2] ^ pb(wmd.d[2], 14) ^ pb(wmd.d[2], 19) ^ pb(wmd.a[2], 19) ^ pb(wmd.d[2], 20) ^ pb(wmd.a[2], 20) ^ pb(wmd.d[2], 21) ^ pb(wmd.a[2], 21) ^ pb(wmd.d[2], 22) ^ pb(wmd.a[2], 22) ^ pb(wmd.d[2], 26) ^ ob(26)
			update('d', dn, 2)
			return false

		},
		7: func() bool {
			cn := wmd.c[2] ^ pb(wmd.c[2], 13) ^ pb(wmd.d[2], 13) ^ pb(wmd.c[2], 14) ^ pb(wmd.c[2], 15) ^ pb(wmd.d[2], 15) ^ pb(wmd.c[2], 19) ^ pb(wmd.c[2], 20) ^ pb(wmd.c[2], 21) ^ ob(21) ^ pb(wmd.c[2], 22)
			update('c', cn, 2)
			return false

		},
		8: func() bool {
			bn := wmd.b[2] ^ pb(wmd.b[2], 13) ^ ob(13) ^ pb(wmd.b[2], 14) ^ ob(14) ^ pb(wmd.b[2], 15) ^ pb(wmd.b[2], 17) ^ pb(wmd.c[2], 17) ^ pb(wmd.b[2], 19) ^ pb(wmd.b[2], 20) ^ pb(wmd.b[2], 21) ^ pb(wmd.b[2], 22)
			update('b', bn, 2)
			return false
		},
		9: func() bool {
			an := wmd.a[3] ^ pb(wmd.a[3], 13) ^ ob(13) ^ pb(wmd.a[3], 14) ^ ob(14) ^ pb(wmd.a[3], 15) ^ ob(15) ^ pb(wmd.a[3], 17) ^ pb(wmd.a[3], 19) ^ pb(wmd.a[3], 20) ^ pb(wmd.a[3], 21) ^ pb(wmd.a[3], 23) ^ pb(wmd.b[2], 23) ^ pb(wmd.a[3], 22) ^ ob(22) ^ pb(wmd.a[3], 26) ^ pb(wmd.b[2], 26)
			update('a', an, 3)
			return false
		},
		10: func() bool {
			dn := wmd.d[3] ^ pb(wmd.d[3], 13) ^ ob(13) ^ pb(wmd.d[3], 14) ^ ob(14) ^ pb(wmd.d[3], 15) ^ ob(15) ^ pb(wmd.d[3], 17) ^ pb(wmd.d[3], 20) ^ pb(wmd.d[3], 21) ^ ob(21) ^ pb(wmd.d[3], 22) ^ ob(22) ^ pb(wmd.d[3], 23) ^ pb(wmd.d[3], 26) ^ ob(26) ^ pb(wmd.d[3], 30) ^ pb(wmd.a[3], 30)
			update('d', dn, 3)
			return false
		},
		11: func() bool {
			cn := wmd.c[3] ^ pb(wmd.c[3], 17) ^ ob(17) ^ pb(wmd.c[3], 20) ^ pb(wmd.c[3], 21) ^ pb(wmd.c[3], 22) ^ pb(wmd.c[3], 23) ^ pb(wmd.c[3], 26) ^ pb(wmd.c[3], 30) ^ ob(30) ^ pb(wmd.c[3], 32) ^ pb(wmd.d[3], 32)
			update('c', cn, 3)
			return false
		},
		12: func() bool {
			bn := wmd.b[3] ^ pb(wmd.b[3], 20) ^ pb(wmd.b[3], 21) ^ ob(21) ^ pb(wmd.b[3], 22) ^ ob(22) ^ pb(wmd.b[3], 23) ^ pb(wmd.c[3], 23) ^ pb(wmd.b[3], 26) ^ ob(26) ^ pb(wmd.b[3], 30) ^ pb(wmd.b[3], 32)
			update('b', bn, 3)
			return false
		},
		13: func() bool {
			an := wmd.a[4] ^ pb(wmd.a[4], 23) ^ pb(wmd.a[4], 26) ^ pb(wmd.a[4], 27) ^ pb(wmd.b[3], 27) ^ pb(wmd.a[4], 29) ^ pb(wmd.b[3], 29) ^ pb(wmd.a[4], 30) ^ ob(30) ^ pb(wmd.a[4], 32)
			update('a', an, 4)
			return false
		},
		14: func() bool {
			dn := wmd.d[4] ^ pb(wmd.d[4], 23) ^ pb(wmd.d[4], 26) ^ pb(wmd.d[4], 27) ^ ob(27) ^ pb(wmd.d[4], 29) ^ ob(29) ^ pb(wmd.d[4], 30) ^ pb(wmd.d[4], 32) ^ ob(32)
			update('d', dn, 4)
			return false
		},
		15: func() bool {
			cn := wmd.c[4] ^ pb(wmd.c[4], 19) ^ pb(wmd.d[4], 19) ^ pb(wmd.c[4], 23) ^ ob(23) ^ pb(wmd.c[4], 26) ^ ob(26) ^ pb(wmd.c[4], 27) ^ pb(wmd.c[4], 29) ^ pb(wmd.c[4], 30)
			update('c', cn, 4)
			return false
		},
		16: func() bool {
			bn := wmd.b[4] ^ pb(wmd.b[4], 19) ^ pb(wmd.b[4], 26) ^ ob(26) ^ pb(wmd.b[4], 27) ^ ob(27) ^ pb(wmd.b[4], 29) ^ ob(29) ^ pb(wmd.b[4], 30)
			update('b', bn, 4)
			return false
		},
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

func ff(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func gf(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func phi1(a, b, c, d, m, s uint32) uint32 {
	return rotL(a+ff(b, c, d)+m, int(s))
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

var shift = [][4]uint32{{3, 7, 11, 19}, {3, 5, 9, 13}, {3, 9, 11, 15}}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (wmd *WangMD4) GenCollision() ([]byte, []byte) {
	cnt := 1
	for {
		if cnt > 1000000000 {
			fmt.Println("quiccing here", cnt)
			return nil, nil
		}
		cnt++
		if cnt%10000 == 0 {
			fmt.Println(cnt)
		}
		m1 := utils.RandBytes(512 / 8)

		wmd.m = unpack(m1)
	START:

		wmd.aa = uint32(0x67452301)
		wmd.bb = uint32(0xEFCDAB89)
		wmd.cc = uint32(0x98BADCFE)
		wmd.dd = uint32(0x10325476)

		wmd.a[0] = wmd.aa
		wmd.b[0] = wmd.bb
		wmd.c[0] = wmd.cc
		wmd.d[0] = wmd.dd

		st := 0

		//round 0 begins here
		//round := 0

		wmd.aa = phi1(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[st], shift[0][st%4])
		wmd.a[1] = wmd.aa
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.dd = phi1(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[st], shift[0][st%4])
		wmd.d[1] = wmd.dd
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.cc = phi1(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[st], shift[0][st%4])
		wmd.c[1] = wmd.cc
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.bb = phi1(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[st], shift[0][st%4])
		wmd.b[1] = wmd.bb
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.aa = phi1(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[st], shift[0][st%4])
		wmd.a[2] = wmd.aa
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.dd = phi1(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[st], shift[0][st%4])
		wmd.d[2] = wmd.dd
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.cc = phi1(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[st], shift[0][st%4])
		wmd.c[2] = wmd.cc
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.bb = phi1(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[st], shift[0][st%4])
		wmd.b[2] = wmd.bb
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.aa = phi1(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[st], shift[0][st%4])
		wmd.a[3] = wmd.aa
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.dd = phi1(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[st], shift[0][st%4])
		wmd.d[3] = wmd.dd
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.cc = phi1(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[st], shift[0][st%4])
		wmd.c[3] = wmd.cc
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.bb = phi1(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[st], shift[0][st%4])
		wmd.b[3] = wmd.bb
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.aa = phi1(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[st], shift[0][st%4])
		wmd.a[4] = wmd.aa
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.dd = phi1(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[st], shift[0][st%4])
		wmd.d[4] = wmd.dd
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.cc = phi1(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[st], shift[0][st%4])
		wmd.c[4] = wmd.cc
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.bb = phi1(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[st], shift[0][st%4])
		wmd.b[4] = wmd.bb
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		//round 1 begins here
		round := 1
		wmd.temp = wmd.aa
		wmd.aa = phi2(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[0], shift[round][st%4])
		wmd.a[5] = wmd.aa
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		wmd.temp = wmd.dd
		wmd.dd = phi2(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[4], shift[round][st%4])
		wmd.d[5] = wmd.dd
		st++
		if ok := wmd.applyTransform(st); ok {
			goto START
		}

		// wmd.cc = phi2(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[8], shift[round][st%4])
		// wmd.c[5] = wmd.cc
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.bb = phi2(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[12], shift[round][st%4])
		// wmd.b[5] = wmd.bb
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.aa = phi2(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[1], shift[round][st%4])
		// wmd.a[6] = wmd.aa
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.dd = phi2(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[5], shift[round][st%4])
		// wmd.d[6] = wmd.dd
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.cc = phi2(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[9], shift[round][st%4])
		// wmd.c[6] = wmd.cc
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.bb = phi2(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[13], shift[round][st%4])
		// wmd.b[6] = wmd.bb
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.aa = phi2(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[2], shift[round][st%4])
		// wmd.a[7] = wmd.aa
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.dd = phi2(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[6], shift[round][st%4])
		// wmd.d[7] = wmd.dd
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.cc = phi2(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[10], shift[round][st%4])
		// wmd.c[7] = wmd.cc
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.bb = phi2(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[14], shift[round][st%4])
		// wmd.b[7] = wmd.bb
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.aa = phi2(wmd.aa, wmd.bb, wmd.cc, wmd.dd, wmd.m[3], shift[round][st%4])
		// wmd.a[8] = wmd.aa
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.dd = phi2(wmd.dd, wmd.aa, wmd.bb, wmd.cc, wmd.m[7], shift[round][st%4])
		// wmd.d[8] = wmd.dd
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.cc = phi2(wmd.cc, wmd.dd, wmd.aa, wmd.bb, wmd.m[11], shift[round][st%4])
		// wmd.c[8] = wmd.cc
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }

		// wmd.bb = phi2(wmd.bb, wmd.cc, wmd.dd, wmd.aa, wmd.m[15], shift[round][st%4])
		// wmd.b[8] = wmd.bb
		// st++
		// if ok := wmd.applyTransform(st); ok {
		// 	goto START
		// }
		m2 := wmd.getM2()
		msg1 := pack(wmd.m)
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

		return msg1, msg2
	}
}

func (wmd *WangMD4) getM2() [16]uint32 {
	var m2 = wmd.m

	m2[1] = m2[1] + ob(32)

	m2[2] = m2[2] + ob(32)

	m2[2] = m2[2] - ob(29)

	m2[12] = m2[12] - ob(17)

	return m2
}
