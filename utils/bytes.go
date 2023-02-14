package utils

import (
	"math/rand"
)

func CountSetBits(b byte) int {
	cnt := 0
	for b != 0 {
		cnt++
		b = b & (b - 1)
	}
	return cnt
}

// PadBytes pads b to a multiple of n bytes
// according to PKCS#7 standard
func PadBytes(b []byte, n int) []byte {
	extra := len(b) % n
	pad := byte(n - extra)
	if pad == 0 {
		pad = byte(n)
	}
	res := make([]byte, len(b)+int(pad))
	copy(res, b)
	for i := len(b); i < len(b)+int(pad); i++ {
		res[i] = pad
	}
	return res
}

// RemovePad removes padding from b
func RemovePad(b []byte) []byte {
	if len(b) == 0 {
		return []byte{}
	}
	lastByte := b[len(b)-1]
	if len(b) < int(lastByte) {
		return b
	}
	for i := len(b) - int(lastByte); i < len(b); i++ {
		if b[i] != lastByte {
			return b
		}
	}
	res := make([]byte, len(b)-int(lastByte))
	copy(res, b)
	return res
}

// RandBytes returns a byte slice of n random bytes
func RandBytes(n int) (res []byte) {
	res = make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = byte(rand.Intn(1 << 8))
	}
	return
}

func RepBytes(c byte, n int) (res []byte) {
	res = make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = c
	}
	return
}

func ConcatBytes(b ...[]byte) (res []byte) {
	n := 0
	for i := 0; i < len(b); i++ {
		n += len(b[i])
	}
	res = make([]byte, n)
	pos := 0
	for i := 0; i < len(b); i++ {
		copy(res[pos:], b[i])
		pos += len(b[i])
	}
	return
}

func BitStringForInt(i int) string {
	s := ""
	for j := 31; j >= 0; j-- {
		if (i & (1 << j)) == 0 {
			s += "0"
		} else {
			s += "1"
		}
	}
	return s
}
