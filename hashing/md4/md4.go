package md4

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md4 implements the MD4 hash algorithm as defined in RFC 1320.
//
// Deprecated: MD4 is cryptographically broken and should should only be used
// where compatibility with legacy systems, not security, is the goal. Instead,
// use a secure hash like SHA-256 (from crypto/sha256).

import (
	"hash"
	"math/bits"
)

// The size of an MD4 checksum in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() *digest {
	d := new(digest)
	d.Reset()
	return d
}

func NewWithState(state [4]uint32, nn uint64) hash.Hash {
	d := new(digest)
	d.Reset()
	d.s = state
	d.len = nn
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// CSum returns the current checksum
func (d *digest) CSum() []byte {
	var res []byte
	for _, s := range d.s {
		res = append(res, byte(s>>0))
		res = append(res, byte(s>>8))
		res = append(res, byte(s>>16))
		res = append(res, byte(s>>24))
	}
	return res
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(digest)
	*d = *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}

	return in
}

var shift1 = []int{3, 7, 11, 19}
var shift2 = []int{3, 5, 9, 13}
var shift3 = []int{3, 9, 11, 15}

var xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
var xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

func _Block(dig *digest, p []byte) int {
	a := dig.s[0]
	b := dig.s[1]
	c := dig.s[2]
	d := dig.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= _Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// If this needs to be made faster in the future,
		// the usual trick is to unroll each of these
		// loops by a factor of 4; that lets you replace
		// the shift[] lookups with constants and,
		// with suitable variable renaming in each
		// unrolled body, delete the a, b, c, d = d, a, b, c
		// (or you can let the optimizer do the renaming).
		//
		// The index variables are uint so that % by a power
		// of two can be optimized easily by a compiler.

		// Round 1.
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[_Chunk:]
		n += _Chunk
	}

	dig.s[0] = a
	dig.s[1] = b
	dig.s[2] = c
	dig.s[3] = d
	return n
}
