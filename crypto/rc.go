package crypto

import (
	"crypto/rand"
	"crypto/rc4"

	"github.com/sukunrt/cryptopals/utils"
)

func getBiasByte(pos int, msg []byte, encrypt func([]byte) []byte) byte {
	tries := 10_000_000
	m := make(map[byte]int)
	for i := 0; i < tries; i++ {
		res := encrypt(msg)
		m[res[pos]]++

	}
	return getMaxByte(m)
}

func getMaxByte(m map[byte]int) byte {
	var b byte
	mx := 0

	for i := 0; i < 256; i++ {
		if mx < m[byte(i)] {
			mx = m[byte(i)]
			b = byte(i)
		}
	}
	return b
}

func BreakRC4(msg []byte) []byte {
	b := getBiasByte(31, make([]byte, 32), func(b []byte) []byte {
		key := utils.RandBytes(16)
		cipher, err := rc4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		res := make([]byte, len(b))
		cipher.XORKeyStream(res, b)
		return res
	})
	res := make([]byte, len(msg))
	for i := len(msg) - 1; i >= 0; i-- {
		msg := utils.ConcatBytes(utils.RepBytes('A', 32-i-1), msg)
		mb := getBiasByte(31, msg, func(b []byte) []byte {
			key := make([]byte, 16)
			_, err := rand.Read(key)
			if err != nil {
				panic(err)
			}
			cipher, err := rc4.NewCipher(key)
			if err != nil {
				panic(err)
			}
			res := make([]byte, len(b))
			cipher.XORKeyStream(res, b)
			return res
		})
		res[i] = mb ^ b
	}
	return res
}
