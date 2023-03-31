package main

import (
	"math/rand"

	"github.com/sukunrt/cryptopals/crypto/wangmd"
	"github.com/sukunrt/cryptopals/utils"
)

func init() {
	// b := make([]byte, 8)
	// crand.Read(b)
	// rand.Seed(int64(binary.BigEndian.Uint64(b)))
	rand.Seed(35)
}

func main() {
	wmd := &wangmd.WangMD4{}
	for i := 0; i < 100; i++ {
		wmd.Hash(utils.RandBytes(512 / 8))
	}
}
