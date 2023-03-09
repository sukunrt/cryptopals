package main

import (
	"bytes"
	"fmt"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func makeCBCMac(cipher crypto.AESInCBCCipher, iv []byte, msg []byte) []byte {
	c := cipher.Encrypt(msg, iv)
	return c[len(c)-crypto.AESBlockSize:]
}

func Solve7_49() {
	partA_49()
}

func partA_49() {
	// This attack is not very sophisticated.
	// We can only change the first block which is not too long. But in this case we'll assume account
	// numbers are 2 digits. Also we cannot change the digits much otherwise the msg will get scrambled
	key := crypto.RandAESKey()
	cipher := crypto.NewAESInCBCCipher(key)
	ogIv := utils.RandBytes(crypto.AESBlockSize)
	pt := "from=23&to=45&amount=1000000"
	mac := makeCBCMac(cipher, ogIv, []byte(pt))
	msg := utils.ConcatBytes([]byte(pt), ogIv, mac)

	targetMsg := "from=23&to=21&amount=1000000"
	originalIV := msg[len(msg)-2*crypto.AESBlockSize : len(msg)-1*crypto.AESBlockSize]
	targetIv := utils.XorBytes(utils.XorBytes([]byte(targetMsg[:crypto.AESBlockSize]), originalIV), []byte(pt[:crypto.AESBlockSize]))
	mac2 := makeCBCMac(cipher, targetIv, []byte(targetMsg))
	if bytes.Equal(mac, mac2) {
		fmt.Println("success")
	} else {
		fmt.Println("failure")
	}
}

func partB_49() {
	// This is again not a very sophisticated attack. Requires the server to use the same key for every
	// client
	
}
