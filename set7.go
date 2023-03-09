package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func makeCBCMac(cipher crypto.AESInCBCCipher, iv []byte, msg []byte) []byte {
	c := cipher.Encrypt(msg, iv)
	return c[len(c)-crypto.AESBlockSize:]
}

func Solve7_49() {
	fmt.Println("partA:")
	partA_49()
	fmt.Println("partB:")
	partB_49()
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
	ourAccount := 20
	theirAccount := 30
	thirdAccount := 40
	fourthAccount := 50
	cipher := crypto.NewAESInCBCCipher(crypto.RandAESKey())
	m1 := string(utils.PadBytes([]byte(fmt.Sprintf("from=%d&tx_list=%d:100", theirAccount, thirdAccount)), crypto.AESBlockSize))
	m2 := fmt.Sprintf("from=%d&tx_list=%d:0000000000001;%d:1000000", ourAccount, fourthAccount, ourAccount)
	mac1 := makeCBCMac(cipher, make([]byte, crypto.AESBlockSize), []byte(m1))
	mac2 := makeCBCMac(cipher, make([]byte, crypto.AESBlockSize), []byte(m2))

	b1 := m2[:crypto.AESBlockSize]
	newB1 := utils.XorBytes([]byte(b1), mac1)
	newMsg := m1 + string(utils.RepBytes(16, 16)) + string(newB1) + m2[crypto.AESBlockSize:]
	mac3 := makeCBCMac(cipher, make([]byte, crypto.AESBlockSize), []byte(newMsg))
	if !bytes.Equal(mac3, mac2) {
		fmt.Println("FAILED mac should be same")
		return
	}

	// Parse transactions and see if we are getting any money:
	var from int
	parts := strings.Split(newMsg, "&")
	from, _ = strconv.Atoi(parts[0][strings.Index(parts[0], "from=")+len("from="):])
	if from != theirAccount {
		fmt.Println("FAILED money should be from their account")
		return
	}
	txns := strings.Split(parts[1][len("tx_list="):], ";")
	for _, tx := range txns {
		parts := strings.Split(tx, ":")
		to, _ := strconv.Atoi(parts[0])
		amt, _ := strconv.Atoi(parts[1])
		if to == ourAccount && amt > 100000 {
			fmt.Println("success")
			return
		}
	}
	fmt.Println("failed: received no money")
}