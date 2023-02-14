package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/mt"
	"github.com/sukunrt/cryptopals/utils"
)

func Solve3_17() {
	key := utils.RandBytes(crypto.AESBlockSize)
	cipher := crypto.NewAESInCBCCipher(key)
	encFunc := func() ([]byte, []byte) {
		msgs := []string{
			"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
			"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
			"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
			"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
			"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
			"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
			"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
			"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
			"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
			"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
		}
		IV := utils.RandBytes(crypto.AESBlockSize)
		idx := rand.Intn(len(msgs))
		msg, err := base64.StdEncoding.DecodeString(msgs[idx])
		if err != nil {
			panic(err)
		}
		return cipher.Encrypt(msg, IV), IV
	}

	paddingOracle := func(b []byte, IV []byte) bool {
		msg := cipher.DecryptWithoutPadding(b, IV)
		msgPaddingRemoved := utils.RemovePad(msg)
		return !bytes.Equal(msg, msgPaddingRemoved)
	}

	for i := 0; i < 100; i++ {
		cipherText, IV := encFunc()
		plainText := crypto.BreakCBCWithPaddingOracle(cipherText, IV, paddingOracle)
		fmt.Println(string(plainText))
	}
}

func Solve3_18() {
	s := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	msg, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	key := []byte("YELLOW SUBMARINE")
	nonce := utils.RepBytes(0, crypto.AESBlockSize/2)
	aesCipher := crypto.NewAESInCTRCipherWithNonce(key, nonce)
	plainText := aesCipher.Decrypt(msg)
	fmt.Println(string(plainText))
}

func Solve3_19() {
	texts := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}[:5]
	plainTexts := make([][]byte, len(texts))
	for i, t := range texts {
		plainTexts[i] = utils.FromBase64String(t)
	}
	key := utils.RandBytes(crypto.AESBlockSize)
	cipher := crypto.NewAESInCTRCipher(key)
	cipherTexts := make([][]byte, len(plainTexts))
	for i, t := range plainTexts {
		cipherTexts[i] = cipher.Encrypt(t)
	}

	byteMap := make(map[byte]byte)
	revByteMap := make(map[byte]byte)
	for i := 0; i < len(cipherTexts); i++ {
		for j := 0; j < len(cipherTexts[i]) && j < crypto.AESBlockSize; j++ {
			byteMap[cipherTexts[i][j]] = plainTexts[i][j]
			if v, ok := revByteMap[plainTexts[i][j]]; ok {
				fmt.Println(plainTexts[i][j], "Already Assigned to ", v, cipherTexts[i][j], i, j)
				panic("Failed")
			}
			revByteMap[plainTexts[i][j]] = cipherTexts[i][j]
		}
	}

	byteCountMap := make(map[byte]int)
	for i := 0; i < len(cipherTexts); i++ {
		for j := 0; j < len(cipherTexts[i]) && j < crypto.AESBlockSize; j++ {
			byteCountMap[cipherTexts[i][j]]++
		}
	}
	type pair struct {
		B   byte
		Cnt int
	}
	var byteCounts []pair
	for k, v := range byteCountMap {
		byteCounts = append(byteCounts, pair{k, v})
	}
	sort.SliceStable(byteCounts, func(i, j int) bool {
		if byteCounts[i].Cnt != byteCounts[j].Cnt {
			return byteCounts[i].Cnt > byteCounts[j].Cnt
		}
		return byteCounts[i].B > byteCounts[j].B
	})

	for i := 0; i < 5; i++ {
		fmt.Println(byteCounts[i].B, byteMap[byteCounts[i].B], string(byteMap[byteCounts[i].B]), byteCounts[i].Cnt)
	}
}

func Solve3_20() {
	scanner := utils.GetFileScanner("inputs/3-20.txt")
	var plainTexts [][]byte
	for scanner.Scan() {
		t := scanner.Text()
		plainTexts = append(plainTexts, utils.FromBase64String(t))
	}

	minLen := 1 << 32
	for _, p := range plainTexts {
		minLen = utils.MinInt(minLen, len(p))
	}

	truncatedPlainTexts := make([][]byte, len(plainTexts))
	for i, p := range plainTexts {
		truncatedPlainTexts[i] = p[:minLen]
	}
	key := utils.RandBytes(crypto.AESBlockSize)
	cipher := crypto.NewAESInCTRCipher(key)
	cipherTexts := make([][]byte, len(plainTexts))
	for i, p := range truncatedPlainTexts {
		cipherTexts[i] = cipher.Encrypt(p)
	}

	msg := utils.ConcatBytes(cipherTexts...)
	decryptedMsg, _ := crypto.BreakRepeatingKeyXorWithKeySize(msg, minLen)
	for i, j := 0, 0; i < len(decryptedMsg); i, j = i+minLen, j+1 {
		if !bytes.Equal(decryptedMsg[i:i+minLen], truncatedPlainTexts[j]) {
			fmt.Println("Failed to decode")
			fmt.Println(string(decryptedMsg[i:i+minLen]), string(truncatedPlainTexts[j]))
		} else {
			fmt.Println("done")
		}
	}
}

func Solve3_21() {
	for seed := 0; seed < 1000; seed++ {
		mt1 := mt.NewMTRNG(seed)
		mt2 := mt.NewMTRNG(seed)
		for i := 0; i < 1000; i++ {
			if mt1.Int() != mt2.Int() {
				fmt.Println("failed")
			}
		}
	}
}

func Solve3_22() {
	diff := rand.Intn(4 * 1000_0000_000)
	seed := time.Now().Add(time.Duration(-1 * diff)).Unix()
	m := mt.NewMTRNG(int(seed))
	x := m.Int()
	fmt.Println("Used", seed)
	now := time.Now()
	for {
		seed = now.Unix()
		y := mt.NewMTRNG(int(seed)).Int()
		if y == x {
			fmt.Println("Found: ", seed)
			break
		} else {
			now = now.Add(-1 * time.Millisecond)
		}
	}

}

const MTStateSize = 624

func Solve3_23() {
	seed := rand.Intn(1 << 31)
	m := mt.NewMTRNG(seed)
	var state [MTStateSize]int
	for i := 0; i < MTStateSize; i++ {
		x := m.Int()
		state[i] = crypto.ReverseTemper(x)
	}
	nm := mt.NewMTRNGWithState(state, MTStateSize)
	success := true
	for i := 0; i < 1000; i++ {
		x, y := m.Int(), nm.Int()
		if x != y {
			success = false
			break
		}
	}
	fmt.Println("success: ", success)
}

func Solve3_24() {
	seed := rand.Intn(1 << 16)
	fmt.Println("Used Seed:", seed)
	mtc := crypto.NewMTCipher(seed)
	plainText := utils.RepBytes('A', 10)

	prefix := utils.RandBytes(rand.Intn(100))
	inputPlainText := utils.ConcatBytes(prefix, plainText)
	cipherText := mtc.Encrypt(inputPlainText)

	msg := utils.ConcatBytes(utils.RepBytes('A', len(cipherText)-len(plainText)), plainText)
	lastCipherTextN := cipherText[len(cipherText)-len(plainText):]
	for trySeed := 0; ; trySeed++ {
		mtc := crypto.NewMTCipher(trySeed)
		ct := mtc.Encrypt(msg)
		lastN := ct[len(ct)-len(plainText):]
		if bytes.Equal(lastN, lastCipherTextN) {
			fmt.Println("Found Seed: ", trySeed)
			break
		}
	}

	seed = int(time.Now().Unix()) - rand.Intn(1<<20)
	mtc = crypto.NewMTCipher(seed)
	token := mtc.Bytes(5)
	foundSeed := crypto.BreakMTCipherToken(token)
	fmt.Println(seed, foundSeed)
}
