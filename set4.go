package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func Solve4_25() {
	plainText := "Imagine the \"edit\" function was exposed to attackers by means of an API call"
	key := crypto.RandAESKey()
	cipher := crypto.NewAESInCTRCipher(key)
	cipherText := cipher.Encrypt([]byte(plainText))
	reEncryptF := func(original []byte) func([]byte, int) []byte {
		cipherCopy := make([]byte, len(original))
		copy(cipherCopy, original)
		f := func(b []byte, offset int) []byte {
			res := make([]byte, len(cipherCopy))
			copy(res, cipherCopy)
			copy(res[offset:], cipher.EncryptAtOffset(b, offset))
			return res
		}
		return f
	}
	reEncrypt := reEncryptF(cipherText)
	recoveredText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		text := utils.RepBytes(0, 1)
		ct := reEncrypt(text, i)
		recoveredText[i] = ct[i] ^ cipherText[i] ^ text[0]
	}
	fmt.Println(string(recoveredText))

	scanner := utils.GetFileScanner("inputs/4-25.txt")
	b64Text := make([]byte, 0)
	for scanner.Scan() {
		t := scanner.Text()
		b64Text = append(b64Text, []byte(t)...)
	}
	cipherText = utils.FromBase64String(string(b64Text))
	cbcCipher := crypto.NewAESInECBCipher([]byte("YELLOW SUBMARINE"))
	pt := cbcCipher.Decrypt(cipherText)

	cipherText = cipher.Encrypt(pt)
	recoveredText = make([]byte, len(cipherText))
	reEncrypt = reEncryptF(cipherText)
	for i := 0; i < len(cipherText); i++ {
		text := utils.RepBytes(0, 1)
		ct := reEncrypt(text, i)
		recoveredText[i] = ct[i] ^ cipherText[i] ^ text[0]
	}
	fmt.Println(string(recoveredText))
}

func Solve4_26() {
	key := utils.RandBytes(crypto.AESBlockSize)
	cipher := crypto.NewAESInCTRCipher(key)
	encFunc := func(b []byte) []byte {
		cookie := utils.GenerateUserCookie(string(b))
		return cipher.Encrypt([]byte(cookie))
	}

	passFunc := func(b []byte) bool {
		msg := cipher.Decrypt(b)
		role := utils.FindKeyInCookie(string(msg), "admin")
		v := utils.FindKeyInCookie(string(msg), "userdata")
		if role == "true" && v != "" {
			fmt.Println(string(msg))
		}
		return role == "true" && v != ""
	}

	crypto.BreakCTRWithBitFlipping(encFunc, passFunc)
}

func Solve4_27() {
	key := utils.RandBytes(crypto.AESBlockSize)
	cipher := crypto.NewAESInCBCCipher(key)
	encFunc := func(b []byte) []byte {
		cookie := utils.GenerateUserCookie(string(b))
		return cipher.Encrypt([]byte(cookie), key)
	}

	validate := func(b []byte) bool {
		for _, v := range b {
			if v >= (1 << 7) {
				return false
			}
		}
		return true
	}

	passFunc := func(b []byte) (bool, []byte) {
		msg := cipher.Decrypt(b, key)
		if validate(msg) {
			return true, nil
		}
		return false, msg
	}

	for i := 0; i < 1<<7; i++ {
		cipherText := encFunc(utils.RepBytes(byte(i), 3*crypto.AESBlockSize))
		firstBlock := cipherText[:crypto.AESBlockSize]
		attackMsg := utils.ConcatBytes(firstBlock, utils.RepBytes(0, crypto.AESBlockSize), firstBlock)
		success, msg := passFunc(attackMsg)
		if !success {
			recoveredKey := utils.XorBytes(msg[:crypto.AESBlockSize], msg[2*crypto.AESBlockSize:3*crypto.AESBlockSize])
			if !bytes.Equal(recoveredKey, key) {
				panic("failure")
			} else {
				fmt.Println("Key: ", recoveredKey)
				break
			}
		}
	}
}

func Solve4_28() {
	secret := utils.RandBytes(crypto.AESBlockSize + 12)
	macFunc := crypto.SHA1MacF(secret)
	msg := []byte("Some very serious msg")
	mac1 := macFunc(msg)
	msg[5] = 0
	mac2 := macFunc(msg)
	if bytes.Equal(mac1, mac2) {
		fmt.Println("failed")
	} else {
		fmt.Println("pass")
	}
}

func Solve4_29() {
	secret := []byte("Submarine world is here forever")
	macF := crypto.SHA1MacF(secret)
	msg := utils.GenerateUserCookie("hello world")
	originalCheckSum := macF([]byte(msg))
	validatorF := func(b []byte, checksum []byte) bool {
		if !bytes.Equal(macF(b), checksum) {
			return false
		}
		return strings.Contains(string(b), ";admin=true")
	}

	crypto.BreakPrefixSHA1([]byte(msg), originalCheckSum, validatorF)

}

func Solve4_30() {
	secret := []byte("Submarine world is here")
	macF := crypto.MD4MacF(secret)
	msg := utils.GenerateUserCookie("hello world for this msg")
	originalCheckSum := macF([]byte(msg))
	validatorF := func(b []byte, checksum []byte) bool {
		if !bytes.Equal(macF(b), checksum) {
			return false
		}
		return strings.Contains(string(b), ";admin=true")
	}

	crypto.BreakPrefixMD4([]byte(msg), originalCheckSum, validatorF)

}

func Solve4_31() {
	hashValue := "2daa7426c49ce43323b4009a70294420847ed0f8e1dc2e20104588c7f248e9b7"
	checkSum := utils.FromHexString(hashValue)
	httpHandler := func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		v, ok := params["signature"]
		if !ok || len(v) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		vv, err := hex.DecodeString(v[0])
		if err != nil || len(vv) != len(checkSum) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for i := 0; i < len(checkSum); i++ {
			if checkSum[i] == vv[i] {
				time.Sleep(1 * time.Millisecond)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}
	server := utils.GetLocalHTTPServer(10001, httpHandler, "checkfile")
	go func() {
		server.ListenAndServe()
		fmt.Println("server started")
	}()
	attackCheckSum := make([]byte, 32)
	for bytePos := 0; bytePos < 32; bytePos++ {
		m := make(map[byte]int)
		type Pair struct {
			K byte
			V int
		}
		var byteDelays []Pair
		epsilon := 0.2 // Error margin from expected difference
		st := time.Now()
		tries := 0
		invalidBytes := make(map[byte]struct{})
		for {
			tries += 5
			for j := 0; j < 5; j++ {
				for i := 0; i < 1<<8; i++ {
					if _, ok := invalidBytes[byte(i)]; ok {
						continue
					}
					bb := byte(i)
					attackCheckSum[bytePos] = bb
					msg := hex.EncodeToString(attackCheckSum)
					t := time.Now()
					_, err := http.Get("http://localhost:10001/checkfile?signature=" + msg)
					if err != nil {
						panic(err)
					}
					d := time.Since(t).Microseconds()
					m[bb] += int(d)
				}
			}
			byteDelays = make([]Pair, 0)
			for k, v := range m {
				byteDelays = append(byteDelays, Pair{k, v})
			}
			sort.Slice(byteDelays, func(i, j int) bool {
				return byteDelays[i].V > byteDelays[j].V
			})
			if byteDelays[0].V-byteDelays[1].V > int(float64(tries*1000)*(1.0-epsilon)) {
				attackCheckSum[bytePos] = byteDelays[0].K
				break
			} else {
				if tries > 50 {
					bytePos -= 2
					if bytePos < -1 {
						bytePos = -1
					}
					break
				}
				for i := len(byteDelays) - 1; i >= 0; i-- {
					if (byteDelays[0].V - byteDelays[i].V) > int(float64(tries*1000)*(1.0-epsilon)) {
						invalidBytes[byteDelays[i].K] = struct{}{}
					}
				}
			}
		}
		d := time.Since(st)
		fmt.Println("Took ", d.Milliseconds(), "For ", bytePos)
	}
	fmt.Println(hex.EncodeToString(checkSum))
	fmt.Println(hex.EncodeToString(attackCheckSum))
	server.Close()
}
