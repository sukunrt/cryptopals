package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"

	"github.com/sukunrt/cryptopals/crypto"
	"github.com/sukunrt/cryptopals/utils"
)

func Solve2_10() {
	scanner := utils.GetFileScanner("inputs/2-10.txt")
	input := make([]byte, 0)
	for scanner.Scan() {
		t := scanner.Text()
		b, err := base64.StdEncoding.DecodeString(t)
		if err != nil {
			panic(err)
		}
		input = append(input, b...)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, crypto.AESBlockSize)
	msg := crypto.NewAESInCBCCipher(key).Decrypt(input, iv)
	fmt.Println(string(msg))
}

type aesUserProfile struct {
	cipher crypto.AESInECBCipher
}

func (aup aesUserProfile) Encrypt(email string) []byte {
	return aup.cipher.Encrypt([]byte(utils.URLEncodeProfile(utils.ProfileFor(email))))
}

func (aup aesUserProfile) Decrypt(b []byte) map[string]string {
	s := string(aup.cipher.Decrypt(b))
	return utils.ParseURLEncoding(s)
}

func NewAESUserProfile(key []byte) aesUserProfile {
	return aesUserProfile{cipher: crypto.NewAESInECBCipher(key)}
}

func Solve2_12() {
	secret := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	secret = strings.Replace(secret, "\n", "", -1)
	randKey := utils.RandBytes(crypto.AESBlockSize)
	bsecret, _ := base64.StdEncoding.DecodeString(secret)
	encFunc := crypto.AESInECBWithSecretEncryptor(randKey, bsecret)
	realSecret := crypto.BreakSecretInECB(encFunc)
	fmt.Println(string(realSecret))
}

func Solve2_13() {
	key := utils.RandBytes(crypto.AESBlockSize)
	aup := NewAESUserProfile(key)
	adminBlock := utils.PadBytes([]byte("admin"), crypto.AESBlockSize)
	emailPrefix := utils.RepBytes('A', aes.BlockSize-len("email="))
	emailSuffix := []byte("@x.com")
	emailB := make([]byte, len(emailPrefix)+len(adminBlock)+len(emailSuffix))
	copy(emailB, emailPrefix)
	copy(emailB[len(emailPrefix):], adminBlock)
	copy(emailB[len(emailPrefix)+len(adminBlock):], emailSuffix)
	encProfile := aup.Encrypt(string(emailB))
	adminCipherBlock := encProfile[aes.BlockSize : 2*aes.BlockSize]

	var email []byte
	for i := 0; ; i++ {
		emailS := string(utils.RepBytes('A', i)) + "@x.com"
		profile := utils.URLEncodeProfile(utils.ProfileFor(emailS))
		n := strings.Index(profile, "role=") + len("role=")
		if len(profile[:n])%crypto.AESBlockSize == 0 {
			email = []byte(emailS)
			break
		}
	}
	encProfile = aup.Encrypt(string(email))
	encProfile = encProfile[:len(encProfile)-crypto.AESBlockSize]
	encProfile = append(encProfile, adminCipherBlock...)
	fmt.Println(aup.Decrypt(encProfile))
}

func Solve2_14() {
	key := utils.RandBytes(crypto.AESBlockSize)
	aesCipher := crypto.NewAESInECBCipher(key)
	minPrefixLen := 3
	maxPrefixLen := 31
	secretS := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	secretS = strings.Replace(secretS, "\n", "", -1)
	secret, err := base64.StdEncoding.DecodeString(secretS)
	if err != nil {
		panic(err)
	}
	encFunc := func(b []byte) []byte {
		prefixLen := 0
		for prefixLen%crypto.AESBlockSize != 0 {
			prefixLen = minPrefixLen + rand.Intn(maxPrefixLen-minPrefixLen)
		}
		prefix := utils.RandBytes(prefixLen)
		msg := utils.ConcatBytes(prefix, b, secret)
		return aesCipher.Encrypt(msg)
	}

	realSecret := crypto.BreakSecretInECBWithRandomPrefix(encFunc)
	fmt.Println(string(realSecret), len(realSecret), len(secret))
}

func Solve2_16() {
	key := utils.RandBytes(crypto.AESBlockSize)
	cipher := crypto.NewAESInCBCCipher(key)
	encFunc := func(b, iv []byte) []byte {
		cookie := utils.GenerateUserCookie(string(b))
		return cipher.Encrypt([]byte(cookie), iv)
	}

	passFunc := func(b, iv []byte) bool {
		msg := cipher.Decrypt(b, iv)
		role := utils.FindKeyInCookie(string(msg), "admin")
		v := utils.FindKeyInCookie(string(msg), "userdata")
		if role == "true" && v != "" {
			fmt.Println(string(msg))
		}
		return role == "true" && v != ""
	}

	crypto.BreakCBCWithBitFlipping(encFunc, passFunc)
}
