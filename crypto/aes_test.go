package crypto

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
)

func init() {
	b := make([]byte, 8)
	crand.Read(b)
	rand.Seed(int64(binary.BigEndian.Uint64(b)))
}

func TestAESEncryptAndAESDecryptINCBCMode(t *testing.T) {
	tt := "This is some standard plaintext"
	key := "1234567890123456"
	iv := "2345678901234567"
	cipher := NewAESInCBCCipher([]byte(key))
	encryptedBytes := cipher.Encrypt([]byte(tt), []byte(iv))
	decryptedBytes := cipher.Decrypt(encryptedBytes, []byte(iv))
	if string(decryptedBytes) != tt {
		t.Fatalf("Failed to encrypt or decrypt AES in CBC mode")
	}
}

func TestAESOracle(t *testing.T) {
	var modeUsed Mode
	encFunc := func(b []byte) []byte {
		cipherText, mode := randAESEncrypt(b)
		modeUsed = mode
		return cipherText
	}
	maxTries := 100
	for i := 0; i < maxTries; i++ {
		mode := DetectAESMode(encFunc)
		if mode != modeUsed {
			fmt.Println(mode, modeUsed)
			t.Fatalf("Mode detection oracle failed")
		}
	}
}

func TestBreakSecretInECB(t *testing.T) {
	key := []byte("YeLLOW SubmariNE")
	secret := []byte("This is a good secret to test things")
	encFunc := AESInECBWithSecretEncryptor(key, secret)
	found := BreakSecretInECB(encFunc)
	if !bytes.Equal(secret, found) {
		t.Fatalf("Failed to find secret in ECB")
	}
}
