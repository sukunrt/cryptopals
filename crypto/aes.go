package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/sukunrt/cryptopals/utils"
)

const AESBlockSize = 16

type Mode string

const CBC Mode = "CBC"
const ECB Mode = "ECB"
const CTR Mode = "CTR"

func newAESCipher(key []byte) cipher.Block {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher
}

func RandAESKey() []byte {
	return utils.RandBytes(AESBlockSize)
}

func PadKey(k []byte) []byte {
	if len(k) < AESBlockSize {
		k = append(k, make([]byte, AESBlockSize-len(k))...)
	}
	return k[:AESBlockSize]
}

// AESInECBCipher encrypts or decrypts bytes in aes with ecb mode
type AESInECBCipher struct {
	key    []byte
	cipher cipher.Block
}

// Encrypt encrypts bytes in ECB mode
func (cipher AESInECBCipher) Encrypt(b []byte) []byte {
	msg := utils.PadBytes(b, AESBlockSize)
	cipherText := make([]byte, len(msg))
	for i := 0; i < len(msg); i += AESBlockSize {
		cipher.cipher.Encrypt(cipherText[i:], msg[i:i+AESBlockSize])
	}
	return cipherText
}

// Decrypt decrypts bytes in ECB Mode
func (cipher AESInECBCipher) Decrypt(b []byte) []byte {
	plainText := make([]byte, len(b))
	for i := 0; i < len(b); i += AESBlockSize {
		cipher.cipher.Decrypt(plainText[i:], b[i:])
	}
	plainText = utils.RemovePad(plainText)
	return plainText
}

// NewAESInECBCipher returns a new cipher struct
func NewAESInECBCipher(key []byte) AESInECBCipher {
	return AESInECBCipher{key: key, cipher: newAESCipher(key)}
}

// AESInCBCCipher encrypts or decrypts bytes with AES in CBC Mode
type AESInCBCCipher struct {
	cipher cipher.Block
	key    []byte
}

// NewAESInCBCCipher returns a new AESInCBCCipher struct
func NewAESInCBCCipher(key []byte) AESInCBCCipher {
	return AESInCBCCipher{key: PadKey(key), cipher: newAESCipher(PadKey(key))}
}

// Encrypt encrypts b with the ac.key and iv
func (ac AESInCBCCipher) Encrypt(b []byte, iv []byte) []byte {
	msg := utils.PadBytes(b, AESBlockSize)
	cipherText := make([]byte, len(msg))
	prevIV := make([]byte, len(iv))
	copy(prevIV, iv)
	for i := 0; i < len(msg); i += AESBlockSize {
		subMsg := utils.XorBytes(msg[i:i+AESBlockSize], prevIV)
		ac.cipher.Encrypt(cipherText[i:], subMsg)
		prevIV = cipherText[i : i+AESBlockSize]
	}
	return cipherText
}

// DecryptWithoutPadding decrypts the msg without removing the padding
// from the final plaintext
func (ac AESInCBCCipher) DecryptWithoutPadding(b []byte, IV []byte) []byte {
	plainText := make([]byte, len(b))
	prevIV := make([]byte, len(IV))
	decryptedBlock := make([]byte, AESBlockSize)
	copy(prevIV, IV)
	for i := 0; i < len(b); i += AESBlockSize {
		ac.cipher.Decrypt(decryptedBlock, b[i:i+AESBlockSize])
		plainTextBlock := utils.XorBytes(decryptedBlock, prevIV)
		copy(plainText[i:], plainTextBlock)
		prevIV = b[i : i+AESBlockSize]
	}
	return plainText
}

// Decrypt decrypts the block with ac.key and iv
func (ac AESInCBCCipher) Decrypt(b []byte, iv []byte) []byte {
	plainText := ac.DecryptWithoutPadding(b, iv)
	plainText = utils.RemovePad(plainText)
	return plainText
}

// AESInCTRCipher encrypts and decrypts bytes in CTR Mode
// It uses a 8 byte nonce and 8 byte little endian ctr
type AESInCTRCipher struct {
	key    []byte
	nonce  []byte
	cipher cipher.Block
}

func NewAESInCTRCipher(key []byte) AESInCTRCipher {
	return AESInCTRCipher{
		key:    utils.RandBytes(AESBlockSize),
		nonce:  utils.RandBytes(AESBlockSize / 2),
		cipher: newAESCipher(key),
	}
}

func NewAESInCTRCipherWithNonce(key []byte, nonce []byte) AESInCTRCipher {
	return AESInCTRCipher{
		key:    utils.RandBytes(AESBlockSize),
		nonce:  nonce,
		cipher: newAESCipher(key),
	}
}

func (ac AESInCTRCipher) getKey(round int) []byte {
	c := uint64(round)
	cb := make([]byte, AESBlockSize/2)
	binary.LittleEndian.PutUint64(cb, c)
	input := utils.ConcatBytes(ac.nonce, cb)
	key := make([]byte, AESBlockSize)
	ac.cipher.Encrypt(key, input)
	return key
}

func (ac AESInCTRCipher) EncryptAtOffset(b []byte, offset int) []byte {
	cipherBlocks := make([][]byte, 0)
	paddingLen := (offset % AESBlockSize)
	b = utils.ConcatBytes(utils.RepBytes(0, paddingLen), b)
	round := offset / AESBlockSize
	for i := 0; i < len(b); i += AESBlockSize {
		key := ac.getKey(round)
		var cipherBlock []byte
		if len(b) < i+AESBlockSize {
			cipherBlock = utils.XorBytes(key[:len(b)-i], b[i:])
		} else {
			cipherBlock = utils.XorBytes(key, b[i:i+AESBlockSize])
		}
		cipherBlocks = append(cipherBlocks, cipherBlock)
		round++
	}
	return utils.ConcatBytes(cipherBlocks...)[paddingLen:]
}

func (ac AESInCTRCipher) Encrypt(b []byte) []byte {
	return ac.EncryptAtOffset(b, 0)
}

func (ac AESInCTRCipher) Decrypt(b []byte) []byte {
	return ac.Encrypt(b)
}

func AESInECBWithSecretEncryptor(key []byte, secret []byte) func([]byte) []byte {
	aesCipher := NewAESInECBCipher(key)
	return func(b []byte) []byte {
		msg := make([]byte, len(b)+len(secret))
		copy(msg, b)
		copy(msg[len(b):], secret)
		return aesCipher.Encrypt(msg)
	}
}

func DetectAESinECBMode(b []byte) int {
	cnt := 0
	for i := 0; i < len(b); i += AESBlockSize {
		for j := i + AESBlockSize; j < len(b); j += AESBlockSize {
			x, y := b[i:i+AESBlockSize], b[j:j+AESBlockSize]
			if bytes.Equal(x, y) {
				cnt++
			}
		}
	}
	return cnt
}

// RandAESEncrypt encrypts b with either CBC or ECB mode with a random key and iv
func randAESEncrypt(b []byte) ([]byte, Mode) {
	maxPadding := 10
	prefixPadding := utils.RandBytes(rand.Intn(maxPadding))
	suffixPadding := utils.RandBytes(rand.Intn(maxPadding))
	msg := make([]byte, len(b)+len(prefixPadding)+len(suffixPadding))
	copy(msg, prefixPadding)
	copy(msg[len(prefixPadding):], b)
	copy(msg[len(prefixPadding)+len(b):], suffixPadding)
	key := utils.RandBytes(AESBlockSize)
	modes := []Mode{CBC, ECB}
	mode := modes[rand.Intn(2)]
	if mode == CBC {
		IV := utils.RandBytes(AESBlockSize)
		aesCipher := NewAESInCBCCipher(key)
		return aesCipher.Encrypt(msg, IV), CBC
	}
	return NewAESInECBCipher(key).Encrypt(msg), ECB
}

// DetectAESMode detects whether a particular source encrypts messages in
// ECB Mode or CBC Mode
func DetectAESMode(encFunc func([]byte) []byte) Mode {
	// We send a message of 3*AESBlockSize length string containing the same letter
	// This block should return identical consecutive blocks in the cipherText if the
	// mode is ECB otherwise it is CBC
	// 2 * AESBlockSize + epsilon doesn't work because the block may be broken up
	// such that randomText + block1, block1 + block2, block2 + randomText
	randBlock := utils.RandBytes(AESBlockSize)
	minBlocksRequired := 3
	msg := make([]byte, minBlocksRequired*AESBlockSize)
	for i := 0; i < len(msg); i += AESBlockSize {
		copy(msg[i:], randBlock)
	}
	cipherText := encFunc(msg)
	for i := 0; i+AESBlockSize < len(cipherText); i += AESBlockSize {
		if bytes.Equal(cipherText[i:i+AESBlockSize], cipherText[i+AESBlockSize:i+2*AESBlockSize]) {
			return ECB
		}
	}
	return CBC
}

// BreakSecretInECB takes an encryptor function which uses a secret suffix to encrypt
// the message and returns the secret used by the encryptor
func BreakSecretInECB(encFunc func(b []byte) []byte) []byte {
	fc := byte('A')
	blockSize := 0
	for i := 1; i <= 100; i++ {
		b := make([]byte, 2*i)
		for j := 0; j < len(b); j++ {
			b[j] = fc
		}
		cipher := encFunc(b)
		if bytes.Equal(cipher[0:i], cipher[i:2*i]) {
			blockSize = i
			break
		}
	}

	mode := DetectAESMode(encFunc)
	if mode == CBC {
		panic("Cannot break CBC Mode")
	}

	secret := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		secret[i] = fc
	}
	for byteNum := 0; ; byteNum++ {
		// make map of expected codes
		cipherToByteMap := make(map[string]byte)
		targetMsg := make([]byte, blockSize)
		copy(targetMsg, secret[len(secret)-blockSize+1:])
		for i := 0; i < 1<<8; i++ {
			targetMsg[blockSize-1] = byte(i)
			cipher := encFunc(targetMsg)
			cipherToByteMap[string(cipher[:blockSize])] = byte(i)
		}

		blockPos := byteNum % blockSize
		msgLen := blockSize - (blockPos + 1)
		msg := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			msg[i] = fc
		}
		cipher := encFunc(msg)
		blockStart := (byteNum / blockSize) * blockSize
		relevantBlock := cipher[blockStart : blockStart+blockSize]
		s, ok := cipherToByteMap[string(relevantBlock)]
		if !ok {
			break
		}
		secret = append(secret, s)
	}
	return secret[blockSize : len(secret)-1]
}

// BreakSecretInECBWithRandomPrefix breaks encFunc which encrypts bytes by
// adding a random prefix and adds a random suffix
func BreakSecretInECBWithRandomPrefix(encFunc func([]byte) []byte) []byte {
	blockSize := 0
	fc := byte('B')
	for i := 2; i < 100; i++ {
		msg := utils.RepBytes(fc, 3*i)
		cipherText := encFunc(msg)
		isValid := false
		for j := 0; j+2*i < len(cipherText); j += i {
			if bytes.Equal(cipherText[j:j+i], cipherText[j+i:j+2*i]) {
				isValid = true
				blockSize = i
				break
			}
		}
		if isValid {
			break
		}
	}
	mode := DetectAESMode(encFunc)
	if mode == CBC {
		panic("Cannot break CBC Mode")
	}

	maxTries := 1 << 16
	secret := utils.RepBytes(fc, blockSize)
	marker := make([]byte, 2*blockSize)
	for i := 0; i < len(marker); i++ {
		marker[i] = byte(i % blockSize)
	}
	marker = utils.ConcatBytes(utils.RepBytes(fc, 3), marker)
	for bytePos := 0; ; bytePos++ {
		cipherToByteMap := make(map[string]byte)
		targetMsg := make([]byte, blockSize)
		copy(targetMsg, secret[len(secret)-blockSize+1:])
		for targetByte := 0; targetByte < 1<<8; targetByte++ {
			targetMsg[blockSize-1] = byte(targetByte)
			found := false
			for t := 0; t < maxTries; t++ {
				prefixLen := rand.Intn(blockSize)
				prefix := utils.RepBytes(fc, prefixLen)
				msg := utils.ConcatBytes(prefix, marker, targetMsg)
				cipherText := encFunc(msg)
				for k := 0; k+blockSize < len(cipherText); k += blockSize {
					if bytes.Equal(cipherText[k:k+blockSize], cipherText[k+blockSize:k+2*blockSize]) {
						found = true
						st := k + 2*blockSize
						relevantBlock := cipherText[st : st+blockSize]
						cipherToByteMap[string(relevantBlock)] = byte(targetByte)
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				panic(fmt.Sprintf("Failed to find a cipher for byte %d", targetByte))
			}
		}
		blockPos := bytePos % blockSize
		blockNum := (bytePos / blockSize)
		bytesNeeded := (blockSize - blockPos - 1)
		paddingBytes := utils.RepBytes(fc, bytesNeeded)
		found := false
		done := false
		for t := 0; t < maxTries; t++ {
			prefixLen := rand.Intn(blockSize)
			prefix := utils.RepBytes(fc, prefixLen)
			msg := utils.ConcatBytes(prefix, marker, paddingBytes)
			cipherText := encFunc(msg)
			for j := 0; j+blockSize < len(cipherText); j += blockSize {
				if bytes.Equal(cipherText[j:j+blockSize], cipherText[j+blockSize:j+2*blockSize]) {
					found = true
					st := j + (2+blockNum)*blockSize
					relevantBlock := cipherText[st : st+blockSize]
					k, ok := cipherToByteMap[string(relevantBlock)]
					if !ok {
						done = true
						break
					}
					secret = append(secret, k)
					break
				}
			}
			if found || done {
				break
			}
		}
		if done {
			break
		}
	}
	secret = utils.RemovePad(secret[blockSize:])
	return secret
}

func BreakCBCWithBitFlipping(encFunc func([]byte, []byte) []byte, passFunc func([]byte, []byte) bool) {
	fc := byte('A')
	input := utils.RepBytes(fc, 2*AESBlockSize)
	targetBlock := []byte(";admin=true;k=AAAAAAAAAAAAAAAAA")[:AESBlockSize]
	diff := utils.XorBytes(input[:AESBlockSize], targetBlock)
	buff := make([]byte, AESBlockSize)
	maxTries := 1 << 16
	success := false
	for t := 0; t < maxTries; t++ {
		prefixLen := rand.Intn(AESBlockSize)
		prefix := utils.RepBytes(fc, prefixLen)
		msg := utils.ConcatBytes(prefix, input)
		iv := utils.RandBytes(AESBlockSize)
		cipherText := encFunc(msg, iv)
		for i := 0; i < len(cipherText); i++ {
			copy(buff, cipherText[i:i+AESBlockSize])
			copy(cipherText[i:], utils.XorBytes(buff, diff))
			if passFunc(cipherText, iv) {
				success = true
				break
			}
			copy(cipherText[i:], buff)
		}
		if success {
			break
		}
	}
	if success {
		fmt.Println("PWN")
	} else {
		fmt.Println("Access Denied")
	}
}

func BreakCTRWithBitFlipping(encFunc func([]byte) []byte, passFunc func([]byte) bool) {
	fc := byte('A')
	msg := utils.RepBytes(fc, 3*AESBlockSize)
	required := []byte("A;admin=true;k=AAAAAAAAAAAAAAAAAAA")[:AESBlockSize]
	xorMsg := utils.XorBytes(msg[:AESBlockSize], required)
	cipherText := encFunc(msg)
	buff := make([]byte, AESBlockSize)
	success := false
	for i := 0; i < len(cipherText); i += AESBlockSize {
		copy(buff, cipherText[i:])
		attack := utils.XorBytes(cipherText[i:i+AESBlockSize], xorMsg)
		copy(cipherText[i:], attack)
		if passFunc(cipherText) {
			success = true
			break
		}
		copy(cipherText[i:], buff)
	}
	if success {
		fmt.Println("PWN")
	} else {
		fmt.Println("FAILED")
	}
}

func breakCBCWithPaddingOracleBlock(cipherText []byte, IV []byte,
	paddingOracle func([]byte, []byte) bool, n int) []byte {
	var a []byte
	if n == 0 {
		a = IV
	} else {
		a = cipherText[(n-1)*AESBlockSize : n*AESBlockSize]
	}
	endPos := (n + 1) * AESBlockSize
	plainText := make([]byte, AESBlockSize)
	buff := make([]byte, AESBlockSize)
	targetByte := 1
	for ; targetByte < AESBlockSize; targetByte++ {
		pos := AESBlockSize - targetByte
		suffix := utils.XorBytes(plainText, utils.RepBytes(byte(targetByte), AESBlockSize))
		suffix = suffix[pos+1:]
		found := false
		prefix := utils.RepBytes('A', AESBlockSize-len(suffix))
		for tryB := 0; tryB < 1<<8; tryB++ {
			prefix[len(prefix)-1] = byte(tryB)
			msg := utils.ConcatBytes(prefix, suffix)
			xorMsg := utils.XorBytes(msg, a)
			copy(buff, a)
			copy(a, xorMsg)
			if paddingOracle(cipherText[:endPos], IV) {
				plainText[pos] = byte(targetByte) ^ msg[pos]
				found = true
			}
			copy(a, buff)
			if found {
				break
			}
		}
		if !found {
			fmt.Println(targetByte)
			panic("Could not decode byte at position")
		}
	}
	return plainText
}

func BreakCBCWithPaddingOracle(cipherText []byte, IV []byte, paddingOracle func([]byte, []byte) bool) []byte {
	plainTexts := make([][]byte, 0)
	for i := 0; i < len(cipherText); i += AESBlockSize {
		block := breakCBCWithPaddingOracleBlock(cipherText, IV, paddingOracle, i/AESBlockSize)
		plainTexts = append(plainTexts, block)
	}
	return utils.ConcatBytes(plainTexts...)
}
