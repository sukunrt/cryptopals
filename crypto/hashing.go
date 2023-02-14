package crypto

import (
	"encoding/binary"
	"fmt"

	"github.com/sukunrt/cryptopals/hashing"
	"github.com/sukunrt/cryptopals/hashing/md4"
	"github.com/sukunrt/cryptopals/utils"
)

func SHA1MacF(secret []byte) func([]byte) []byte {
	sh := make([]byte, len(secret))
	copy(sh, secret)
	h := hashing.New()
	return func(b []byte) []byte {
		h.Reset()
		msg := utils.ConcatBytes(sh, b)
		h.Write(msg)
		return h.Sum(nil)
	}
}

func MD4MacF(secret []byte) func([]byte) []byte {
	sh := make([]byte, len(secret))
	copy(sh, secret)
	h := md4.New()
	return func(b []byte) []byte {
		h.Reset()
		msg := utils.ConcatBytes(sh, b)
		h.Write(msg)
		return h.Sum(nil)
	}
}

const sha1BlockSize = 64

func AddSHA1Padding(b []byte, msgLen int) []byte {
	var T [64]byte
	res := make([]byte, len(b))
	copy(res, b)
	res = append(res, 0x80)
	n := (msgLen + 1) % sha1BlockSize
	// Want 8 bytes available after padding
	if n <= 56 {
		res = append(res, T[:56-n]...)
	} else {
		res = append(res, T[:64+56-n]...)
	}
	// Length is in bits
	res = binary.BigEndian.AppendUint64(res, uint64(msgLen<<3))
	return res
}

const md4BlockSize = 64

func AddMD4Padding(b []byte, msgLen int) []byte {
	var T [64]byte
	res := make([]byte, len(b))
	copy(res, b)
	res = append(res, 0x80)
	n := (msgLen + 1) % md4BlockSize
	// Want 8 bytes available after padding
	if n <= 56 {
		res = append(res, T[:56-n]...)
	} else {
		res = append(res, T[:64+56-n]...)
	}
	// Length is in bits
	res = binary.LittleEndian.AppendUint64(res, uint64(msgLen<<3))
	return res
}

func ExtractSHA1State(checkSum []byte) [5]uint32 {
	var res [5]uint32
	for i := 0; i < len(checkSum); i += 4 {
		res[i/4] = binary.BigEndian.Uint32(checkSum[i : i+4])
	}
	return res
}

func ExtractMD4State(checksum []byte) [4]uint32 {
	var res [4]uint32
	for i := 0; i < len(checksum); i += 4 {
		res[i/4] = binary.LittleEndian.Uint32(checksum[i : i+4])
	}
	return res
}

func BreakPrefixSHA1(b, checkSum []byte, validatorF func([]byte, []byte) bool) {
	suffix := []byte(";admin=true")
	for i := 0; i < 100; i++ {
		paddedMsg := AddSHA1Padding(b, len(b)+i)
		inputMsg := utils.ConcatBytes(paddedMsg, suffix)
		sh := hashing.NewWithState(ExtractSHA1State(checkSum), uint64(len(paddedMsg)+i))
		sh.Write(suffix)
		ncs := sh.Sum(nil)
		if validatorF(inputMsg, ncs[:]) {
			fmt.Println("PWN")
			break
		}
	}
}

func BreakPrefixMD4(b, checkSum []byte, validatorF func([]byte, []byte) bool) {
	suffix := []byte(";admin=true")
	for i := 0; i < 100; i++ {
		paddedMsg := AddMD4Padding(b, len(b)+i)
		inputMsg := utils.ConcatBytes(paddedMsg, suffix)
		sh := md4.NewWithState((ExtractMD4State(checkSum)), uint64(len(paddedMsg)+i))
		sh.Write(suffix)
		ncs := sh.Sum(nil)
		if validatorF(inputMsg, ncs[:]) {
			fmt.Println("PWN")
			break
		}
	}
}
