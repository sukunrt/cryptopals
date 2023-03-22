package crypto

import (
	"github.com/sukunrt/cryptopals/utils"
)

type MD struct {
	// Size is the size of the hash in bits
	Size int
}

func NewMD(n int) *MD {
	return &MD{n}
}

func (m *MD) Hash(b []byte, initH []byte) []byte {
	hsz := (m.Size + 7) / 8
	h := make([]byte, hsz)
	copy(h, initH)
	cipher := NewAESInCBCCipher(utils.PadBytes(h, AESBlockSize))
	b = utils.PadBytes(b, AESBlockSize)
	for i := 0; i < len(b); i += AESBlockSize {
		h = cipher.Encrypt(b[i:i+AESBlockSize], make([]byte, AESBlockSize))[:hsz]
		cipher = NewAESInCBCCipher(utils.PadBytes(h, AESBlockSize))
	}
	return h
}
