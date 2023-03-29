package crypto

import (
	"errors"

	"github.com/sukunrt/cryptopals/utils"
)

type MD struct {
	// Size is the size of the hash in bits
	Size int
	Hsz  int
	H    []byte
}

func NewMD(n int) *MD {
	hsz := (n + 7) / 8
	return &MD{Size: n, Hsz: hsz, H: make([]byte, hsz)}
}

func (m *MD) Copy() *MD {
	h := make([]byte, m.Hsz)
	copy(h, m.H)
	return &MD{
		Size: m.Size,
		Hsz:  m.Hsz,
		H:    h,
	}
}

func (m *MD) Hash(b []byte, initH []byte) []byte {
	m.H = make([]byte, m.Hsz)
	copy(m.H, initH)
	cipher := NewAESInCBCCipher(utils.PadBytes(m.H, AESBlockSize))
	b = utils.PadBytes(b, AESBlockSize)
	for i := 0; i < len(b); i += AESBlockSize {
		m.H = cipher.Encrypt(b[i:i+AESBlockSize], make([]byte, AESBlockSize))[:m.Hsz]
		cipher = NewAESInCBCCipher(utils.PadBytes(m.H, AESBlockSize))
	}
	return m.H
}

func (m *MD) WriteBlock(b []byte) ([]byte, error) {
	if len(b)%AESBlockSize != 0 {
		return nil, errors.New("invalid message size")
	}
	cipher := NewAESInCBCCipher(utils.PadBytes(m.H, AESBlockSize))
	for i := 0; i < len(b); i += AESBlockSize {
		m.H = cipher.Encrypt(b[i:i+AESBlockSize], make([]byte, AESBlockSize))[:m.Hsz]
		cipher = NewAESInCBCCipher(utils.PadBytes(m.H, AESBlockSize))
	}
	return m.H, nil
}

func (m *MD) Reset() {
	m.H = make([]byte, m.Hsz)
}

func (m *MD) Set(h []byte) {
	m.H = h[:m.Hsz]
}

func MakeExpandableMessages(md *MD, k int) [][2][]byte {
	res := make([][2][]byte, k)
	hp := make([]byte, md.Hsz)
	for i := 0; i < k; i++ {
		md.Set(hp)

		n := 1
		for j := 0; j < k-i-1; j++ {
			n *= 2
		}
		b2 := utils.RandBytes(n * AESBlockSize)
		st, _ := md.WriteBlock(b2)

		m := make(map[string][]byte)
		for {
			md.Set(hp)
			b1 := utils.RandBytes(AESBlockSize)
			h1, _ := md.WriteBlock(b1)
			m[string(h1)] = b1

			md.Set(st)
			b3 := utils.RandBytes(AESBlockSize)
			h2, _ := md.WriteBlock(b3)
			if b, ok := m[string(h2)]; ok {
				hp = h2
				res[i] = [...][]byte{b, utils.ConcatBytes(b2, b3)}
				break
			}
		}
	}
	md.Reset()
	return res
}

func FindCollisions(b []byte, md *MD) []byte {
	k, n := 0, 1
	for (n * AESBlockSize) < len(b) {
		k++
		n *= 2
	}
	md.Reset()
	m := make(map[string]int)
	for i := 0; i < n; i += 1 {
		h, _ := md.WriteBlock(b[i*AESBlockSize : (i+1)*AESBlockSize])
		if i >= k {
			m[string(h)] = i + 1
		}
	}
	md.Reset()
	msgs := MakeExpandableMessages(md, k)
	md.Reset()
	var st []byte
	for i := 0; i < k; i++ {
		st, _ = md.WriteBlock(msgs[i][0])
	}

	var ii int
	var ok bool
	var bridge []byte
	for {
		bridge = utils.RandBytes(AESBlockSize)
		md.Set(st)
		h, _ := md.WriteBlock(bridge)
		if ii, ok = m[string(h)]; ok {
			break
		}
	}

	t := ii - 1
	if t < k {
		panic("small len")
	}
	var res []byte
	for i := 0; i < k; i++ {
		x := len(msgs[i][1]) / AESBlockSize
		if t-(k-i-1) >= x {
			res = append(res, msgs[i][1]...)
			t -= x
		} else {
			res = append(res, msgs[i][0]...)
			t -= 1
		}
	}
	res = append(res, bridge...)
	res = append(res, b[ii*AESBlockSize:]...)
	return res
}

type sTree struct {
	nm     []map[string][]byte
	hm     []map[string]string
	sz     int
	states [][][]byte
	md     *MD

	Len  int
	Hash []byte
}

func (s *sTree) isLeaf(b []byte) bool {
	_, ok := s.nm[0][string(b)]
	return ok
}

func makeSTree(k int, md *MD) *sTree {
	s := &sTree{
		nm:     make([]map[string][]byte, k+1),
		hm:     make([]map[string]string, k+1),
		sz:     k,
		states: make([][][]byte, k+1),
		md:     md,
		Len:    k + 2048 + 10,
		Hash:   make([]byte, md.Hsz),
	}
	n := 1
	for i := 0; i < k; i++ {
		n *= 2
	}
	s.nm[0] = make(map[string][]byte)
	s.hm[0] = make(map[string]string)
	s.states[0] = make([][]byte, 0)
	for i := 0; i < n; i++ {
		for {
			h := utils.RandBytes(md.Hsz)
			if _, ok := s.nm[0][string(h)]; !ok {
				s.nm[0][string(h)] = make([]byte, AESBlockSize)
				s.states[0] = append(s.states[0], h)
				break
			}
		}
	}
	// at this point the ith layer has been set. The last layer will not need any work so i < k-1
	for i := 0; i < k; i++ {
		if i+1 <= k {
			s.nm[i+1] = make(map[string][]byte)
			s.states[i+1] = make([][]byte, 0)
			s.hm[i+1] = make(map[string]string)
		}
		m := make(map[string]int)
		mb := make([]map[string][]byte, n)
		done := make(map[int]bool)
		cnt := 0
		for j := 0; j < n; j++ {
			mb[j] = make(map[string][]byte)
		}
	OUTER:
		for {
			for j := 0; j < n; j++ {
				if done[j] {
					continue
				}
				b := utils.RandBytes(AESBlockSize)
				md.Set(s.states[i][j])
				h, _ := md.WriteBlock(b)
				x, ok := m[string(h)]
				if !ok {
					m[string(h)] = j
					mb[j][string(h)] = b
					continue
				} else if ok && (x == j || done[x]) {
					continue
				}
				done[j] = true
				done[x] = true
				s.nm[i+1][string(h)] = make([]byte, AESBlockSize)
				s.states[i+1] = append(s.states[i+1], h)
				s.nm[i][string(s.states[i][j])] = b
				s.nm[i][string(s.states[i][x])] = mb[x][string(h)]
				s.hm[i][string(s.states[i][j])] = string(h)
				s.hm[i][string(s.states[i][x])] = string(h)
				cnt += 2
				if cnt >= n {
					break OUTER
				}
			}
		}
		n /= 2
	}
	x := utils.PadBytes(make([]byte, AESBlockSize), AESBlockSize)
	s.md.Set(s.states[k][0])
	s.Hash, _ = s.md.WriteBlock(x[len(x)-AESBlockSize:])
	return s
}
