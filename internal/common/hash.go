package common

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	mrand "math/rand"
	"os"

	"golang.org/x/crypto/sha3"
)

const Hash256Len = 32

// Hash256 is 32-byte hash value
type Hash256 [Hash256Len]byte

// EmptyHash256 returns zero hash
func EmptyHash256() Hash256 { return Hash256{} }

// SetBytes copy given byte slice to hash value
func (h *Hash256) SetBytes(b []byte) {
	copy(h[:], b[:])
}

func (h *Hash256) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

func (h *Hash256) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}

	return h.SetString(str)
}

// Bytes convert hash result to byte slice
func (h Hash256) Bytes() []byte {
	return h[:]
}

func (h Hash256) String() string {
	return string(Base58Encode(h[:]))
}

func (h *Hash256) SetString(s string) error {
	bytes := Base58Decode(s)
	if len(bytes) != len(h) {
		return errors.New("invalid length")
	}

	copy(h[:], bytes[:])
	return nil
}

// Equal returns true, if hashes is equal
func (h Hash256) Equal(h2 Hash256) bool {
	return bytes.Equal(h[:], h2[:])
}

// Empty returns if hash is zero
func (h Hash256) Empty() bool { return h.Equal(Hash256{}) }

// Xor operations for hashes
func (h Hash256) Xor(other Hash256) (ret Hash256) {
	for i := 0; i < Hash256Len; i++ {
		ret[i] = h[i] ^ other[i]
	}
	return ret
}

// PrefixLen Возвращает длину префикса ID в сравнении с other
func (h Hash256) PrefixLen(other Hash256) int {
	distance := h.Xor(other)
	for i := 0; i < Hash256Len; i++ {
		for j := 0; j < 8; j++ {
			if (distance[i]>>uint8(7-j))&0x1 != 0 {
				return 8*i + j
			}
		}
	}
	return -1
}

// Distance is scalar XOR for hashes
func (h Hash256) Distance(other Hash256) int {
	dist := 0
	for i := 0; i < 32; i++ {
		dist += int(h[i] ^ other[i])
	}
	return dist
}

// ToBigInt returns big.Int from given hash
func (h Hash256) ToBigInt() *big.Int {
	return new(big.Int).SetBytes(h[:])
}

// SetBigInt set big.Int as hash
func (h Hash256) SetBigInt(i *big.Int) Hash256 {
	buf := make([]byte, 32)
	copy(buf, i.Bytes())
	copy(h[:], buf)
	return h
}

// SortHash256 sorts 256-bit hashes
func SortHash256(a []Hash256) []Hash256 {
	if len(a) < 2 {
		return a
	}

	l, r := 0, len(a)-1

	pivIndex := mrand.Int() % len(a)

	a[pivIndex], a[r] = a[r], a[pivIndex]
	for i := range a {
		if a[i].ToBigInt().Cmp(a[r].ToBigInt()) < 0 {
			a[i], a[l] = a[l], a[i]
			l++
		}
	}

	a[l], a[r] = a[r], a[l]
	SortHash256(a[:l])
	SortHash256(a[l+1:])

	return a
}

// FileSha256 returns SHA3-256 hash of given file
func FileSha256(path string) (fh Hash256, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return
	}

	defer fd.Close()

	h := sha3.New256()
	_, err = io.Copy(h, fd)
	if err != nil {
		return
	}

	copy(fh[:], h.Sum(nil))
	return
}

// Sha256H calculate SHA3-256 hash and returns it as Hash256
func Sha256H(input ...[]byte) Hash256 {
	h := Hash256{}
	// h.SetBytes(utils.SHA256(input...))
	hsr := sha3.New256()
	for i := range input {
		hsr.Write(input[i])
	}

	copy(h[:], hsr.Sum(nil))
	return h
}

// Hmac256 returns SHA3-256-HMAC for given data and key
func Hmac256(data []byte, key []byte) (h Hash256) {
	hm := hmac.New(sha3.New256, key)
	hm.Write(data)
	copy(h[:], hm.Sum(nil))
	return
}
