package common

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
)

// Length contants
const (
	PubKeyLen  = ed25519.PublicKeySize
	PrivKeyLen = ed25519.PrivateKeySize
	SignSize   = ed25519.SignatureSize
)

// PubKey is ed25519 public key type
type PubKey [PubKeyLen]byte

// Equal returns true, if key equal other
func (k *PubKey) Equal(other *PubKey) bool {
	return bytes.Equal(k[:], other[:])
}

func (k PubKey) String() string {
	return Base58Encode(k[:])
}

// SetString decodes hex-encoded key
func (k *PubKey) SetString(str string) *PubKey {
	copy(k[:], Base58Decode(str))
	return k
}

// GetHash returns SHA3-256 hash of public key
func (k *PubKey) GetHash() Hash256 {
	return Sha256H(k[:])
}

// PrivKey is ed25519 private key type
type PrivKey [PrivKeyLen]byte

func (k *PrivKey) String() string {
	return Base58Encode(k[:])
}

// SetString decodes hex-encoded key
func (k *PrivKey) SetString(str string) *PrivKey {
	copy(k[:], Base58Decode(str))
	return k
}

// SigData is ed25519 signature content type
type SigData [SignSize]byte

func (k SigData) String() string {
	return Base58Encode(k[:])
}

// SetString decodes hex-encoded key
func (k *SigData) SetString(str string) *SigData {
	copy(k[:], Base58Decode(str))
	return k
}

// GenerateKeypair returns new ed25519 key pair
func GenerateKeypair() (*PubKey, *PrivKey, error) {
	var (
		pubKey  PubKey
		privKey PrivKey
	)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	copy(pubKey[:], pub)
	copy(privKey[:], priv)
	return &pubKey, &privKey, nil
}

// Sign create ed25519 signature
func Sign(priv *PrivKey, msg []byte) *SigData {
	var sigData SigData
	sig := ed25519.Sign(priv[:], msg)
	copy(sigData[:], sig)
	return &sigData
}

// Verify ed25519 signature
func Verify(pub *PubKey, msg []byte, sig *SigData) bool {
	return ed25519.Verify(pub[:], msg, sig[:])
}

// PubKeyOf returns public key from private key
func PubKeyOf(priv *PrivKey) *PubKey {
	var pk PubKey
	copy(pk[:], priv[PubKeyLen:])
	return &pk
}

// SeedOf returns private key seed
func SeedOf(priv *PrivKey) []byte {
	return priv[:PubKeyLen]
}

// PrivKeyFromSeed returns private key from given seed
func PrivKeyFromSeed(seed []byte) *PrivKey {
	var priv PrivKey

	if len(seed) < 32 {
		seed = append(seed, make([]byte, 32-len(seed))...)
	}

	if len(seed) > 32 {
		seed = seed[:32]
	}

	pk := ed25519.NewKeyFromSeed(seed)
	copy(priv[:], pk[:])
	return &priv
}
