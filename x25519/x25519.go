package x25519

import (
	"crypto/ed25519"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func (kp *KeyPair) EcdhShare(peerPubKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(kp.PrivateKey, peerPubKey)
	if err != nil {
		return nil, err
	}

	hashedSecret := sha256.Sum256(sharedSecret)
	return hashedSecret[:], nil
}

func GenerateKeyPair(ed25519PrivKey ed25519.PrivateKey) (*KeyPair, error) {
	privKey := ed25519PrivKey.Seed()
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privKey[:],
		PublicKey:  pubKey[:],
	}, nil
}
