package ecdh

import (
	"crypto/ed25519"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

type Keypair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func GenerateKeyPair(ed25519PrivKey ed25519.PrivateKey) (*Keypair, error) {
	privKey := ed25519PrivKey.Seed()
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		PrivateKey: privKey[:],
		PublicKey:  pubKey[:],
	}, nil
}

func EcdhShare(privKey, peerPubKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privKey, peerPubKey)
	if err != nil {
		return nil, err
	}

	hashedSecret := sha256.Sum256(sharedSecret)
	return hashedSecret[:], nil
}
