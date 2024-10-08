package x25519

import (
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

func EcdhShare(privKey, peerPubKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privKey, peerPubKey)
	if err != nil {
		return nil, err
	}

	hashedSecret := sha256.Sum256(sharedSecret)
	return hashedSecret[:], nil
}
