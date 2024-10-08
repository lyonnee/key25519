package key25519

import "github.com/lyonnee/key25519/x25519"

// ECDH functions for KeyPair

func (kp *KeyPair) ExportEcdhKeyPair() (*x25519.KeyPair, error) {
	return x25519.GenerateKeyPair(kp.privKey.Bytes())
}

func (kp *KeyPair) ECDH(peerEcdhPubKey []byte) ([]byte, error) {
	x25519kp, err := kp.ExportEcdhKeyPair()
	if err != nil {
		return nil, err
	}
	return x25519kp.EcdhShare(peerEcdhPubKey)
}

// PrivateKey functions for KeyPair

func (privKey PrivateKey) ExportEcdhKeyPair() (*x25519.KeyPair, error) {
	return x25519.GenerateKeyPair(privKey.ToEd25519PrivKey())
}

func (privKey PrivateKey) ECDH(peerEcdhPubKey []byte) ([]byte, error) {
	x25519kp, err := x25519.GenerateKeyPair(privKey.ToEd25519PrivKey())
	if err != nil {
		return nil, err
	}
	return x25519kp.EcdhShare(peerEcdhPubKey)
}
