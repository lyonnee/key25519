package key25519

import "github.com/lyonnee/key25519/ecdh"

func Ecdh(privKey PrivateKey, peerPubKey []byte) ([]byte, error) {
	kp, err := ecdh.GenerateKeyPair(privKey.ToEd25519PrivKey())
	if err != nil {
		return nil, err
	}
	return ecdh.EcdhShare(kp.PrivateKey, peerPubKey)
}

func ExportEcdhKeypair(privKey PrivateKey) (*ecdh.Keypair, error) {
	return ecdh.GenerateKeyPair(privKey.ToEd25519PrivKey())
}
