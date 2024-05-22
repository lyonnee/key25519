package key25519

import (
	"crypto/ed25519"
	"encoding/hex"
)

const PublicKeyLength int = ed25519.PublicKeySize

type PublicKey [PublicKeyLength]byte

func NewPubKeyFromEd25119PubKey(key ed25519.PublicKey) (PublicKey, error) {
	return bytesToPubKey(key)
}

func (pk PublicKey) HexString() string {
	return hex.EncodeToString(pk.Bytes())
}

func (pk PublicKey) VerifyMsg(originMsg, signMsg []byte) bool {
	return ed25519.Verify(pk[:], originMsg, signMsg)
}

func (pk PublicKey) Bytes() []byte {
	return pk[:]
}

func (pk *PublicKey) LoadFromBytes(d []byte) error {
	bpk, err := bytesToPubKey(d)
	if err != nil {
		return err
	}

	*pk = bpk

	return err
}

func bytesToPubKey(d []byte) (PublicKey, error) {
	var pubKey PublicKey
	copy(pubKey[:], d)
	return pubKey, nil
}
