package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
)

type Key struct {
	PrivKey   []byte
	ChainCode []byte
}

// HMAC-SHA512 function
func hmacSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// GenerateMasterKey generates a master key from the seed
func GenerateMasterKey(seed []byte) Key {
	I := hmacSHA512([]byte("ed25519 seed"), seed)

	return Key{
		PrivKey:   I[:32],
		ChainCode: I[32:],
	}
}

func CKDPriv(key Key, index uint32) Key {
	buffer := make([]byte, 0, 1+4+len(key.PrivKey))
	buffer = append(buffer, 0)
	buffer = append(buffer, key.PrivKey...)
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, index)
	buffer = append(buffer, v...)

	I := hmacSHA512(key.ChainCode, buffer)

	return Key{
		PrivKey:   I[:32],
		ChainCode: I[32:],
	}
}
