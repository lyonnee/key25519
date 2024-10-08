// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

/*

This key store behaves as KeyStorePlain with the difference that
the private key is encrypted and on disk uses another JSON encoding.

The crypto is documented at https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

*/

package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Constants for Scrypt and AES
const (
	keyHeaderKDF = "scrypt"

	StandardScryptN = 1 << 18
	StandardScryptP = 1

	LightScryptN = 1 << 12
	LightScryptP = 6

	scryptR     = 8
	scryptDKLen = 32
)

// CryptoJSON holds the encrypted data and encryption parameters
type cryptoJson struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

// CipherParamsJSON holds the IV parameter
type cipherparamsJSON struct {
	IV string `json:"iv"`
}

// encryptData encrypts the given data with the specified password and scrypt parameters
func encryptData(data, password []byte, scryptN, scryptP int) (cryptoJson, error) {
	// 生成加密盐
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return cryptoJson{}, fmt.Errorf("reading from crypto/rand failed: %w", err)
	}

	// 生成加密的密钥
	derivedKey, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return cryptoJson{}, err
	}
	encryptKey := derivedKey[:16]

	// 生成私钥密文
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return cryptoJson{}, fmt.Errorf("reading from crypto/rand failed: %w", err)
	}
	cipherText, err := aesCTRXOR(encryptKey, data, iv)
	if err != nil {
		return cryptoJson{}, err
	}

	// 生成用于验证密码的代码
	// mac := crypto.Keccak256(derivedKey[16:32], cipherText)
	h := hmac.New(sha256.New, derivedKey[16:32])
	h.Write(cipherText)
	mac := h.Sum(nil)

	scryptParamsJSON := map[string]interface{}{
		"n":     scryptN,
		"r":     scryptR,
		"p":     scryptP,
		"dklen": scryptDKLen,
		"salt":  hex.EncodeToString(salt),
	}
	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJson{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          keyHeaderKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	return cryptoStruct, nil
}

// decryptData decrypts the given encrypted data with the specified password
func decryptData(cryptoJson cryptoJson, auth string) ([]byte, error) {
	if cryptoJson.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("cipher not supported: %v", cryptoJson.Cipher)
	}
	mac, err := hex.DecodeString(cryptoJson.MAC)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(cryptoJson.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(cryptoJson.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(cryptoJson, auth)
	if err != nil {
		return nil, err
	}

	// calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	h := hmac.New(sha256.New, derivedKey[16:32])
	h.Write(cipherText)
	calculatedMAC := h.Sum(nil)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, fmt.Errorf("invalid MAC, decryption failed")
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// aesCTRXOR performs AES-128-CTR encryption/decryption
func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, nil
}

// getKDFKey generates the derived key using the specified KDF parameters and password
func getKDFKey(cryptoJSON cryptoJson, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	switch cryptoJSON.KDF {
	case keyHeaderKDF:
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key(authArray, salt, n, r, p, dkLen)
	case "pbkdf2":
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("unsupported PBKDF2 PRF: %s", prf)
		}
		return pbkdf2.Key(authArray, salt, c, dkLen, sha256.New), nil
	default:
		return nil, fmt.Errorf("unsupported KDF: %s", cryptoJSON.KDF)
	}
}

// ensureInt ensures that the provided interface is converted to an integer
func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}
