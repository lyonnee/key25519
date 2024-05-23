<div align="center">
</br>

# key25519


| English | [中文](README.zh.md) |
| ------- | -------------------- |

`key25519` is a cryptographic library written in Go that implements a variety of cryptographic functions based on Ed25519, including BIP32 hierarchical deterministic wallets, BIP39 mnemonic generation, BIP44 multi-account wallet structures, and ECDH key exchange protocols based on Curve25519.

</div>

## Features

- **BIP32, BIP39, BIP44**: Supports hierarchical deterministic wallets and mnemonic generation.
- **ECDH Key Exchange**: Secure key exchange implemented using Curve25519.
- **Keystore Management**: Provides functionalities to securely export and import Keystores.

## Installation

Install using the `go get` command:

```bash
go get github.com/lyonnee/key25519
```

## Usage Examples

### ECDH Key Exchange

```go
kp1 := key25519.NewKeypair()
kp2 := key25519.NewKeypair()

kp1EcdhPubKey, _ := kp1.ExportEcdhPubKey()
kp2EcdhPubKey, _ := kp2.ExportEcdhPubKey()

sk1, _ := kp1.Ecdh(kp2EcdhPubKey)
sk2, _ := kp2.Ecdh(kp1EcdhPubKey)

// The shared secret should be the same for both parties
fmt.Println(format.EncodeBase58(sk1))
fmt.Println(format.EncodeBase58(sk2))
```

### HD Wallet

```go
mnemonic, _ := bip39.GenerateMnemonic(bip39.LEN_12, bip39.ENGLISH)
seed := bip39.NewSeed(mnemonic, "")

masterKey := bip32.NewMasterKey(seed)
path := "m/44'/501'/0'/0'"
indexs, _ := bip44.ParsePath(path)

var newKey = masterKey
for _, v := range indexs {
    newKey = bip32.CKDPriv(newKey, v)
}

edPrivKey := ed25519.NewKeyFromSeed(newKey.PrivKey)
pubk, _ := key25519.NewPubKeyFromEd25519PubKey(edPrivKey.Public().(ed25519.PublicKey))

fmt.Println(format.EncodeBase58(edPrivKey)) // Private key
fmt.Println(format.EncodeBase58(pubk.Bytes())) // Public key
```

### Keystore Example

```go
kp := key25519.NewKeypair()
originMsg := []byte("i am lyon")
signedMsg := kp.PrivateKey().SignMsg(originMsg)

filename := "./" + format.EncodeBase58(kp.PublicKey().Bytes()) + ".keystore"
password := "kaixin"

err := kp.ExportKeystore(filename, password)
// ...

key, _ := key25519.LoadPrivKeyFromKeystore(filename, password)
kp2, _ := key25519.NewKeypairFromPrivKeyBytes(key)

res := key25519.VerifyMsg(kp2.PublicKey(), originMsg, signedMsg)
// Verification of the signature
fmt.Println(res)
```

## Contribution

We welcome issues and pull requests to improve `key25519`.

## License

`key25519` is released under the MIT License. See the [LICENSE](LICENSE) file for more information.
