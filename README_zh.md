<div align="center">
</br>

# key25519


| [English](README.md) | 中文 |
| -------------------- | ---- |

`key25519` 是一个用Go语言编写的加密库，实现了基于Ed25519的多种密码学功能，包括BIP32分层确定性钱包、BIP39助记词生成、BIP44多账户钱包结构以及基于Curve25519的ECDH密钥交换协议。

</div>

## 特性

* **BIP32、BIP39、BIP44**：支持分层确定性钱包和助记词生成。
* **ECDH 密钥交换**：使用 Curve25519 实现安全密钥交换。
* **Keystore管理**：提供安全导出和导入Keystore的功能。

## 安装

使用`go get`命令安装:

```bash
go get github.com/lyonnee/key25519
```

## 使用示例

### ECDH 密钥交换

```go
kp1 := key25519.NewKeypair()
kp2 := key25519.NewKeypair()

kp1EcdhPubKey, _ := kp1.ExportEcdhPubKey()
kp2EcdhPubKey, _ := kp2.ExportEcdhPubKey()

sk1, _ := kp1.Ecdh(kp2EcdhPubKey)
sk2, _ := kp2.Ecdh(kp1EcdhPubKey)

// 双方共享的秘密应当相同
fmt.Println(format.EncodeBase58(sk1)) 
fmt.Println(format.EncodeBase58(sk2))
```

### HD钱包

```go
mnemonic, _ := bip39.GenerateMnemonic(bip39.LEN_12, bip39.ENGLISH)
seed := bip39.ToSeed(mnemonic, "")

masterKey := bip32.GenerateMasterKey(seed)
path := "m/44'/501'/0'/0'"
indexs, _ := bip44.ParsePath(path)

var newKey = masterKey
for _, v := range indexs {
    newKey = bip32.CKDPriv(newKey, v)
}

edPrivKey := ed25519.NewKeyFromSeed(newKey.PrivKey)
pubk, _ := key25519.NewPubKeyFromEd25119PubKey(edPrivKey.Public().(ed25519.PublicKey))

fmt.Println(format.EncodeBase58(edPrivKey)) // 私钥
fmt.Println(format.EncodeBase58(pubk.Bytes())) // 公钥
```

### 密钥库示例

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
 // 验证签名结果
fmt.Println(res)
```

## 贡献

欢迎提交问题和拉取请求来改进`key25519`。

## 许可证

`key25519`遵循MIT许可证。查看[LICENSE](LICENSE)文件以获取更多信息。
