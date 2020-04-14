# DwEncrypt

符合BIP39标准的加密SDK

### 0x1 初始化

```c#
PM> Install-Package DwEncrypt
或
> dotnet add package DwEncrypt
```

### 0x2 生成助记词

```c#
var mnemonic = EncryptManager.GenerateMnemonicString(MnemonicType.English, MnemonicCount.Twelve);
```

### 0x3 实例化管理器

```c#
var manager = new EncryptManager(mnemonic, "私钥密码");
```

### 0x4 加密文本

```c#
// 助记词
// icon scheme shallow person tuition world visit eyebrow detail hint caution night
var text = "文本";
var encryptText = manager.Encrypt(text, "文本密码");
// P5uczBIU0/TANay9eb7D4chv+GC4jM+QZ0uAT8U4AhU=
```

### 0x5 解密文本

```c#
text = manager.Decrypt(encryptText, "文本密码");
```

### 0x6 传输加密

传输加密使用RSA加密方式，你可以自行生成密钥对或者通过LockManager生成。

```c#
// 生成密钥对
var keyPair = EncryptManager.GenerateKeyPair(RsaKeyType.Pkcs1, 2048);
var text = "文本";
// 加密
var encryptText = EncryptManager.Encrypt(RsaKeyType.Pkcs1, keyPair.PublicKey, text, RSAEncryptionPadding.OaepSHA256);
// 解密
text = EncryptManager.Decrypt(RsaKeyType.Pkcs1, keyPair.PrivateKey, encryptText, RSAEncryptionPadding.OaepSHA256);
```

### 0x7签名及验证

```c#
var data = "文本";
// 签名
var sign = EncryptManager.Sign(RsaKeyType.Pkcs1, data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
// 验证
var isPass = var isPass = EncryptManager.Verify(RsaKeyType.Pkcs1, data, sign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
```