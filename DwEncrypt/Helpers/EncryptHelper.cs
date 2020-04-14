using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

using XC.RSAUtil;

namespace DwEncrypt
{
    public class Aes
    {
        private const string DefaultKey = "FkdcRHwHMsvj1Ijh";
        private const string DefaultIv = "eotLNWogMH2RtDfc";

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="str"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Encrypt(string str, string key = null, string iv = null, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            if (key == null)
                key = DefaultKey;
            byte[] keyArray = encoding.GetBytes(key);
            if (keyArray.Length != 16)
                throw new ArgumentException("Key长度错误");
            if (iv == null)
                iv = DefaultIv;
            byte[] ivArray = encoding.GetBytes(iv);
            if (ivArray.Length != 16)
                throw new ArgumentException("IV长度错误");
            byte[] strArray = encoding.GetBytes(str);
            var rijndael = new RijndaelManaged
            {
                Key = keyArray,
                IV = ivArray,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            ICryptoTransform cTransform = rijndael.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(strArray, 0, strArray.Length);
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="str"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Decrypt(string str, string key = null, string iv = null, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            if (key == null)
                key = DefaultKey;
            byte[] keyArray = encoding.GetBytes(key);
            if (keyArray.Length != 16)
                throw new ArgumentException("Key长度错误");
            if (iv == null)
                iv = DefaultIv;
            byte[] ivArray = encoding.GetBytes(iv);
            if (ivArray.Length != 16)
                throw new ArgumentException("IV长度错误");
            byte[] strArray = Convert.FromBase64String(str);
            var rijndael = new RijndaelManaged
            {
                Key = keyArray,
                IV = ivArray,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            ICryptoTransform cTransform = rijndael.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(strArray, 0, strArray.Length);
            return Encoding.UTF8.GetString(resultArray);
        }
    }

    public class Md5
    {
        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string Encode(byte[] bytes)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] newBuffer = md5.ComputeHash(bytes);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < newBuffer.Length; i++)
                {
                    sb.Append(newBuffer[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Encode(string str, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            byte[] bytes = encoding.GetBytes(str);
            return Encode(bytes);
        }
    }

    public enum RsaKeyType
    {
        XML,
        Pkcs1,
        Pkcs8
    }

    public class RsaKeyPair
    {
        public RsaKeyType KeyType { get; private set; }
        public string PrivateKey { get; private set; }
        public string PublicKey { get; private set; }

        public RsaKeyPair(RsaKeyType keyType, int keySize)
        {
            List<string> keys;
            switch (keyType)
            {
                case RsaKeyType.XML:
                    keys = RsaKeyGenerator.XmlKey(keySize);
                    break;
                case RsaKeyType.Pkcs1:
                    keys = RsaKeyGenerator.Pkcs1Key(keySize, false);
                    break;
                case RsaKeyType.Pkcs8:
                    keys = RsaKeyGenerator.Pkcs8Key(keySize, false);
                    break;
                default:
                    throw new ArgumentException("Key类型不存在");
            }
            PrivateKey = keys[0];
            PublicKey = keys[1];
        }

        /// <summary>
        /// XML-> Pkcs1
        /// </summary>
        public void XmlToPkcs1()
        {
            PrivateKey = RsaKeyConvert.PrivateKeyXmlToPkcs1(PrivateKey);
            PublicKey = RsaKeyConvert.PublicKeyXmlToPem(PublicKey);
        }

        /// <summary>
        /// Pkcs1-> XML
        /// </summary>
        public void Pkcs1ToXml()
        {
            PrivateKey = RsaKeyConvert.PrivateKeyPkcs1ToXml(PrivateKey);
            PublicKey = RsaKeyConvert.PublicKeyPemToXml(PublicKey);
        }

        /// <summary>
        /// XML-> Pkcs8
        /// </summary>
        public void XmlToPkcs8()
        {
            PrivateKey = RsaKeyConvert.PrivateKeyXmlToPkcs8(PrivateKey);
            PublicKey = RsaKeyConvert.PublicKeyXmlToPem(PublicKey);
        }

        /// <summary>
        /// Pkcs8-> XML
        /// </summary>
        public void Pkcs8ToXml()
        {
            PrivateKey = RsaKeyConvert.PrivateKeyPkcs8ToXml(PrivateKey);
            PublicKey = RsaKeyConvert.PublicKeyPemToXml(PublicKey);
        }

        /// <summary>
        /// Pkcs1-> Pkcs8
        /// </summary>
        public void Pkcs1ToPkcs8()
        {
            PrivateKey = RsaKeyConvert.PrivateKeyPkcs1ToPkcs8(PrivateKey);
        }

        /// <summary>
        /// Pkcs8-> Pkcs1
        /// </summary>
        public void Pkcs8ToPkcs1()
        {
            PrivateKey = RsaKeyConvert.PrivateKeyPkcs8ToPkcs1(PrivateKey);
        }
    }

    public class Rsa
    {
        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKeyPair GenerateKeyPair(RsaKeyType keyType, int keySize) => new RsaKeyPair(keyType, keySize);

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(RsaKeyType keyType, string publicKey, string data, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            switch (keyType)
            {
                case RsaKeyType.XML:
                    return new RsaXmlUtil(encoding, publicKey).Encrypt(data, padding);
                case RsaKeyType.Pkcs1:
                    return new RsaPkcs1Util(encoding, publicKey).Encrypt(data, padding);
                case RsaKeyType.Pkcs8:
                    return new RsaPkcs8Util(encoding, publicKey).Encrypt(data, padding);
                default:
                    throw new ArgumentException("Key类型不存在");
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(RsaKeyType keyType, string privateKey, string data, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            switch (keyType)
            {
                case RsaKeyType.XML:
                    return new RsaXmlUtil(encoding, null, privateKey).Decrypt(data, padding);
                case RsaKeyType.Pkcs1:
                    return new RsaPkcs1Util(encoding, null, privateKey).Decrypt(data, padding);
                case RsaKeyType.Pkcs8:
                    return new RsaPkcs8Util(encoding, null, privateKey).Decrypt(data, padding);
                default:
                    throw new ArgumentException("Key类型不存在");
            }
        }

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <param name="hashAlgorithm"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Sign(RsaKeyType keyType, string privateKey, string data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            switch (keyType)
            {
                case RsaKeyType.XML:
                    return new RsaXmlUtil(encoding, null, privateKey).SignData(data, hashAlgorithm, padding);
                case RsaKeyType.Pkcs1:
                    return new RsaPkcs1Util(encoding, null, privateKey).SignData(data, hashAlgorithm, padding);
                case RsaKeyType.Pkcs8:
                    return new RsaPkcs8Util(encoding, null, privateKey).SignData(data, hashAlgorithm, padding);
                default:
                    throw new ArgumentException("Key类型不存在");
            }
        }

        /// <summary>
        /// 验证
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="sign"></param>
        /// <param name="hashAlgorithm"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static bool Verify(RsaKeyType keyType, string publicKey, string data, string sign, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            switch (keyType)
            {
                case RsaKeyType.XML:
                    return new RsaXmlUtil(encoding, publicKey).VerifyData(data, sign, hashAlgorithm, padding);
                case RsaKeyType.Pkcs1:
                    return new RsaPkcs1Util(encoding, publicKey).VerifyData(data, sign, hashAlgorithm, padding);
                case RsaKeyType.Pkcs8:
                    return new RsaPkcs8Util(encoding, publicKey).VerifyData(data, sign, hashAlgorithm, padding);
                default:
                    throw new ArgumentException("Key类型不存在");
            }
        }
    }
}
