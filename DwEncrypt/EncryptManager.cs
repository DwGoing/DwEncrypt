using System;
using System.Security.Cryptography;
using System.Text;

using NBitcoin;

namespace DwEncrypt
{
    public class MnemonicType
    {
        public static Wordlist ChineseSimplified { get { return Wordlist.ChineseSimplified; } }
        public static Wordlist ChineseTraditional { get { return Wordlist.ChineseTraditional; } }
        public static Wordlist Czech { get { return Wordlist.Czech; } }
        public static Wordlist English { get { return Wordlist.English; } }
        public static Wordlist French { get { return Wordlist.French; } }
        public static Wordlist Japanese { get { return Wordlist.Japanese; } }
        public static Wordlist PortugueseBrazil { get { return Wordlist.PortugueseBrazil; } }
        public static Wordlist Spanish { get { return Wordlist.Spanish; } }
    }

    public enum MnemonicCount
    {
        Twelve = 12,
        Fifteen = 15,
        Eighteen = 18,
        TwentyOne = 21,
        TwentyFour = 24
    }

    public class EncryptManager
    {
        private string[] _aesKeys;
        private Encoding _encoding;

        public bool IsInit
        {
            get
            {
                if (_aesKeys == null || _aesKeys.Length <= 0)
                    return false;
                return true;
            }
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="mnemonicString"></param>
        /// <param name="passphrase"></param>
        public EncryptManager(string mnemonicString, string passphrase = null, Encoding encoding = null)
        {
            if (encoding == null)
                _encoding = Encoding.UTF8;
            InitAesKeyIvs(new Mnemonic(mnemonicString), passphrase);
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="mnemonicWords"></param>
        /// <param name="passphrase"></param>
        public EncryptManager(string[] mnemonicWords, string passphrase = null, Encoding encoding = null)
        {
            if (encoding == null)
                _encoding = Encoding.UTF8;
            InitAesKeyIvs(new Mnemonic(WordsToString(mnemonicWords)), passphrase);
        }

        /// <summary>
        /// 初始化AesKeyIvs
        /// </summary>
        /// <param name="mnemonic"></param>
        /// <param name="passphrase"></param>
        private void InitAesKeyIvs(Mnemonic mnemonic, string passphrase)
        {
            _aesKeys = new string[4];
            var privateKey = GenerateExtKey(mnemonic, passphrase).PrivateKey.ToHex();
            for (int i = 0; i < 4; i++)
            {
                _aesKeys[i] = privateKey.Substring(i * 16, 16);
            }
        }

        #region 公共静态方法
        /// <summary>
        /// 生成助记词
        /// </summary>
        /// <param name="wordlist"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static string GenerateMnemonicString(Wordlist wordlist, MnemonicCount count)
        {
            return GenerateMnemonic(wordlist, count).ToString();
        }

        /// <summary>
        /// 生成助记词
        /// </summary>
        /// <param name="wordlist"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static string[] GenerateMnemonicWords(Wordlist wordlist, MnemonicCount count)
        {
            return GenerateMnemonic(wordlist, count).Words;
        }

        /// <summary>
        /// MnemonicWords转MnemonicString
        /// </summary>
        /// <param name="words"></param>
        /// <returns></returns>
        public static string WordsToString(string[] words)
        {
            StringBuilder builder = new StringBuilder();
            foreach (var item in words)
            {
                builder.Append(item);
                if (words[words.Length - 1] != item)
                    builder.Append(" ");
            }
            return builder.ToString();
        }

        /// <summary>
        /// MnemonicString转MnemonicWords
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string[] StringToWords(string str)
        {
            return str.Split(" ");
        }

        /// <summary>
        /// 生成RSA密钥对
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static RsaKeyPair GenerateKeyPair(RsaKeyType keyType, int keySize)
        {
            return Rsa.GenerateKeyPair(keyType, keySize);
        }

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Encrypt(RsaKeyType keyType, string publicKey, string data, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            return Rsa.Encrypt(keyType, publicKey, data, padding, encoding);
        }

        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="privateKey"></param>
        /// <param name="data"></param>
        /// <param name="padding"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(RsaKeyType keyType, string privateKey, string data, RSAEncryptionPadding padding, Encoding encoding = null)
        {
            return Rsa.Decrypt(keyType, privateKey, data, padding, encoding);
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
            return Rsa.Sign(keyType, privateKey, data, hashAlgorithm, padding, encoding);
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
            return Rsa.Verify(keyType, publicKey, data, sign, hashAlgorithm, padding, encoding);
        }
        #endregion

        #region 公共方法
        /// <summary>
        /// 加密文本
        /// </summary>
        /// <param name="text"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public string Encrypt(string text, string password)
        {
            if (!IsInit)
                throw new Exception("未初始化");
            var ivStr = Md5.Encode(password);
            for (int i = 0; i < 4; i++)
            {
                var key = _encoding.GetString(XorBytes(_encoding.GetBytes(_aesKeys[i]), _encoding.GetBytes(ivStr.Substring(i % 2 * 16, 16))));
                text = Aes.Encrypt(text, key);
            }
            return text;
        }

        /// <summary>
        /// 解密文本
        /// </summary>
        /// <param name="text"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public string Decrypt(string text, string password)
        {
            if (!IsInit)
                throw new Exception("未初始化");
            var ivStr = Md5.Encode(password);
            for (int i = 3; i >= 0; i--)
            {
                try
                {
                    var key = _encoding.GetString(XorBytes(_encoding.GetBytes(_aesKeys[i]), _encoding.GetBytes(ivStr.Substring(i % 2 * 16, 16))));
                    text = Aes.Decrypt(text, key);
                }
                catch { throw new Exception("无法解密"); }
            }
            return text;
        }
        #endregion

        #region 私有静态方法
        /// <summary>
        /// 生成助记词
        /// </summary>
        /// <param name="wordlist"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        private static Mnemonic GenerateMnemonic(Wordlist wordlist, MnemonicCount count) => new Mnemonic(wordlist, (WordCount)count);

        /// <summary>
        /// 生成Key
        /// </summary>
        /// <param name="mnemonic"></param>
        /// <param name="passphrase"></param>
        /// <returns></returns>
        private static ExtKey GenerateExtKey(Mnemonic mnemonic, string passphrase = null) => mnemonic.DeriveExtKey(passphrase);

        /// <summary>
        /// 异或操作
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte[] XorBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new Exception("数组长度不相同");
            var newBytes = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                newBytes[i] = Convert.ToByte(a[i] ^ b[i]);
            }
            return newBytes;
        }
        #endregion
    }
}
