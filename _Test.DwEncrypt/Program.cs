using System;
using System.Security.Cryptography;

using DwEncrypt;

namespace _Test.DwEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            var publicKey = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0CJNhxLG2wOo57eF/Ornj7YXD6/eJoFq/Gc/KNm5EoVafv9Ug92jmUbPAPWIM9Ci07KaQd+J6T18VCO2WzFtYHV3uyu+cIUNSrZcBHXple5u3Z4/1le76x/DaMGCaGfRdtg6hoON33BV6+2Y09KcOqpFankMDUhOHGxej+w4s5Gz02/OPY1ubH8RN9+kSd7Cu/NBDnyV1losPC/aGXtV8IuVT4hF3E6AFywNNer4R59oUO+bKoDIwu89eTVoZR2haRgtryhq9VCDFVIOVXGup2w5CVHnOLJsvtMtqjKMO/wCbVYTmbtGaVQy2r7W2FT+tbCUdxH3sc0kLYXtVfwhtwIDAQAB";
            var privateKey = @"MIIEpAIBAAKCAQEA0CJNhxLG2wOo57eF/Ornj7YXD6/eJoFq/Gc/KNm5EoVafv9Ug92jmUbPAPWIM9Ci07KaQd+J6T18VCO2WzFtYHV3uyu+cIUNSrZcBHXple5u3Z4/1le76x/DaMGCaGfRdtg6hoON33BV6+2Y09KcOqpFankMDUhOHGxej+w4s5Gz02/OPY1ubH8RN9+kSd7Cu/NBDnyV1losPC/aGXtV8IuVT4hF3E6AFywNNer4R59oUO+bKoDIwu89eTVoZR2haRgtryhq9VCDFVIOVXGup2w5CVHnOLJsvtMtqjKMO/wCbVYTmbtGaVQy2r7W2FT+tbCUdxH3sc0kLYXtVfwhtwIDAQABAoIBAQCsqCgkKwFnYgvV3Tp7auqZHvbWfpAM5UM5CvUsECElKha+T1Vu5of2ePTz2LsaMLNCZmDs0GF5aRYgPlfiIoiXghrG3Czo7pbuKYT/9kjFpbu2gLZ4OuOa0wipeA2USrtKmWlDeRJSDsBYLQugfJA5YlKfVrcWtaqGjaeMQOtwmabvcswIYDe1saiBCRXr7/Iv4KFgpVMfRYls1wzwaDv393RaUKmSjxmIRLW+k75jKdglkcGAK3RqLLs/CIYQ/mHWxWQsS2xf1SN+vK3CNNXsVNO000i7uVwS2e9Ou/P9wYhOsADs4Axf+sTPUnDCZvzGblmpqtUzD6ErAcC8VKtxAoGBAP8O1c1lNI9yp65SVMgCFx8HaOn9U+wruKWJ6O0VeiEaJLasgwF05E+nEImM0Q/Scq5EoCg6mh2aY95iOam2aBwVgah9qHnrEJ+wChclxGviNNfDm1zcAeltUO2yHD4dtFPEIl+yXD3KUwlQRgFyvo+XhA/HOwsDTySDFSnAKrk1AoGBANDnGYVO6gjFmshlljRIlLohJnqVmvmtE5IUn5NCMX+TNakzvwpRzrtLc+1ZSf1yBMosgn88poDdjkGHZL8ZXwtEsV/+v/zkFQW0aEtFs67cVUfktOKSjHG+evqMZlekEcQTXZz1UG4wulZ7RBqQxM0PybBk5Dys9m43claE3ni7AoGBANq6VCuiIOLrhlT+Eeq7sCxR5GzVbITaMaz0iaXXhzaf/uARLP+wyKJuOMZc1mRlKye7fkVBjCza2844Gg8qeDmtT9W4fSSgq07mXqDfKIUEJiDqhG+r1I/jyUUuOv4h5yT2zCuY/3WV7oPMLVzMlBL78qq9Rir5mYNMTnfRblIJAoGADUQ/6KlkT35NICDjcxqQ52knim1p1CVbstFAeRehERsGM2Kn5T3gxSA7kn0zJ7dP+o7tEquFX3WyjRLOIRy5XnvUT+ZbxvGtLBmS7gTVLmurts8dda4c4TRZlwPHlBVFU5BvR4KEwxqxGsDlSFKdTPCNvHgLzpalZ8Z5qmjxv/UCgYAC3J1BB4h14e3mFfQ8wAI2KJudL2zHbWX3EG6DG+PLAfBNmw4PyYRycfViXBGZvYTka355vmxDFjkSQea7yIDk0oiL/QNQPXQF9BRcHMBgopW4eaj81RqVWv8P8QCMH4u1cE6mD5KwT2DB1cXMslkFS6oCN85nokFJZ6Jt/O0Ucg==";
            var data = "ondinfoiwinfionweoifn";
            var encryptedData = Rsa.Encrypt(RsaKeyType.Pkcs1, publicKey, data, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine(encryptedData);
            var rawData = Rsa.Decrypt(RsaKeyType.Pkcs1, privateKey, encryptedData, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine(rawData);
        }
    }
}
