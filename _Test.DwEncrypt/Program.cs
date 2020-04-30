using System;
using System.Security.Cryptography;

using DwEncrypt;

namespace _Test.DwEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            var publicKey = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwjpMOdG80cYeoKmR1Eb8BnZ9ir37luB4OATNfkRfdhPMtjk5g1g0kHriiNjH4FPaCnfwW/HKNRg+iP95unoUgTEf1iS3LN9Ywk5ZwOyFB/c7zNHhv9DVM285Infy7j4m5oZlzwIOCQdbvPojoxPYR61nq1mq4zvJM06YqMIA7gz+fNd3M3V5xROf2udlCenqW8hEZ/CavPoGnhN4sPtYP2aVxo1FdcK7VaXdayLu/P86Y8BI6NaIW7trLEctmG18nUoM9UoCR1W4qK6hNYTLgz59cCm4ymRWtKMYrL52eBfkeh2EyIBH6zyF2HQxHHX6Qnlz4NCAB9y4dwvKzKbftwIDAQAB";
            var privateKey = @"MIIEogIBAAKCAQEAwjpMOdG80cYeoKmR1Eb8BnZ9ir37luB4OATNfkRfdhPMtjk5g1g0kHriiNjH4FPaCnfwW/HKNRg+iP95unoUgTEf1iS3LN9Ywk5ZwOyFB/c7zNHhv9DVM285Infy7j4m5oZlzwIOCQdbvPojoxPYR61nq1mq4zvJM06YqMIA7gz+fNd3M3V5xROf2udlCenqW8hEZ/CavPoGnhN4sPtYP2aVxo1FdcK7VaXdayLu/P86Y8BI6NaIW7trLEctmG18nUoM9UoCR1W4qK6hNYTLgz59cCm4ymRWtKMYrL52eBfkeh2EyIBH6zyF2HQxHHX6Qnlz4NCAB9y4dwvKzKbftwIDAQABAoIBACrmbIrC2FVvULmE6sh761PUHTOldeoj53ncGbV/jaRLiEZhimIH/AhDlEDMvQ1ACCOSzVzJobOriLiC0VTOfTPx8Um/71Oye2zjmHCD7XhOc/9wBlBzZHwJX5HM87QKt1XorpkUJ5x36xvpFjEBg56FXyYaVqP9QxoZjJ+Nxl3Nz0j4OLrhuUSZWVYRfYr7gDllvsQ0gMJ4moOR+MR06fGKaQzkzx+RwB4ck5hPRkJlkTj9Ifwc7JBOblN/s7jSUm1wukXCNw9r157rfxGdXjbpHAHuUn1dCKp05F0NPk5NBK2xWKToAC2yJmLxgQypWW9oo3acPAZBK59ZuQ3X32kCgYEA6+GrTSMJ7RIOHmNHxBYZhZLXGYzO+TThu58Pvcf4IOoHjq/AIasoKYDkk2Wp7nZj1fzS0iY++wteEg9/2YVRMzDpXdBWrPl1YHzFQqydBA5D06odUHNpv0wFo6k9fJtWJxdtPfGOKs+tXyiK/vY0mL88TBl+IJs1BUXssArqp18CgYEA0sskosNHWsBBtzRsZKWXnvq53QQe3ShAz0b78VZUW2Bdc72b91ndIgUO7oVbCJQM+y8QJQ9GqE5bg+3eV3O7ZRQAsdv26urXfgfU/w0ccr/cXH09+u2KSDBJgmJz9lwi8jB4r8c9Jl8DVOWEKUuOEggNZi9MK/hPfTU35E2m3qkCgYEAi45KgSq31rEV9VibvyGsG+ESriUm1z44R38GGyxSW3ba3cqRi9ntuxBtK9+8OD+HNbWNLZQ/Mtw43cqZw6Iitny7tStr/I7iqSFou9fQVfPyoSpGibCe4fUiaP/aRvzIbfxoP3vItv+D/YbJJauY1r5d+FAk1Tm+ls4WCNmMl1UCf25V5tdLYA4glEVRK2uDQdn1Y1RM09rvNv1IKpgol/88ca4jkX/nidhEzYwMQZo75I+WEt1TIaj3Wu+zkq4z5eMClVqDyLsuMZ3Ge7cFJd7qjm3bIJY3wCoJHHEjF4/cqm4a8REROPDcyuGlQYhcBAFsNZdHKpfZYcIoGRlni/ECgYEA0d8GeA0iIHsqILpmgCnoF1SDCOrNwHiolhzZl0VQ5H9kkfKFNtLIx0KKLffcBInNIrYVm0FRZ7i5rssTJVI996LPCA19QCOxtdIywrA8TMu6c9hx4k+k8rxDHlYEdV/eHitjdGOa0uF2CbyHQqtTicNzNwJ/bY2pN3TAIRdEPEU=";
            var data = "ondinfoiwinfionweoifn";
            var encryptedData = Rsa.Encrypt(RsaKeyType.Pkcs1, publicKey, data, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine(encryptedData);
            var rawData = Rsa.Decrypt(RsaKeyType.Pkcs1, privateKey, encryptedData, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine(rawData);
        }
    }
}
