using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptorDecryptor1
{
    class User
    {
        public string Email { get; }
        public string publicKey { get; }
        public string privateKey { get; }
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

        public User(string Email)
        {
            this.Email = Email;
            this.publicKey = rsa.ToXmlString(false);
            this.privateKey = rsa.ToXmlString(true);
            //RSAParameters RSAKeyInfo = rsa.ExportParameters(true);
        }

        public string encryptSessionKey(string sessionKey)
        {
            byte[] toEncryptData = Encoding.UTF8.GetBytes(sessionKey);

            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
            rsaPublic.FromXmlString(publicKey);
            byte[] encryptedRSA = rsaPublic.Encrypt(toEncryptData, false);
            //string EncryptedResult = Encoding.Default.GetString(encryptedRSA);
            string EncryptedResult = Convert.ToBase64String(encryptedRSA);

            return EncryptedResult;
        }

        public string decryptSessionKey(string encSessionKey)
        {
            //byte[] toDecryptData = Encoding.UTF8.GetBytes(encSessionKey);
            byte[] toDecryptData = Convert.FromBase64String(encSessionKey);

            RSACryptoServiceProvider rsaPrivate = new RSACryptoServiceProvider();
            rsaPrivate.FromXmlString(privateKey);
            byte[] decryptedRSA = rsaPrivate.Decrypt(toDecryptData, false);
            string originalResult = Encoding.Default.GetString(decryptedRSA);

            return originalResult;
        }
    }
}
