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
            byte[] toEncryptData = Encoding.ASCII.GetBytes(sessionKey);

            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
            rsaPublic.FromXmlString(publicKey);
            byte[] encryptedRSA = rsaPublic.Encrypt(toEncryptData, false);
            string EncryptedResult = Encoding.Default.GetString(encryptedRSA);

            return EncryptedResult;
        }
    }
}
