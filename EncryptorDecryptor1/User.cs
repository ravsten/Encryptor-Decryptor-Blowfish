using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptorDecryptor1
{
    class User
    {
        public string Email { get; set; }
        public string publicKey { get; set; }
        public string privateKey { get; set; }
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

        public User(string Email)
        {
            this.Email = Email;
            this.publicKey = rsa.ToXmlString(false);
            this.privateKey = rsa.ToXmlString(true);

            //zapisz klucze nowego uzytkownika na dysku
            using (FileStream fs = File.Create(MainWindow.publicKeysPath + "\\" + Email + ".txt"))
            {
                Byte[] info = new UTF8Encoding(true).GetBytes(publicKey);
                fs.Write(info, 0, info.Length);
            }
            using (FileStream fs = File.Create(MainWindow.privateKeysPath + "\\" + Email + ".txt"))
            {
                Byte[] info = new UTF8Encoding(true).GetBytes(privateKey);
                fs.Write(info, 0, info.Length);
            }
        }

        public User(string Email, string publicKey)
        {
            this.Email = Email;
            this.publicKey = publicKey;
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
