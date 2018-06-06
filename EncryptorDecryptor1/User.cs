using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptorDecryptor1
{
    class User
    {
        public string Email { get; set; }
        public string publicKey { get; set; }
        private string privateKey { get; set; }
        public string password { get; set; }
        private byte[] encPrivateKey;
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

        //constructor for new user
        public User(string Email)
        {
            this.Email = Email;
            this.publicKey = rsa.ToXmlString(false);
            this.privateKey = rsa.ToXmlString(true);
        }

        //constructor for existing user with saved keys in files
        public User(string Email, byte[] encPrivateKey)
        {
            this.Email = Email;
            this.encPrivateKey = encPrivateKey;
        }

        public string encryptSessionKey(string sessionKey)
        {
            byte[] toEncryptData = Encoding.UTF8.GetBytes(sessionKey);

            //encrypt session key with public key
            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
            rsaPublic.FromXmlString(publicKey);
            byte[] encryptedRSA = rsaPublic.Encrypt(toEncryptData, false);
            string EncryptedResult = Convert.ToBase64String(encryptedRSA);

            return EncryptedResult;
        }

        public string decryptSessionKey(string encSessionKey)
        {
            byte[] toDecryptData = Convert.FromBase64String(encSessionKey);

            //decrypt session key with previously decrypted private key
            RSACryptoServiceProvider rsaPrivate = new RSACryptoServiceProvider();
            rsaPrivate.FromXmlString(privateKey);
            byte[] decryptedRSA = rsaPrivate.Decrypt(toDecryptData, false);
            string originalResult = Encoding.Default.GetString(decryptedRSA);

            return originalResult;
        }

        public string computeSha256Hash(string rawPass)
        { 
            //hash user password using SHA-256
            using (SHA256 sha256Hash = SHA256.Create())
            {  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawPass));

                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public void saveKeysToFiles()
        {
            //save keys of a new user to files
            using (FileStream fs = File.Create(MainWindow.publicKeysPath + "\\" + Email + ".txt"))
            {
                Byte[] info = new UTF8Encoding(true).GetBytes(publicKey);
                fs.Write(info, 0, info.Length);
            }
            using (FileStream fs = File.Create(MainWindow.privateKeysPath + "\\" + Email + ".txt"))
            {
                Byte[] privateKeyBytes = new UTF8Encoding(true).GetBytes(privateKey);
                string key = computeSha256Hash(password); //hashed password

                BlowfishEngine engine = new BlowfishEngine();
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine); //ECB
                KeyParameter keyBytes = new KeyParameter(Encoding.UTF8.GetBytes(key));

                cipher.Init(true, keyBytes);
                encPrivateKey = new byte[cipher.GetOutputSize(privateKeyBytes.Length)];
                int len1 = cipher.ProcessBytes(privateKeyBytes, 0, privateKeyBytes.Length, encPrivateKey, 0); //private key encrypted with hashed password
                cipher.DoFinal(encPrivateKey, len1);

                fs.Write(encPrivateKey, 0, encPrivateKey.Length);
            }
        }

        public void decryptPrivateKey(string keyString)
        {
            //decrypt private key with key = user password hashed with SHA-256
            BlowfishEngine engine = new BlowfishEngine();
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
            StringBuilder result = new StringBuilder();

            cipher.Init(false, new KeyParameter(Encoding.UTF8.GetBytes(keyString)));
            byte[] out2 = new byte[cipher.GetOutputSize(encPrivateKey.Length)];
            int len2 = cipher.ProcessBytes(encPrivateKey, 0, encPrivateKey.Length, out2, 0);
            cipher.DoFinal(out2, len2);

            this.privateKey = Encoding.UTF8.GetString(out2);
        }
    }
}
