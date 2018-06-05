using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Xml;

namespace EncryptorDecryptor1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        BackgroundWorker encryptBgw = new BackgroundWorker();
        BackgroundWorker decryptBgw = new BackgroundWorker();
        private string inputFilename;
        private string outputFilename;
        private string outputDir;
        private string fileExt;
        private string algName = "Blowfish";
        private int encryptTypeIndex;
        private readonly string[] encryptTypes = { "ECB", "CBC", "CFB", "OFB" };
        private List<User> allUsers = new List<User>();
        private List<string> allUsersGUI = new List<string>();
        private List<string> senderOrReceivers = new List<string>();
        static readonly Encoding Encoding = Encoding.UTF8;
        private int blockSize = 0;
        private readonly int keyLength = 448;
        private string sessionKey; //do usunięcia po testowaniu

        /*KONSTRUKTOR*/
        public MainWindow()
        {
            InitializeComponent();
            this.Title = "Encryptor/Decryptor 0.1";

            allUsers.Add(new User("adam@wp.pl"));
            allUsers.Add(new User("beata@gmail.com"));
            allUsers.Add(new User("cyryl@onet.pl"));
            foreach (User u in allUsers)
            {
                allUsersGUI.Add(u.Email);
            }
            listView.ItemsSource = allUsersGUI;

            textBoxBlockSize.IsEnabled = false;
        }

        /*OBSLUGA INTERFEJSU*/
        private void buttonNewUser_Click(object sender, RoutedEventArgs e)
        {
            bool suchUserAlreadyExists = false;
            foreach(User u in allUsers)
            {
                if (u.Email == textBoxNewUser.Text)
                {
                    suchUserAlreadyExists = true;
                    break;
                }
            }
            if (!suchUserAlreadyExists)
            {
                User newUser = new User(textBoxNewUser.Text);
                allUsers.Add(newUser);
                allUsersGUI.Add(newUser.Email);
                listView.Items.Refresh();
            }
            else
            {
                MessageBox.Show("Taki użytkownik już istnieje", "Uwaga", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void listView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            foreach (var remItem in e.RemovedItems)
            {
                senderOrReceivers.Remove(remItem.ToString());
            }
            foreach (var addItem in e.AddedItems)
            {
                senderOrReceivers.Add(addItem.ToString());
            }
        }

        private void buttonFilePicker_Click(object sender, RoutedEventArgs e)
        {
            // Create OpenFileDialog 
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            // Set filter for file extension and default file extension 
            //dlg.DefaultExt = ".txt";
            //dlg.Filter = "JPEG Files (*.jpeg)|*.jpeg|PNG Files (*.png)|*.png|JPG Files (*.jpg)|*.jpg|GIF Files (*.gif)|*.gif";

            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox 
            if (result.HasValue && result.Value)
            {
                // Open document 
                inputFilename = dlg.FileName;
                labelPickedFile.Content = inputFilename;
            }
        }

        private void buttonApplyOutputFilename_Click(object sender, RoutedEventArgs e)
        {
            outputFilename = textboxOutputFilename.Text;
            labelOutputFilename.Content = outputFilename;
        }

        private void buttonDirPicker_Click(object sender, RoutedEventArgs e)
        {
            // Create OpenFileDialog 
            System.Windows.Forms.FolderBrowserDialog dlg = new System.Windows.Forms.FolderBrowserDialog();

            // Display OpenFileDialog by calling ShowDialog method 
            System.Windows.Forms.DialogResult result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox 
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                outputDir = dlg.SelectedPath;
                labelPickedDir.Content = outputDir;
            }
        }

        private void comboBoxEncryptType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            encryptTypeIndex = comboBoxEncryptType.SelectedIndex;
            if (encryptTypes[encryptTypeIndex] == "CFB"
                || encryptTypes[encryptTypeIndex] == "OFB")
            {
                textBoxBlockSize.IsEnabled = true;
                label7.Foreground = Brushes.Black;
            }
            else
            {
                textBoxBlockSize.IsEnabled = false;
                label7.Foreground = Brushes.Red;
            }
        }

        private void textBoxBlockSize_TextChanged(object sender, TextChangedEventArgs e)
        {
            TextBox blockSizeTextBox = (TextBox)sender;
            Int32.TryParse(blockSizeTextBox.Text, out blockSize);
        }

        /*ENCRYPTION, DECRYPTION*/
        private void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            encryptBgw.DoWork += new DoWorkEventHandler(bgw_startEncryption);
            encryptBgw.ProgressChanged += new ProgressChangedEventHandler(bgw_progressChanged);
            encryptBgw.WorkerReportsProgress = true;
            encryptBgw.RunWorkerAsync();
        }

        private void buttonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            decryptBgw.DoWork += new DoWorkEventHandler(bgw_startDecryption);
            decryptBgw.ProgressChanged += new ProgressChangedEventHandler(bgw_progressChanged);
            decryptBgw.WorkerReportsProgress = true;
            decryptBgw.RunWorkerAsync();       
        }

        public void bgw_startEncryption(object sender, DoWorkEventArgs e)
        {
            sessionKey = GenerateRandomCryptographicKey(keyLength);
            fileExt = Path.GetExtension(inputFilename);
            byte[] contentBytes;

            using (FileStream fs = File.Open(inputFilename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                contentBytes = new byte[fs.Length];
                byte[] oneByte = new byte[1];

                for (int i = 0; i < fs.Length; i++)
                {
                    encryptBgw.ReportProgress((i * 100) / (int)fs.Length);
                    fs.Read(contentBytes, i, 1);
                }
                encryptBgw.ReportProgress(100);

                //contentBytes += fs.ReadByte();
                //fs.Read(contentBytes, 0, (int)fs.Length);
            }
            string path = outputDir + "\\" + outputFilename + fileExt;
            addXmlHeader(path);
            ByteArrayToFile(path, BlowfishEncrypt(contentBytes, sessionKey));
        }

        public void bgw_startDecryption(object sender, DoWorkEventArgs e)
        {
            fileExt = Path.GetExtension(inputFilename);
            byte[] contentBytes;

            //pobranie parametrow z naglowka xml
            //to do!

            using (FileStream fs = File.Open(inputFilename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                contentBytes = new byte[fs.Length];
                byte[] oneByte = new byte[1];

                for (int i = 0; i < fs.Length; i++)
                {
                    decryptBgw.ReportProgress((i * 100) / (int)fs.Length);
                    fs.Read(contentBytes, i, 1);
                }
                decryptBgw.ReportProgress(100);
            }
            string path = outputDir + "\\" + outputFilename + fileExt;
            ByteArrayToFile(path, BlowfishDecrypt(contentBytes, sessionKey));
        }

        public void bgw_progressChanged(object sender, ProgressChangedEventArgs e)
        {
            progressBar.Value = e.ProgressPercentage;
        }

        public bool ByteArrayToFile(string fileName, byte[] byteArray)
        {
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Append, FileAccess.Write))
                {
                    int i = byteArray.Length - 1;
                    while (byteArray[i] == 0) --i;

                    byte[] cleanByteArray = new byte[i + 1];
                    Array.Copy(byteArray, cleanByteArray, i + 1);

                    fs.Write(cleanByteArray, 0, cleanByteArray.Length);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                return false;
            }
        }

        //private void saveToFile(string path, string szyfrogram)
        //{
        //    try
        //    {
        //        // Delete the file if it exists.
        //        if (File.Exists(path))
        //        {
        //            File.Delete(path);
        //        }

        //        // Create the file.
        //        using (FileStream fs = File.Create(path))
        //        {
        //            Byte[] info = new UTF8Encoding(true).GetBytes(szyfrogram);
        //            // Add some information to the file.
        //            fs.Write(info, 0, info.Length);
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine(ex.ToString());
        //    }
        //}

        public byte[] BlowfishEncrypt(byte[] contentBytes, string key)
        {
            try
            {
                BlowfishEngine engine = new BlowfishEngine();
                PaddedBufferedBlockCipher cipher = null;
                switch (encryptTypes[encryptTypeIndex])
                {
                    case "ECB":
                        cipher = new PaddedBufferedBlockCipher(engine);
                        break;
                    case "CBC":
                        cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
                        break;
                    case "CFB":
                        cipher = new PaddedBufferedBlockCipher(new CfbBlockCipher(engine, blockSize));
                        break;
                    case "OFB":
                        cipher = new PaddedBufferedBlockCipher(new OfbBlockCipher(engine, blockSize));
                        break;
                }

                KeyParameter keyBytes = new KeyParameter(Encoding.GetBytes(key));

                cipher.Init(true, keyBytes);

                byte[] outB = new byte[cipher.GetOutputSize(contentBytes.Length)];

                int len1 = cipher.ProcessBytes(contentBytes, 0, contentBytes.Length, outB, 0);

                cipher.DoFinal(outB, len1);

                return outB;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public byte[] BlowfishDecrypt(byte[] contentBytes, string keyString)
        {
            BlowfishEngine engine = new BlowfishEngine();
            PaddedBufferedBlockCipher cipher = null;
            switch (encryptTypes[encryptTypeIndex])
            {
                case "ECB":
                    cipher = new PaddedBufferedBlockCipher(engine);
                    break;
                case "CBC":
                    cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
                    break;
                case "CFB":
                    cipher = new PaddedBufferedBlockCipher(new CfbBlockCipher(engine, blockSize));
                    break;
                case "OFB":
                    cipher = new PaddedBufferedBlockCipher(new OfbBlockCipher(engine, blockSize));
                    break;
            }

            StringBuilder result = new StringBuilder();

            cipher.Init(false, new KeyParameter(Encoding.GetBytes(keyString)));

            //byte[] out1 = Hex.Decode(contentBytes);
            byte[] out2 = new byte[cipher.GetOutputSize(contentBytes.Length)]; //tu bylo wczesniej bez dzielenia na 2

            int len2 = cipher.ProcessBytes(contentBytes, 0, contentBytes.Length, out2, 0);

            cipher.DoFinal(out2, len2); //Pad block corrupted error happens here

            //String s2 = BitConverter.ToString(out2);

            //for (int i = 0; i < s2.Length; i++)
            //{
            //    char c = s2[i];
                
            //    if (c != 0)
            //    {
            //        result.Append(c.ToString());
            //    }
            //}

            //string resultStr = HexStringToString(result.ToString());
            return out2;
        }

        //public string HexStringToString(string hexString)
        //{
        //    if (hexString == null)
        //    {
        //        throw new ArgumentException();
        //    }
        //    var sb = new StringBuilder();
        //    for (var i = 0; i < hexString.Length; i += 3)
        //    {
        //        var hexChar = hexString.Substring(i, 2);
        //        sb.Append((char)Convert.ToByte(hexChar, 16));
        //    }
        //    return sb.ToString();
        //}

        public XmlDocument addXmlHeader(string path)
        {
            XmlDocument doc = new XmlDocument();

            XmlNode declaration = doc.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            doc.AppendChild(declaration);

            XmlElement header = (XmlElement)doc.AppendChild(doc.CreateElement("EncryptedFileHeader"));

            XmlElement xmlAlgorithm = (XmlElement)header.AppendChild(doc.CreateElement("Algorithm"));
            xmlAlgorithm.InnerText = algName;

            XmlElement xmlKeySize = (XmlElement)header.AppendChild(doc.CreateElement("KeySize"));
            xmlKeySize.InnerText = keyLength.ToString();

            XmlElement xmlBlockSize = (XmlElement)header.AppendChild(doc.CreateElement("BlockSize"));
            xmlBlockSize.InnerText = blockSize.ToString();

            XmlElement xmlCipherMode = (XmlElement)header.AppendChild(doc.CreateElement("CipherMode"));
            xmlCipherMode.InnerText = encryptTypes[encryptTypeIndex];

            XmlElement xmlApprovedUsers = (XmlElement)header.AppendChild(doc.CreateElement("ApprovedUsers"));
            foreach (var userName in senderOrReceivers)
            {
                User user = null;
                foreach (var u in allUsers)
                {
                    if (u.Email.Equals(userName)) user = u;
                }

                XmlElement xmlUser = (XmlElement)xmlApprovedUsers.AppendChild(doc.CreateElement("User"));
                XmlElement xmlUserEmail = (XmlElement)xmlUser.AppendChild(doc.CreateElement("Email"));
                xmlUserEmail.InnerText = user.Email;
                XmlElement xmlUserSessionKey = (XmlElement)xmlUser.AppendChild(doc.CreateElement("SessionKey"));
                xmlUserSessionKey.InnerText = user.encryptSessionKey(sessionKey);
                user.decryptSessionKey(xmlUserSessionKey.InnerText);
            }

            doc.Save(path);
            return doc;
        }

        public string GenerateRandomCryptographicKey(int keyLengthInBits)
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLengthInBits/8];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            rngCryptoServiceProvider.Dispose();
            return Convert.ToBase64String(randomBytes);
        }

        //public static string Utf16ToUtf8(string utf16String)
        //{
        //    // Get UTF16 bytes and convert UTF16 bytes to UTF8 bytes
        //    byte[] utf16Bytes = Encoding.Unicode.GetBytes(utf16String);
        //    byte[] utf8Bytes = Encoding.Convert(Encoding.Unicode, Encoding.UTF8, utf16Bytes);

        //    // Return UTF8 bytes as ANSI string
        //    return Encoding.Default.GetString(utf8Bytes);
        //}

        //public string BlowfishEncryption(string plain, string key, bool fips)
        //{
        //    BCEngine bcEngine = new BCEngine(new BlowfishEngine(), new CBC);
        //    bcEngine.SetPadding(_padding);
        //    return bcEngine.Encrypt(plain, key);
        //}

        //public string BlowfishDecryption(string cipher, string key, bool fips)
        //{
        //    BCEngine bcEngine = new BCEngine(new BlowfishEngine(), _encoding);
        //    bcEngine.SetPadding(_padding);
        //    return bcEngine.Decrypt(cipher, key);
        //}
    }
}
