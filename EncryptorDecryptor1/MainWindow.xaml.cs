using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Xml;
using System.Xml.Linq;

namespace EncryptorDecryptor1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        BackgroundWorker encryptBgw = new BackgroundWorker();
        BackgroundWorker decryptBgw = new BackgroundWorker();

        public static readonly string publicKeysPath = "C:\\Users\\r_ste_000\\Documents\\PG_6sem\\bsk\\EncryptorDecryptor1\\public-keys";
        public static readonly string privateKeysPath = "C:\\Users\\r_ste_000\\Documents\\PG_6sem\\bsk\\EncryptorDecryptor1\\private-keys";

        string inputFilename, fileExt; //input file vars
        string outputFilename, outputDir; //output file vars

        string algName = "Blowfish";
        int encryptTypeIndex; //index of encrypt type (cipher block) from GUI list
        readonly string[] encryptTypes = { "ECB", "CBC", "CFB", "OFB" }; //cipher block options

        List<User> allUsers = new List<User>(); //list of users of application
        List<string> allUsersGUI = new List<string>(); //GUI list representing users
        List<string> senderOrReceivers = new List<string>(); //list of selected users from GUI list

        static readonly Encoding Encoding = Encoding.UTF8; //default encoding
        const int maxBlockSize = 64;
        int blockSize = 0; //set only for CFB, OFB, defult value of 64 bits for others
        int keySize = 448;
        string sessionKey;

        /*CONSTRUCTOR*/
        public MainWindow()
        {
            InitializeComponent();
            this.Title = "Encryptor/Decryptor 0.1";

            loadUsers();

            //allUsers.Add(new User("adam@wp.pl"));
            //allUsers.Add(new User("beata@gmail.com"));
            //allUsers.Add(new User("cyryl@onet.pl"));
            //foreach (User u in allUsers)
            //{
            //    allUsersGUI.Add(u.Email);
            //}
            listView.ItemsSource = allUsersGUI;

            textBoxBlockSize.IsEnabled = false;
            buttonBlockSize.IsEnabled = false;
        }

        /*USER INTERFACE INTERACTION*/
        private void buttonNewUser_Click(object sender, RoutedEventArgs e)
        {
            if (textBoxNewUser.Text == "" || textBoxPassword.Text == "")
            {
                MessageBox.Show("Podaj email i hasło!",
                    "Uwaga",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                bool suchUserAlreadyExists = false;
                foreach (User u in allUsers)
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
                    newUser.password = textBoxPassword.Text;
                    newUser.saveKeysToFiles();

                    allUsers.Add(newUser);
                    allUsersGUI.Add(newUser.Email);
                    listView.Items.Refresh();
                    textBoxNewUser.Clear();
                    textBoxPassword.Clear();
                }
                else
                {
                    MessageBox.Show("Taki użytkownik już istnieje", "Uwaga", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
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
                buttonBlockSize.IsEnabled = true;
                label7.Foreground = Brushes.Black;
            }
            else
            {
                textBoxBlockSize.IsEnabled = false;
                buttonBlockSize.IsEnabled = false;
                label7.Foreground = Brushes.Red;
            }
        }

        private void buttonBlockSize_Click(object sender, RoutedEventArgs e)
        {
            ulong inputBlockSize;
            ulong.TryParse(textBoxBlockSize.Text, out inputBlockSize);
            if (inputBlockSize > maxBlockSize)
            {
                MessageBox.Show("Wielkość bloku nie może przekraczać 64 bitów!",
                    "Uwaga",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                textBoxBlockSize.Clear();
            }
            else if (!(isPowerOfTwo(inputBlockSize) || inputBlockSize % 8 == 0))
            {
                MessageBox.Show("Podana wielkość bloku nie jest potęgą liczby 2,\nani wielokrotnością bajtu!",
                    "Uwaga",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                textBoxBlockSize.Clear();
            }
            else blockSize = (int)inputBlockSize;
        }

        private bool isPowerOfTwo(ulong x)
        {
            return (x != 0) && ((x & (x - 1)) == 0);
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
            encryptBgw.ReportProgress(0);
            sessionKey = GenerateRandomCryptographicKey(keySize);
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

            byte[] encryptedData = BlowfishEncrypt(contentBytes, sessionKey);
            saveWithXmlHeader(path, Convert.ToBase64String(encryptedData));
            //ByteArrayToFile(path, BlowfishEncrypt(contentBytes, sessionKey), true);
        }

        public void bgw_startDecryption(object sender, DoWorkEventArgs e)
        {
            decryptBgw.ReportProgress(0);
            fileExt = Path.GetExtension(inputFilename);
            //byte[] contentBytes;

            //pobranie parametrow z naglowka xml
            XElement header = XElement.Load(inputFilename);
            Int32.TryParse(header.Element("KeySize").Value, out keySize);
            Int32.TryParse(header.Element("BlockSize").Value, out blockSize);
            string cipherMode = header.Element("CipherMode").Value;
            XElement approvedUsers = header.Element("ApprovedUsers");

            decryptBgw.ReportProgress(25);

            bool isCurrentUserApproved = false;
            foreach (var u in approvedUsers.Elements("User"))
            {
                string userEmail = u.Element("Email").Value;
                if (userEmail == senderOrReceivers[0])
                {
                    decryptBgw.ReportProgress(50);

                    isCurrentUserApproved = true;
                    string userEncSessKey = u.Element("SessionKey").Value;
                    User currUser = allUsers.Find(user => user.Email.Equals(userEmail));
                    currUser.decryptPrivateKey(currUser.computeSha256Hash(passwordBox.Password));
                    sessionKey = currUser.decryptSessionKey(userEncSessKey);
                    break;
                }
            }
            if (!isCurrentUserApproved)
            {
                decryptBgw.ReportProgress(100);
                return; //uzytkownik nie jest uprawniony do odszyfrowania tego pliku
            }

            decryptBgw.ReportProgress(75);

            string encryptedData = header.Element("EncryptedData").Value;
            byte[] dataToDecrypt = Convert.FromBase64String(encryptedData);

            //using (FileStream fs = File.Open(inputFilename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            //{
            //    contentBytes = new byte[fs.Length];
            //    byte[] oneByte = new byte[1];

            //    for (int i = 0; i < fs.Length; i++)
            //    {
            //        decryptBgw.ReportProgress((i * 100) / (int)fs.Length);
            //        fs.Read(contentBytes, i, 1);
            //    }
            //    decryptBgw.ReportProgress(100);
            //}
            string path = outputDir + "\\" + outputFilename + fileExt;
            ByteArrayToFile(path, BlowfishDecrypt(dataToDecrypt, sessionKey, cipherMode), false);

            decryptBgw.ReportProgress(100);
        }

        public void bgw_progressChanged(object sender, ProgressChangedEventArgs e)
        {
            progressBar.Value = e.ProgressPercentage;
        }

        public bool ByteArrayToFile(string fileName, byte[] byteArray, bool isHeaderAppended)
        {
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Append, FileAccess.Write))
                {
                    int i = byteArray.Length - 1;
                    while (byteArray[i] == 0) --i;

                    byte[] cleanByteArray = new byte[i + 1];
                    Array.Copy(byteArray, cleanByteArray, i + 1);

                    if (isHeaderAppended)
                    {
                        byte[] newline = Encoding.UTF8.GetBytes(Environment.NewLine);
                        fs.Write(newline, 0, newline.Length);
                        //XmlDocument doc = new XmlDocument();
                        //XmlElement encData = (XmlElement)doc.AppendChild(doc.CreateElement("EncryptedData"));
                        //encData.InnerText = cleanByteArray;
                        byte[] encDataOpening = Encoding.UTF8.GetBytes("<EncryptedData>");
                        fs.Write(encDataOpening, 0, encDataOpening.Length);

                        fs.Write(cleanByteArray, 0, cleanByteArray.Length);

                        byte[] encDataClosing = Encoding.UTF8.GetBytes("</EncryptedData>");
                        fs.Write(encDataClosing, 0, encDataClosing.Length);
                    }
                    else
                    {
                        fs.Write(cleanByteArray, 0, cleanByteArray.Length);
                    }
                    
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                return false;
            }
        }

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

        public byte[] BlowfishDecrypt(byte[] contentBytes, string keyString, string cipherMode)
        {
            BlowfishEngine engine = new BlowfishEngine();
            PaddedBufferedBlockCipher cipher = null;
            switch (cipherMode)
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

        public XmlDocument saveWithXmlHeader(string path, string encData)
        {
            XmlDocument doc = new XmlDocument();

            XmlNode declaration = doc.CreateXmlDeclaration("1.0", "UTF-8", "yes");
            doc.AppendChild(declaration);

            XmlElement header = (XmlElement)doc.AppendChild(doc.CreateElement("EncryptedFileHeader"));

            XmlElement xmlAlgorithm = (XmlElement)header.AppendChild(doc.CreateElement("Algorithm"));
            xmlAlgorithm.InnerText = algName;

            XmlElement xmlKeySize = (XmlElement)header.AppendChild(doc.CreateElement("KeySize"));
            xmlKeySize.InnerText = keySize.ToString();

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
                //user.decryptSessionKey(xmlUserSessionKey.InnerText);
            }

            XmlElement xmlEncData = (XmlElement)header.AppendChild(doc.CreateElement("EncryptedData"));
            xmlEncData.InnerText = encData; // Encoding.GetString(encData);

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

        public void loadUsers()
        {
            foreach (string file in Directory.EnumerateFiles(privateKeysPath, "*.txt"))
            {
                User newUser = new User(Path.GetFileNameWithoutExtension(file), File.ReadAllBytes(file));
                allUsers.Add(newUser);
                allUsersGUI.Add(newUser.Email);
                listView.Items.Refresh();
            }
            foreach (string file in Directory.EnumerateFiles(publicKeysPath, "*.txt"))
            {
                User foundUser = allUsers.Find(user => user.Email.Equals(Path.GetFileNameWithoutExtension(file)));
                foundUser.publicKey = File.ReadAllText(file);
            }
        }
    }
}
