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

            //set startup parameters for GUI elements
            listView.ItemsSource = allUsersGUI;
            textBoxBlockSize.IsEnabled = false;
            buttonBlockSize.IsEnabled = false;
        }

        /*USER INTERFACE INTERACTION*/
        private void buttonNewUser_Click(object sender, RoutedEventArgs e)
        {
            //if Email or password box was not filled
            if (textBoxNewUser.Text == "" || textBoxPassword.Text == "")
            {
                MessageBox.Show("Podaj email i hasło!",
                    "Uwaga",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                //check if user with this Email already exists
                bool suchUserAlreadyExists = false;
                foreach (User u in allUsers)
                {
                    if (u.Email == textBoxNewUser.Text)
                    {
                        suchUserAlreadyExists = true;
                        break;
                    }
                }
                //if there was no such Email yet
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
                //if there is a user with such email
                else
                {
                    MessageBox.Show("Taki użytkownik już istnieje", "Uwaga", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private void listView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            //add selected users to senderOrReceivers list
            foreach (var remItem in e.RemovedItems)
            {
                senderOrReceivers.Remove(remItem.ToString());
            }
            //remove unselected users from senderOrReceivers list
            foreach (var addItem in e.AddedItems)
            {
                senderOrReceivers.Add(addItem.ToString());
            }
        }

        private void buttonFilePicker_Click(object sender, RoutedEventArgs e)
        {
            //create file dialog 
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            Nullable<bool> result = dlg.ShowDialog();

            //if a file was selected
            if (result.HasValue && result.Value)
            {
                //assign filename to global var
                inputFilename = dlg.FileName;
                labelPickedFile.Content = inputFilename;
            }
        }

        private void buttonApplyOutputFilename_Click(object sender, RoutedEventArgs e)
        {
            //set outputFilename var to text from textbox
            outputFilename = textboxOutputFilename.Text;
            labelOutputFilename.Content = outputFilename;
        }

        private void buttonDirPicker_Click(object sender, RoutedEventArgs e)
        {
            //create folder dialog
            System.Windows.Forms.FolderBrowserDialog dlg = new System.Windows.Forms.FolderBrowserDialog();
            System.Windows.Forms.DialogResult result = dlg.ShowDialog();

            //if a folder=directory was selected 
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                //assign directory to global var
                outputDir = dlg.SelectedPath;
                labelPickedDir.Content = outputDir;
            }
        }

        private void comboBoxEncryptType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            //get index of option from a list
            encryptTypeIndex = comboBoxEncryptType.SelectedIndex;

            //if a user chose CFB or OFB cipher block
            if (encryptTypes[encryptTypeIndex] == "CFB"
                || encryptTypes[encryptTypeIndex] == "OFB")
            {
                //let user input custom block size
                textBoxBlockSize.IsEnabled = true;
                buttonBlockSize.IsEnabled = true;
                label7.Foreground = Brushes.Black;
            }
            else
            {
                //block block size textbox
                textBoxBlockSize.IsEnabled = false;
                buttonBlockSize.IsEnabled = false;
                label7.Foreground = Brushes.Red;
            }
        }

        private void buttonBlockSize_Click(object sender, RoutedEventArgs e)
        {
            //get block size from textbox
            ulong inputBlockSize;
            ulong.TryParse(textBoxBlockSize.Text, out inputBlockSize);

            //check if block size is not bigger than maximum default block size
            if (inputBlockSize > maxBlockSize)
            {
                MessageBox.Show("Wielkość bloku nie może przekraczać 64 bitów!",
                    "Uwaga",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                textBoxBlockSize.Clear();
            }
            //check if block size is power of 2 or multiple of 8 
            else if (!(isPowerOfTwo(inputBlockSize) || inputBlockSize % 8 == 0))
            {
                MessageBox.Show("Podana wielkość bloku nie jest potęgą liczby 2,\nani wielokrotnością bajtu!",
                    "Uwaga",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                textBoxBlockSize.Clear();
            }
            //if everything is fine
            else blockSize = (int)inputBlockSize;
        }

        private bool isPowerOfTwo(ulong x)
        {
            return (x != 0) && ((x & (x - 1)) == 0);
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

        /*ENCRYPTION, DECRYPTION*/
        private void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            //setup background worker
            encryptBgw.DoWork += new DoWorkEventHandler(bgw_startEncryption);
            encryptBgw.ProgressChanged += new ProgressChangedEventHandler(bgw_progressChanged);
            encryptBgw.WorkerReportsProgress = true;
            encryptBgw.RunWorkerAsync();
        }

        private void buttonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            //setup background worker
            decryptBgw.DoWork += new DoWorkEventHandler(bgw_startDecryption);
            decryptBgw.ProgressChanged += new ProgressChangedEventHandler(bgw_progressChanged);
            decryptBgw.WorkerReportsProgress = true;
            decryptBgw.RunWorkerAsync();       
        }

        public void bgw_startEncryption(object sender, DoWorkEventArgs e)
        {
            //set progress bar to 0%
            encryptBgw.ReportProgress(0);
            //generate session key for encryption
            sessionKey = GenerateRandomCryptographicKey(keySize);
            //get file extension from input filename
            fileExt = Path.GetExtension(inputFilename);
            //byte table for content to encrypt
            byte[] contentBytes;
            //open file you want to encrypt
            using (FileStream fs = File.Open(inputFilename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                contentBytes = new byte[fs.Length];
                byte[] oneByte = new byte[1];
                //read byte by byte
                for (int i = 0; i < fs.Length; i++)
                {
                    encryptBgw.ReportProgress((i * 100) / (int)fs.Length);
                    fs.Read(contentBytes, i, 1);
                }
                //reading from file finished
                encryptBgw.ReportProgress(100);
            }
            //create path for output file
            string path = outputDir + "\\" + outputFilename + fileExt;
            //encrypt data using Blowfish
            byte[] encryptedData = BlowfishEncrypt(contentBytes, sessionKey);
            //save output file with XML header
            saveWithXmlHeader(path, Convert.ToBase64String(encryptedData));
        }

        public void bgw_startDecryption(object sender, DoWorkEventArgs e)
        {
            //set progress bar to 0%
            decryptBgw.ReportProgress(0);
            try
            {
                //get file extension from input filename
                fileExt = Path.GetExtension(inputFilename);

                //get decryption parameters from XML header
                XElement header = XElement.Load(inputFilename);
                Int32.TryParse(header.Element("KeySize").Value, out keySize);
                Int32.TryParse(header.Element("BlockSize").Value, out blockSize);
                string cipherMode = header.Element("CipherMode").Value;
                XElement approvedUsers = header.Element("ApprovedUsers");

                decryptBgw.ReportProgress(25);

                //check if logged user is approved to decrypt file
                bool isCurrentUserApproved = false;
                foreach (var u in approvedUsers.Elements("User"))
                {
                    string userEmail = u.Element("Email").Value;
                    //if logged user is approved
                    if (userEmail == senderOrReceivers[0])
                    {
                        decryptBgw.ReportProgress(50);

                        isCurrentUserApproved = true;
                        //get his encrypted session key from XML header
                        string userEncSessKey = u.Element("SessionKey").Value;
                        User currUser = allUsers.Find(user => user.Email.Equals(userEmail));
                        //decrypt private key using given password
                        currUser.decryptPrivateKey(currUser.computeSha256Hash(passwordBox.Password));
                        //decrypt session key using decrypted private key
                        sessionKey = currUser.decryptSessionKey(userEncSessKey);
                        break;
                    }
                }
                //user is not approved to decrypt this file
                if (!isCurrentUserApproved)
                {
                    decryptBgw.ReportProgress(100);
                    return;
                }

                decryptBgw.ReportProgress(75);

                //get encrypted data for decryption
                string encryptedData = header.Element("EncryptedData").Value;
                byte[] dataToDecrypt = Convert.FromBase64String(encryptedData);
                //create path for output file
                string path = outputDir + "\\" + outputFilename + fileExt;
                //decrypt file using decrypted session key
                ByteArrayToFile(path, BlowfishDecrypt(dataToDecrypt, sessionKey, cipherMode));
                //decryption finished
                decryptBgw.ReportProgress(100);
            }
            catch
            {
                decryptBgw.ReportProgress(0);
            }
        }

        public void bgw_progressChanged(object sender, ProgressChangedEventArgs e)
        {
            //update progress bar
            progressBar.Value = e.ProgressPercentage;
        }

        public bool ByteArrayToFile(string fileName, byte[] byteArray)
        {
            //save decrypted data to file
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Append, FileAccess.Write))
                {
                    //remove trailing nulls
                    int i = byteArray.Length - 1;
                    while (byteArray[i] == 0) --i;
                    //clean byte array from trailing nulls
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

        public byte[] BlowfishEncrypt(byte[] contentBytes, string key)
        {
            try
            {
                //create blowfish engine
                BlowfishEngine engine = new BlowfishEngine();
                //create block cipher based on user choice
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
                //create key
                KeyParameter keyBytes = new KeyParameter(Encoding.GetBytes(key));
                cipher.Init(true, keyBytes);

                //create byte array for encrypted data
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
            //create blowfish engine
            BlowfishEngine engine = new BlowfishEngine();
            //create block cipher based on user choice
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

            byte[] out2 = new byte[cipher.GetOutputSize(contentBytes.Length)];
            int len2 = cipher.ProcessBytes(contentBytes, 0, contentBytes.Length, out2, 0);
            cipher.DoFinal(out2, len2);

            return out2;
        }

        public void saveWithXmlHeader(string path, string encData)
        {
            //create XML header
            XmlDocument doc = new XmlDocument();

            //add declaration
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
                //add session key encrypted with specific user's public key
                xmlUserSessionKey.InnerText = user.encryptSessionKey(sessionKey);
            }
            //add encrypted data
            XmlElement xmlEncData = (XmlElement)header.AppendChild(doc.CreateElement("EncryptedData"));
            xmlEncData.InnerText = encData;

            doc.Save(path);
        }

        public string GenerateRandomCryptographicKey(int keyLengthInBits)
        {
            //generate trully random session key
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLengthInBits/8];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            rngCryptoServiceProvider.Dispose();
            return Convert.ToBase64String(randomBytes);
        }
    }
}
