using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace EncryptorDecryptor1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string inputFilename;
        private string outputFilename;
        private string outputDir;
        private int encryptTypeIndex;
        private readonly string[] encryptTypes = { "ECB", "CBC", "CFB", "OFB" };
        private List<string> senderOrReceivers = new List<string>();
        static readonly Encoding Encoding = Encoding.UTF8;
        private int blockSize = 0;

        public MainWindow()
        {
            InitializeComponent();
            this.Title = "Encryptor/Decryptor 0.1";
            List<string> items = new List<string>();
            items.Add("Adam");
            items.Add("Beata");
            items.Add("Cyryl");
            listView.ItemsSource = items;
            textBoxBlockSize.IsEnabled = false;
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

        private void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            string szyfrogram = BlowfishEncrypt("test", "abc");
            string path = outputDir + "\\" + outputFilename;
            saveToFile(path, szyfrogram);
        }

        private void buttonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            string szyfrogram = "";
            using (StreamReader sr = File.OpenText(inputFilename))
            {
                string s = "";
                while ((s = sr.ReadLine()) != null)
                {
                    szyfrogram += s;
                }
            }
            string path = outputDir + "\\" + outputFilename;
            saveToFile(path, BlowfishDecrypt(szyfrogram, "abc"));            
        }

        private void saveToFile(string path, string szyfrogram)
        {
            try
            {
                // Delete the file if it exists.
                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                // Create the file.
                using (FileStream fs = File.Create(path))
                {
                    Byte[] info = new UTF8Encoding(true).GetBytes(szyfrogram);
                    // Add some information to the file.
                    fs.Write(info, 0, info.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        public string BlowfishEncrypt(string strValue, string key)
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

                byte[] inB = Encoding.GetBytes(strValue);

                byte[] outB = new byte[cipher.GetOutputSize(inB.Length)];

                int len1 = cipher.ProcessBytes(inB, 0, inB.Length, outB, 0);

                cipher.DoFinal(outB, len1);

                return BitConverter.ToString(outB).Replace("-", "");
            }
            catch (Exception)
            {
                return "";
            }
        }

        public string BlowfishDecrypt(string name, string keyString)
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

            byte[] out1 = Hex.Decode(name);
            byte[] out2 = new byte[cipher.GetOutputSize(out1.Length)/2]; //tu bylo wczesniej bez dzielenia na 2

            int len2 = cipher.ProcessBytes(out1, 0, out1.Length, out2, 0);

            cipher.DoFinal(out2, len2); //Pad block corrupted error happens here

            String s2 = BitConverter.ToString(out2);

            for (int i = 0; i < s2.Length; i++)
            {
                char c = s2[i];
                
                if (c != 0)
                {
                    result.Append(c.ToString());
                }
            }

            return HexStringToString(result.ToString());

        }

        string HexStringToString(string hexString)
        {
            if (hexString == null)
            {
                throw new ArgumentException();
            }
            var sb = new StringBuilder();
            for (var i = 0; i < hexString.Length; i += 3)
            {
                var hexChar = hexString.Substring(i, 2);
                sb.Append((char)Convert.ToByte(hexChar, 16));
            }
            return sb.ToString();
        }

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
