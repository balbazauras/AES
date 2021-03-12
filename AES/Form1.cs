using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AES
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            aes = new AES();
        }
        AES aes;

        private void decryptButton_Click(object sender, EventArgs e)
        {
            try
            {
                    decypherResult.Text = aes.Decrypt(File.ReadAllText(filePathLabel.Text), keyTextBox.Text, GetMode());
                    MessageBox.Show("Decrypted!");
            }
            catch(Exception exp)
            {
                MessageBox.Show(exp.Message);
            }
        }

        private void encryptButton_Click(object sender, EventArgs e)
        {
            try
            {
                String filePath = String.Format(@"C:\Users\whis\Desktop\Informacijos saugumas\2pd\{0}.txt", newFileNameTexBox.Text);
                string encrypted = aes.Encrypt(encypherTexBox.Text, keyTextBox.Text, GetMode());
                File.WriteAllText(filePath, encrypted);
                MessageBox.Show("Encrypted!");
            }
             catch (Exception exp)
            {
                MessageBox.Show(exp.Message);
            }
        }

        private void fileSelectButton_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.Cancel) return;

            FileStream fs = new FileStream(openFileDialog1.FileName, FileMode.Open);
            StreamReader sr = new StreamReader(fs);

            filePathLabel.Text = openFileDialog1.FileName;

            textInFileLabel.Text = sr.ReadToEnd();

            sr.Close();
            fs.Close();
        }
        private CipherMode GetMode()
        {
            if (radioButton1.Checked)
                return CipherMode.CBC;
            else return CipherMode.ECB;
        }
    }
}
