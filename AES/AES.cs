using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace AES
{
    class AES
    {
        private static string IV = "0123456789012345";
        AesCryptoServiceProvider crypt_provider;

        public AES()
        {


        }
        public string Encrypt (string text,string key, CipherMode mode)
        {
            
            crypt_provider = new AesCryptoServiceProvider();
            crypt_provider.BlockSize = 128;
            crypt_provider.KeySize = 256;
            byte[] textBytes = ASCIIEncoding.ASCII.GetBytes(text);
            crypt_provider.IV = ASCIIEncoding.ASCII.GetBytes(IV);
            crypt_provider.Key = ASCIIEncoding.ASCII.GetBytes(key);
            crypt_provider.Padding = PaddingMode.PKCS7; //Specifies the type of padding to apply when the message data block is shorter than the full number of bytes needed for a cryptographic operation.
            crypt_provider.Mode = mode;
            ICryptoTransform transform = crypt_provider.CreateEncryptor(crypt_provider.Key,crypt_provider.IV);
            byte[] encrypted_bytes = transform.TransformFinalBlock(textBytes, 0,textBytes.Length);
            transform.Dispose();
            return Convert.ToBase64String(encrypted_bytes);
        }
        public string Decrypt(string text,string key, CipherMode mode)
        {
            crypt_provider = new AesCryptoServiceProvider();
            crypt_provider.BlockSize = 128;
            crypt_provider.KeySize = 256;
            byte[] textBytes = Convert.FromBase64String(text);
            crypt_provider.IV = ASCIIEncoding.ASCII.GetBytes(IV);
            crypt_provider.Key = ASCIIEncoding.ASCII.GetBytes(key);
            crypt_provider.Padding = PaddingMode.PKCS7; //Specifies the type of padding to apply when the message data block is shorter than the full number of bytes needed for a cryptographic operation.
            crypt_provider.Mode = mode;
            ICryptoTransform transform = crypt_provider.CreateDecryptor(crypt_provider.Key, crypt_provider.IV);
            byte[] decrypted_bytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
            transform.Dispose();
            return ASCIIEncoding.ASCII.GetString(decrypted_bytes);
        }





    }
}
