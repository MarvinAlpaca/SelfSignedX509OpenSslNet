using OpenSSL.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SelfSignedX509OpenSslNet
{
    public class Cryptography
    {
        /// <summary>
        /// Method that decrypts a message by public key
        /// </summary>
        /// <param name="publicKeyAsPem"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static byte[] AsymmetricEncrypt(string publicKeyAsPem, byte[] payload)
        {
            CryptoKey d = CryptoKey.FromPublicKey(publicKeyAsPem, null);
            RSA rsa = d.GetRSA();
            byte[] result = rsa.PublicEncrypt(payload, RSA.Padding.PKCS1);
            rsa.Dispose();
            return result;
        }

        /// <summary>
        /// Method that encrypts a message by private key
        /// </summary>
        /// <param name="privateKeyAsPem"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static byte[] AsymmetricDecrypt(string privateKeyAsPem, byte[] payload, string password)
        {
            CryptoKey d = CryptoKey.FromPrivateKey(privateKeyAsPem,password);
            RSA rsa = d.GetRSA();
            byte[] result = rsa.PrivateDecrypt(payload, RSA.Padding.PKCS1);
            rsa.Dispose();
            return result;
        }
    }
}
