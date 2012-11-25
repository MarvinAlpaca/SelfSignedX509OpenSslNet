using System;
using System.IO;
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.X509;

namespace SelfSignedX509OpenSslNet
{
    public static class FileHelpers
    {
        /// <summary>
        /// Loads a BIO object from the specified fileName parameter and returns a BIO object with the loaded file.
        /// </summary>
        /// <param name="fileName">The full path of the file to load.</param>
        /// <returns>A BIO object containing the loaded file.</returns>
        private static BIO Load(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentNullException("fileName", "fileName is null or empty");
            }

            return BIO.File(fileName, "r");
        }

        /// <summary>
        /// Creates a writable BIO object stream from the specified path.
        /// </summary>
        /// <param name="fileName">The full path where the file will be created.</param>
        /// <returns>A writable BIO object that for use with write methods.</returns>
        private static BIO Write(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentNullException("fileName", "fileName is null or empty");
            }

            return BIO.File(fileName, "w");
        }

        /// <summary>
        /// Writes the specified cryptoKey out to the file in the fileName parameter. The contents of the
        /// file is encrypted with the triple DES algorithm with the specified password.
        /// </summary>
        /// <param name="cryptoKey">The CryptoKey containing the Private key to be written to file.</param>
        /// <param name="fileName">The name and location of the file to be written.</param>
        /// <param name="password">The password used to decrypt the file.</param>
        public static void WritePrivateKeyToFile(CryptoKey cryptoKey, string fileName, string password)
        {
            if (cryptoKey == null)
            {
                throw new ArgumentNullException("cryptoKey", "CryptoKey is null");
            }

            using (var bio = FileHelpers.Write(fileName))
            {
                cryptoKey.WritePrivateKey(bio, Cipher.DES_EDE3_CBC, password);
            }
        }

        /// <summary>
        /// Loads the private key into memory (as a BIO object) and attempts to create a private key using the RSA algorithm and
        /// the supplied privateKeyPassword.
        /// </summary>
        /// <param name="pathToPrivateKeyFile">The path to the private key file.</param>
        /// <param name="privateKeyPassword">The password for the private key. Pass null if no password.</param>
        /// <returns>A new instance of CryptoKey from the RSA private key.</returns>
        public static CryptoKey LoadRsaPrivateKeyFromFile(string pathToPrivateKeyFile, PasswordHandler privateKeyPassword)
        {
            using (var privateKeyBio = FileHelpers.Load(pathToPrivateKeyFile))
            {
                using (var rsa = RSA.FromPrivateKey(privateKeyBio, privateKeyPassword, null))
                {
                    return new CryptoKey(rsa);
                }
            }
        }

        /// <summary>
        /// Creates a new X509Certificate from the specified path.
        /// </summary>
        /// <param name="pathToRequestFile">The full path and name of the file to load.</param>
        /// <returns>A new X509Certificate.</returns>
        public static X509Certificate LoadX509CertificateFromFile(string pathToCertificateFile)
        {
            using (var certificateBio = FileHelpers.Load(pathToCertificateFile))
            {
                return new X509Certificate(certificateBio);
            }
        }

        /// <summary>
        /// Creates a new X509Request from the specified path.
        /// </summary>
        /// <param name="pathToCertificateFile">The full path and name of the file to load.</param>
        /// <returns>A new X509Request.</returns>
        public static X509Request LoadX509RequestFromFile(string pathToRequestFile)
        {
            using (var certificateBio = FileHelpers.Load(pathToRequestFile))
            {
                return new X509Request(certificateBio);
            }
        }

        /// <summary>
        /// Writes the specified X509Certificate to the file in the fileName parameter. The
        /// certificate is saved in the default PEM format.
        /// </summary>
        /// <param name="fileName">The name and location of the file to write the certificate to.</param>
        /// <param name="certificate">The certificate to write to file.</param>
        public static void WriteCertificateToFileInPemFormat(string fileName, X509Certificate certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate", "certificate is null");
            }

            using (var bio = FileHelpers.Write(fileName))
            {
                certificate.Write(bio);
            }
        }

        /// <summary>
        /// Writes the specified X509Certificate to the file in the fileName parameter. The
        /// certificate is saved in the default DER format.
        /// </summary>
        /// <param name="fileName">The name and location of the file to write the certificate to.</param>
        /// <param name="certificate">The certificate to write to file.</param>
        public static void WriteCertificateToFileInDerFormat(string fileName, X509Certificate certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate", "certificate is null");
            }

            using (var bio = FileHelpers.Write(fileName))
            {
                certificate.Write_DER(bio);
            }
        }

        /// <summary>
        /// Writes the specified Certificate and Crypto key out to the file defined in the fileName parameter. This
        /// file is protected with the specified password. The password is optional.
        /// </summary>
        /// <param name="fileName">The file name and path of the pfx file to be created.</param>
        /// <param name="password">The password to be put on the pfx file if any.</param>
        /// <param name="cryptoKey">The CryptoKey containing the private key that belongs to the certificate parameter.</param>
        /// <param name="certificate">The certificate to write to file.</param>
        public static void WritePfxToFile(string fileName, string password, CryptoKey cryptoKey, X509Certificate certificate)
        {
            if (cryptoKey == null)
            {
                throw new ArgumentNullException("cryptoKey", "CryptoKey is null");
            }
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate", "certificate is null");
            }

            using (var bio = FileHelpers.Write(fileName))
            using (var caStack = new OpenSSL.Core.Stack<X509Certificate>())
            using (var pfx = new PKCS12(password, cryptoKey, certificate, caStack))
            {
                pfx.Write(bio);
            }
        }

        /// <summary>
        /// Creates a new CryptoKey with public and private keys generated by the
        /// RSA algorithm.
        /// </summary>
        /// <param name="numberOfBits">The bit strength to be used for the RSA algorithm. A value greater than 1024 is recommended.</param>
        /// <returns>A new CryptoKey with both private and public keys generated used the RSA algorithm.</returns>
        public static CryptoKey CreateNewRsaKey(int numberOfBits)
        {
            using (var rsa = new RSA())
            {
                BigNumber exponent = 0x10001; // this needs to be a prime number
                rsa.GenerateKeys(numberOfBits, exponent, OnGenerator, null);

                return new CryptoKey(rsa);
            }
        }

        private static int OnGenerator(int p, int n, object arg)
        {
            TextWriter cout = Console.Error;

            switch (p)
            {
                case 0: cout.Write('.'); break;
                case 1: cout.Write('+'); break;
                case 2: cout.Write('*'); break;
                case 3: cout.WriteLine(); break;
            }

            return 1;
        }
    }
}