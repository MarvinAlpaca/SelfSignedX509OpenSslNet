using System;

using OpenSSL.Crypto;
using SelfSignedX509OpenSslNet.Properties;

namespace SelfSignedX509OpenSslNet
{
    internal class Program
    {
         private static void Main(string[] args)
        {
            using (var ca = new CertificateAuthority())
            {
                ca.CreateCryptoKey();
                ca.SetupSubjectInformation();
                ca.CreateCertificateAuthorityWithExtensions();

                // Write the CA certificate and it's private key to file so that it can be re-used.
                FileHelpers.WriteCertificateToFileInPemFormat(@"D:\OpenSSL-Win32\bin\ca.cer", ca.CA.Certificate);
                FileHelpers.WritePrivateKeyToFile(ca.Key, @"d:\OpenSSL-Win32\bin\capkey.key", "caPassword");

                using (var csr = new CertificateSigningRequest())
                {
                    csr.CreateCryptoKey();
                    csr.SetupSubjectInformation();
                    csr.CreateCertificateSigningRequest();

                    // Have the CA process the CSR and issue a certificate that is valid for 1 year.
                    using (var signedCert = ca.CA.ProcessRequest(csr.Request, DateTime.UtcNow, DateTime.UtcNow.AddYears(1), MessageDigest.SHA512))
                    {
                        // Write the new certificate and it's private key to file.
                        FileHelpers.WriteCertificateToFileInPemFormat(@"d:\openssl.net\new cert.cer", signedCert);
                        FileHelpers.WritePrivateKeyToFile(csr.Key, @"d:\openssl.net\pkey.key", "password");

                        //Encrypts and Decrypts one word from generated keys
                        CryptoTest(csr);
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts and Decrypts one word from generated keys
        /// </summary>
        /// <param name="csr"></param>
        private static void CryptoTest(CertificateSigningRequest csr)
        {
            System.Text.Encoding enc = System.Text.Encoding.ASCII;
            String s = "teste";
            byte[] payload = enc.GetBytes(s);
            Console.WriteLine("s: {0}", s);

            byte[] byte_encData = Everest.Common.Security.RSABinaryPattern.Cryptography.AsymmetricEncrypt(csr.Key.GetRSA().PublicKeyAsPEM, payload);

            String res;
            res = Convert.ToBase64String(byte_encData);
            Console.WriteLine("encypted: {0}", res);

            byte[] byte_decrypted = Everest.Common.Security.RSABinaryPattern.Cryptography.AsymmetricDecrypt(csr.Key.GetRSA().PrivateKeyAsPEM, byte_encData, "caPassword");
            String res_unenc;

            res_unenc = Encoding.UTF8.GetString(byte_decrypted);
            Console.WriteLine("decrypted: {0}", res_unenc);
            Console.ReadLine();
        }
    }
}
