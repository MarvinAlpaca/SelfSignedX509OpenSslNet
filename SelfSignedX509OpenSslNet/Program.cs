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
                FileHelpers.WriteCertificateToFileInPemFormat(Settings.Default.caCertificateFileLocation, ca.CA.Certificate);
                FileHelpers.WritePrivateKeyToFile(ca.Key, Settings.Default.caPrivateKeyFileLocation, Settings.Default.caPrivateKeyPassword);

                using (var csr = new CertificateSigningRequest())
                {
                    csr.CreateCryptoKey();
                    csr.SetupSubjectInformation();
                    csr.CreateCertificateSigningRequest();

                    // Have the CA process the CSR and issue a certificate that is valid for 1 year.
                    using (var signedCert = ca.CA.ProcessRequest(csr.Request, DateTime.UtcNow, DateTime.UtcNow.AddYears(1), MessageDigest.SHA512))
                    {
                        // Write the new certificate and it's private key to file.
                        FileHelpers.WriteCertificateToFileInPemFormat(Settings.Default.SignedCertificateFileLocation, signedCert);
                        FileHelpers.WritePrivateKeyToFile(csr.Key, Settings.Default.csrPrivateKeyFileLocation, Settings.Default.csrPrivateKeyPassword);
                    }
                }
            }
        }
    }
}