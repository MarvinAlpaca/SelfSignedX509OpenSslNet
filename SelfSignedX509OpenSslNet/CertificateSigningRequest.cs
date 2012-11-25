using System;
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.X509;
using SelfSignedX509OpenSslNet.Properties;

namespace SelfSignedX509OpenSslNet
{
    public class CertificateSigningRequest : IDisposable
    {
        private static int CertificateVersion = 2; // Version 2 is X.509 Version 3

        /// <summary>
        /// Gets or Sets the CryptoKey containing both public and private keys.
        /// </summary>
        public CryptoKey Key { get; set; }

        /// <summary>
        /// Gets or Sets the X509Request object.
        /// </summary>
        public X509Request Request { get; set; }

        /// <summary>
        /// Gets or Sets the Subject information for the Certificate Request.
        /// </summary>
        public X509Name Subject { get; set; }

        /// <summary>
        /// Default Constructor.
        /// </summary>
        public CertificateSigningRequest()
        {
        }

        /// <summary>
        /// Loads the Certificate Signing Request from the specified path into memory (as a BIO object) then
        /// attempts to create a new X509Request from the BIO object and assigns it to the Request property.
        /// </summary>
        /// <param name="pathToCsr">The path to the CSR file to load.</param>
        public void LoadCertificateSigningRequestFromFile(string pathToCsr)
        {
            this.Request = FileHelpers.LoadX509RequestFromFile(pathToCsr);
        }

        /// <summary>
        /// Loads the private key file from the specified path. Uses the password parameter to decrypt the
        /// file containing the password if it has one.
        /// </summary>
        /// <param name="pathToPrivateKey">The full path and name of the file containing the private key.</param>
        /// <param name="password">Uses the PasswordHandler to decrypt the private key file. Leave null if file is not password protected.</param>
        public void LoadCertificateSigningRequestPrivateKeyFromFile(string pathToPrivateKey, PasswordHandler password)
        {
            this.Key = FileHelpers.LoadRsaPrivateKeyFromFile(pathToPrivateKey, password);
        }

        /// <summary>
        /// Creates a new Certificate Signing Request from the Subject, and Key properties and
        /// assigns the new X509Request object to the Request property.
        /// </summary>
        public void CreateCertificateSigningRequest()
        {
            this.Request = new X509Request(CertificateVersion, this.Subject, this.Key);
        }

        /// <summary>
        /// Callback handler for the Certificate Signing Request password.
        /// </summary>
        /// <param name="verify"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        public static string GetCertificateAuthorityPassword(bool verify, object args)
        {
            return Settings.Default.csrPrivateKeyPassword;
        }

        /// <summary>
        /// Gets the Subject information for the Certificate Signing Request.
        /// </summary>
        /// <returns>X509Name object populated with the subject information for the Certificate Signing Request.</returns>
        private static X509Name GetCertificateSigningRequestSubject()
        {
            var requestDetails = new X509Name();
            requestDetails.Common = "http://testserver.example.com/";
            requestDetails.Country = "UK";
            requestDetails.StateOrProvince = "Hampshire";
            requestDetails.Organization = "Test Co";
            requestDetails.OrganizationUnit = "Development";

            return requestDetails;
        }

        /// <summary>
        /// Calls <see cref="Dispose(bool disposing)"/> to dispose of the class properties.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose of any initialized property that holds resources from the OpenSSL library.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (this.Key != null)
            {
                this.Key.Dispose();
            }
            if (this.Subject != null)
            {
                this.Subject.Dispose();
            }
            if (this.Request != null)
            {
                this.Request.Dispose();
            }
        }

        /// <summary>
        /// Initialize the Subject property with the Certificate Signing Request subject information.
        /// </summary>
        public void SetupSubjectInformation()
        {
            this.Subject = GetCertificateSigningRequestSubject();
        }

        /// <summary>
        /// Create a new RSA based private and public keys.
        /// </summary>
        public void CreateCryptoKey()
        {
            this.Key = FileHelpers.CreateNewRsaKey(4096);
        }
    }
}