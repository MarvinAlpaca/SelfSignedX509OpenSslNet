using System;
using System.IO;
using OpenSSL.Crypto;
using OpenSSL.X509;
using SelfSignedX509OpenSslNet.Properties;

namespace SelfSignedX509OpenSslNet
{
    public class CertificateAuthority : IDisposable
    {
        /// <summary>
        /// Gets or sets the X.509 Certificate Authority.
        /// </summar>
        public X509CertificateAuthority CA { get; set; }

        /// <summary>
        /// Gets or set the CryptoKey containing the public and private keys of the Certificate
        /// Authority.
        /// </summary>
        public CryptoKey Key { get; set; }

        /// <summary>
        /// Gets or sets the subject information for the Certificate Authority.
        /// </summary>
        public X509Name Subject { get; set; }

        /// <summary>
        /// Gets or sets the OpenSSL configuration file.
        /// </summary>
        public Configuration Config { get; set; }

        /// <summary>
        /// Gets or sets the ISequenceNumber instance used for the generating the serial
        /// number for new certificates signed by the Certificate Authority.
        /// </summary>
        public ISequenceNumber SerialNumberSequencer { get; set; }

        /// <summary>
        /// Default Constructor. Initializes the SerialNumberSequencer property.
        /// </summary>
        public CertificateAuthority()
        {
            this.SerialNumberSequencer = GetSerialNumberSequencer();
        }

        /// <summary>
        /// Gets the ISequenceNumber used to generate new certificate serial numbers.
        /// </summary>
        /// <returns>A sequence number for generating new certificate serial numbers.</returns>
        private static ISequenceNumber GetSerialNumberSequencer()
        {
            return new SimpleSerialNumber();
        }

        /// <summary>
        /// Creates a new Certificate Authority from an X.509 Certificate file. Loads the X.509 Certificate from
        /// the pathToCAFile parameter and the private key from the pathToPrivateKeyFile parameter. Uses the
        /// Config property if set.
        /// </summary>
        /// <param name="pathToCAFile">The full path and name of the certificate </param>
        /// <param name="pathToPrivateKeyFile"></param>
        public void LoadCertificateAuthorityFromFile(string pathToCAFile, string pathToPrivateKeyFile)
        {
            using (var certificate = FileHelpers.LoadX509CertificateFromFile(pathToCAFile))
            {
                this.Key = FileHelpers.LoadRsaPrivateKeyFromFile(pathToPrivateKeyFile, GetCertificateAuthorityPassword);

                this.CA = new X509CertificateAuthority(certificate, this.Key, this.SerialNumberSequencer, this.Config);
            }
        }

        /// <summary>
        /// Creates a new Certificate Authority instance that uses the configuration file when
        /// to apply extensions when the CA signs a new certificate. The CA
        /// is created with the extensions in the [ V3_CA ] section in the configuration file.
        /// </summary>
        public void CreateCertificateAuthorityWithConfigurationFile()
        {
            this.Config = LoadConfigurationFile(Path.Combine(Environment.CurrentDirectory, Settings.Default.OpenSslConfigurationFileName));

            this.CA = X509CertificateAuthority.SelfSigned(this.Config, this.SerialNumberSequencer, this.Key, MessageDigest.SHA512, this.Subject, DateTime.UtcNow, TimeSpan.FromDays(365));
        }

        /// <summary>
        /// Creates a new Certificate instance by loading the OpenSSL configuration file
        /// specified in the pathToConfigureationFile parameter.
        /// </summary>
        /// <param name="pathToConfigurationFile">The full path and name of the OpenSSL configuration file.</param>
        /// <returns>A new Configuration instance.</returns>
        private static Configuration LoadConfigurationFile(string pathToConfigurationFile)
        {
            return new Configuration(pathToConfigurationFile);
        }

        /// <summary>
        /// Creates a new Certificate Authority using a list of extensions for the CA certificate.
        /// </summary>
        public void CreateCertificateAuthorityWithExtensions()
        {
            var extensions = GetCertificateAuthorityExtensions();
            this.CA = X509CertificateAuthority.SelfSigned(this.SerialNumberSequencer, this.Key, MessageDigest.SHA512, this.Subject, DateTime.UtcNow, TimeSpan.FromDays(365), extensions);
        }

        /// <summary>
        /// Gets a list of X509V3Extensions that are required for creating a Certificate Authority.
        /// </summary>
        /// <returns>X509V3ExtensionList of parameters required to create a Certificate Authority.</returns>
        private static X509V3ExtensionList GetCertificateAuthorityExtensions()
        {
            var extensions = new X509V3ExtensionList();
            extensions.Add(new X509V3ExtensionValue("basicConstraints", true, "CA:TRUE"));
            extensions.Add(new X509V3ExtensionValue("subjectKeyIdentifier", false, "hash"));
            extensions.Add(new X509V3ExtensionValue("authorityKeyIdentifier", false, "keyid:always,issuer:always"));

            return extensions;
        }

        /// <summary>
        /// Gets the Subject/Issuer information for the Certificate Authority.
        /// </summary>
        /// <returns>X509Name object populated with the subject information for the Certificate Authority.</returns>
        private static X509Name GetCertificateAuthoritySubject()
        {
            X509Name subject = new X509Name();
            subject.Common = "Alpaca Self Signing Certificate";
            subject.Country = "UK";
            subject.StateOrProvince = "Hampshire";
            subject.Organization = "MarvinAlpaca";
            subject.OrganizationUnit = "Testings";

            return subject;
        }

        /// <summary>
        /// Callback handler for the Certificate Authority password.
        /// </summary>
        /// <param name="verify"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        public static string GetCertificateAuthorityPassword(bool verify, object args)
        {
            return Settings.Default.caPrivateKeyPassword;
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
            if (this.CA != null)
            {
                this.CA.Dispose();
            }
            if (this.Subject != null)
            {
                this.Subject.Dispose();
            }
            if (this.Config != null)
            {
                this.Config.Dispose();
            }
        }

        /// <summary>
        /// Create a new RSA based private and public keys.
        /// </summary>
        public void CreateCryptoKey()
        {
            this.Key = FileHelpers.CreateNewRsaKey(4096);
        }

        /// <summary>
        /// Initialize the Subject property with the Certificate Authority subject information.
        /// </summary>
        public void SetupSubjectInformation()
        {
            this.Subject = GetCertificateAuthoritySubject();
        }
    }
}