# About: #

This project uses the [OpenSSL.NET] (http://sourceforge.net/projects/openssl-net/ "OpenSSL.Net") wrapper to create a self signed X.509 certificate. For further information see my
[blog] (http://marvinalpaca.com/blog/index.php/creating-self-signed-x-509-certificates-using-openssl-net/ "blog post") on this subject.

The application performs the following steps:

1. Create a new Certificate Authority (CA).
2. Create Certificate Signing Request (CSR).
3. Use the CA to sign the certificate request.
4. Write the signed certificate out to file.

# Using: #

This project depends on the OpenSSL.Net wrapper and needs to be downloaded in order to use the application.

There are three DLLs used as part of the OpenSSL.Net wrapper:

* ManagedOpenSsl.dll – This needs to be in the project references.
* libeay32.dll – This file needs to be accessible by your project executable.
* ssleay32.dll – This file also needs to be accessible by your project executable.

The OpenSSL.Net files can be downloaded [FILES] (http://sourceforge.net/projects/openssl-net/files/latest/download "here").