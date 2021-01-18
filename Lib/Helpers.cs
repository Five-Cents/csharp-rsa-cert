using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Lib
{
    public static class Helpers
    {

        /// <summary>
        /// Creates a self-signed certificate, using a RSA public/private key pair.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="distinguishedName">Name of the certificate.</param>
        /// <param name="daysValid">How many days the certificate will be valid for.</param>
        /// <param name="persistKeyInCsp">Whether or not the key should be persisted in our key container.</param>
        /// <returns></returns>
        public static X509Certificate2 CreateSelfSignedCert(int keySize, string distinguishedName, int daysValid, bool persistKeyInCsp)
        {
            using var rsa = new RSACryptoServiceProvider(keySize);

            try
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment |
                    X509KeyUsageFlags.DigitalSignature, false));

                var certificate = request.CreateSelfSigned(new DateTimeOffset(
                    DateTime.UtcNow.AddDays(-1)),
                    new DateTimeOffset(DateTime.UtcNow.AddDays(daysValid)));

                var pwd = new Guid().ToString();

                return new X509Certificate2(certificate.Export(X509ContentType.Pfx, pwd), pwd,
                    X509KeyStorageFlags.MachineKeySet);

            }
            finally
            {
                rsa.PersistKeyInCsp = persistKeyInCsp;
            }
        }

        /// <summary>
        /// Encrypts some bytes.
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="bytesToBeEncrypted"></param>
        /// <returns></returns>
        /// ReSharper disable once InconsistentNaming
        public static byte[] EncryptBytesWithRSACertificate(X509Certificate2 certificate, byte[] bytesToBeEncrypted)
        {
            var publicKey = certificate.GetRSAPublicKey();
            return publicKey.Encrypt(bytesToBeEncrypted, RSAEncryptionPadding.OaepSHA256);
        }

        /// <summary>
        /// Decrypts some bytes.
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="bytesToBeDecrypted"></param>
        /// <returns></returns>
        /// ReSharper disable once InconsistentNaming
        public static byte[] DecryptBytesWithRSACertificate(X509Certificate2 certificate, byte[] bytesToBeDecrypted)
        {
            var privateKey = certificate.GetRSAPrivateKey();
            return privateKey.Decrypt(bytesToBeDecrypted, RSAEncryptionPadding.OaepSHA256);
        }
    }
}