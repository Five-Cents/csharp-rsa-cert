using System;
using System.Text;
using Lib;
using Xunit;

namespace Test
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            var certificate = Helpers.CreateSelfSignedCert(2048, "cn=Test", 365, false);
            
            Assert.NotNull(certificate);
            Assert.True(certificate.HasPrivateKey);
            Assert.True(certificate.Thumbprint != null);
            Assert.True(certificate.PublicKey != null);
        }

        [Fact]
        public void Test2()
        {
            var certificate = Helpers.CreateSelfSignedCert(2048, "cn=Test", 365, false);

            const string stringToEncrypt = "TestMe";
            
            // Test encryption.
            var bytesToEncrypt = Encoding.UTF8.GetBytes(stringToEncrypt);
            var encryptedBytes = Helpers.EncryptBytesWithRSACertificate(certificate, bytesToEncrypt);
            var encryptedString = Convert.ToBase64String(encryptedBytes);
            
            Assert.True(stringToEncrypt != encryptedString);

            encryptedBytes = Convert.FromBase64String(encryptedString);
            var decryptedBytes = Helpers.DecryptBytesWithRSACertificate(certificate, encryptedBytes);
            var originalString = Encoding.UTF8.GetString(decryptedBytes);
            
            Assert.Equal(stringToEncrypt, originalString);
        }
    }
}