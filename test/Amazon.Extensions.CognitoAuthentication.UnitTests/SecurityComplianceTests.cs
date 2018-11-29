using Amazon.Extensions.CognitoAuthentication.Util;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Amazon.Extensions.CognitoAuthentication.UnitTests
{
    public class SecurityComplianceTests
    {
        private const int ModulusBitSize = 3072;
        private const int EphemeralBitSize = 256;

        private const int BitsInByte = 8;

        [Fact]
        public void ModulusLengthTest()
        {
            // The -1 is to account for the byte that BigInteger.ToByteArray() adds to account for the sign.
            var modulusLength = (AuthenticationHelper.N.ToBigEndianByteArray().Length - 1) * BitsInByte;
            Assert.Equal(ModulusBitSize, modulusLength);
        }

        [Fact]
        public void EphemeralKeyLengthTest()
        {
            // The -1 is to account for the byte that BigInteger.ToByteArray() adds to account for the sign.
            var ephemeralLengthBits = (AuthenticationHelper.CreateBigIntegerRandom().ToBigEndianByteArray().Length - 1) * BitsInByte;
            Assert.True(ephemeralLengthBits >= EphemeralBitSize);
        }
    }
}
