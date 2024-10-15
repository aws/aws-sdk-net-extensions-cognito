using Amazon.Extensions.CognitoAuthentication.Util;
using System.Globalization;
using System.Linq;
using System.Numerics;
using Xunit;

namespace Amazon.Extensions.CognitoAuthentication.UnitTests
{
    public class BigIntegerExtensionsTests
    {
        [Fact]
        public void TestFromHexPositiveTest()
        {
            TestFromHexPositive("0", 0, 0);
            TestFromHexPositive("1", 1, 1);
            TestFromHexPositive("2", 2, 2);
            TestFromHexPositive("3", 3, 3);
            TestFromHexPositive("4", 4, 4);
            TestFromHexPositive("5", 5, 5);
            TestFromHexPositive("6", 6, 6);
            TestFromHexPositive("7", 7, 7);
            TestFromHexPositive("8", 8, -8);
            TestFromHexPositive("9", 9, -7);
            TestFromHexPositive("A", 10, -6);
            TestFromHexPositive("B", 11, -5);
            TestFromHexPositive("C", 12, -4);
            TestFromHexPositive("D", 13, -3);
            TestFromHexPositive("E", 14, -2);
            TestFromHexPositive("F", 15, -1);

            TestFromHexPositive("00", 0, 0);
            TestFromHexPositive("10", 16, 16);
            TestFromHexPositive("20", 32, 32);
            TestFromHexPositive("30", 48, 48);
            TestFromHexPositive("40", 64, 64);
            TestFromHexPositive("50", 80, 80);
            TestFromHexPositive("60", 96, 96);
            TestFromHexPositive("70", 112, 112);
            TestFromHexPositive("80", 128, -128);
            TestFromHexPositive("90", 144, -112);
            TestFromHexPositive("A0", 160, -96);
            TestFromHexPositive("B0", 176, -80);
            TestFromHexPositive("C0", 192, -64);
            TestFromHexPositive("D0", 208, -48);
            TestFromHexPositive("E0", 224, -32);
            TestFromHexPositive("F0", 240, -16);
        }

        private void TestFromHexPositive(string hex, int expectedFromHexPositive, int expectedFromHexRegular)
        {
            Assert.Equal(new BigInteger(expectedFromHexPositive), BigIntegerExtensions.FromUnsignedLittleEndianHex(hex));
            Assert.Equal(new BigInteger(expectedFromHexRegular), BigInteger.Parse(hex, NumberStyles.HexNumber));
        }

        [Fact]
        public void TestTrueModTest()
        {
            TestTrueMod(10, 3, 1);
            TestTrueMod(10, 5, 0);
            TestTrueMod(-10, 3, 2);
            TestTrueMod(-10, 5, 0);
        }

        private void TestTrueMod(int numerator, int denominator, int expectedTrueMod)
        {
            var biNumerator = new BigInteger(numerator);
            var biDenominator = new BigInteger(denominator);

            var biTrueMod = biNumerator.TrueMod(biDenominator);

            Assert.Equal(expectedTrueMod, biTrueMod);
        }

        [Fact]
        public void TestFromBigEndianPositiveTest()
        {
            TestFromBigEndianPositive(300, new byte[] { 1, 44 }, 300);
            TestFromBigEndianPositive(-266, new byte[] { 254, 246 }, 65270);
        }

        private void TestFromBigEndianPositive(int number, byte[] expectedBigEndianByteArray, int expectedFromBigEndianPositvie)
        {
            var biNumber = new BigInteger(number);
            var bigEndianByteArray = biNumber.ToBigEndianByteArray();
            var biFromBigEndianPositive = BigIntegerExtensions.FromUnsignedBigEndian(bigEndianByteArray);

            Assert.True(expectedBigEndianByteArray.SequenceEqual(bigEndianByteArray));
            Assert.Equal(expectedFromBigEndianPositvie, biFromBigEndianPositive);
        }
    }
}
