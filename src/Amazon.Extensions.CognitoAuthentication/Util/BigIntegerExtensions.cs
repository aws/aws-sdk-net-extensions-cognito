using System;
using System.Globalization;
using System.Numerics;

namespace Amazon.Extensions.CognitoAuthentication.Util
{
    internal static class BigIntegerExtensions
    {
        public static BigInteger FromHexPositive(string hex) => BigInteger.Parse("0" + hex, NumberStyles.HexNumber);

        public static BigInteger TrueMod(this BigInteger self, BigInteger other)
        {
            var remainder = self % other;
            return remainder.Sign >= 0 ? remainder : remainder + other;
        }

        public static BigInteger TrueModPow(this BigInteger self, BigInteger exponent, BigInteger modulus)
        {
            var ret = BigInteger.ModPow(self, exponent, modulus);
            if(ret.Sign < 0)
            {
                ret += ((ret * -1) / modulus) * modulus;
                if(ret.Sign < 0)
                {
                    ret += modulus;
                }
            }
            return ret;
        }

        public static byte[] ToBigEndianByteArray(this BigInteger self) => self.ToByteArray().Reverse();

        public static BigInteger FromBigEndian(byte[] bytes)
        {
            var reverse = bytes.Reverse();

            //Need to end with a zero byte to force positive
            var ensurePos = new byte[reverse.Length + 1];
            Array.Copy(reverse, ensurePos, reverse.Length);

            return new BigInteger(ensurePos);
        }

        private static T[] Reverse<T>(this T[] array)
        {
            var reverse = new T[array.Length];
            for(int rev = array.Length - 1, index = 0; rev >= 0; rev--, index++)
            {
                reverse[index] = array[rev];
            }
            return reverse;
        }
    }
}
