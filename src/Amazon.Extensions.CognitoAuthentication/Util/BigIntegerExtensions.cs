using System;
using System.Globalization;
using System.Numerics;

namespace Amazon.Extensions.CognitoAuthentication.Util
{
    internal static class BigIntegerExtensions
    {
        /// <summary>
        /// Turn a hex string into a BigInteger assuming it's an unsigned, little endian hex string.
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static BigInteger FromUnsignedLittleEndianHex(string hex) => BigInteger.Parse("0" + hex, NumberStyles.HexNumber);

        /// <summary>
        /// If the sign of the remainder of self % other is &lt; 0 then add other so that the answer is always positive.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="other"></param>
        /// <returns></returns>
        public static BigInteger TrueMod(this BigInteger self, BigInteger other)
        {
            var remainder = self % other;
            return remainder.Sign >= 0 ? remainder : remainder + other;
        }

        /// <summary>
        /// Return a big endian byte array that's equivalent to this BigInteger.
        /// </summary>
        /// <param name="self"></param>
        /// <returns></returns>
        public static byte[] ToBigEndianByteArray(this BigInteger self) => self.ToByteArray().Reverse();

        /// <summary>
        /// Turn a byte array into a BigInteger, assuming it's an unsigned big endian integer.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static BigInteger FromUnsignedBigEndian(byte[] bytes)
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
