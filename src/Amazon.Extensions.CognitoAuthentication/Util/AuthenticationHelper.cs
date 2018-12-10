/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 * 
 *  http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Amazon.Extensions.CognitoAuthentication.Util
{
    /// <summary>
    /// Class that provides utility methods for performing the Secure Remote Password protocol
    /// Adapted from http://srp.stanford.edu/design.html
    /// </summary>
    internal static class AuthenticationHelper
    {
        /// <summary>
        /// 3072-bit
        /// </summary>
        private const string Srp_hexN = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

        private const int Srp_g = 2;

        public static readonly BigInteger N = BigIntegerExtensions.FromUnsignedLittleEndianHex(Srp_hexN);
        public static readonly BigInteger g = new BigInteger(Srp_g);
        public static readonly BigInteger k;

        /// <summary>
        /// Secret key size bytes
        /// </summary>
        public const int SecretKeySizeBytes = 128;

        /// <summary>
        /// Value used by AWS Cognito
        /// </summary>
        public const int DerivedKeySizeBytes = 16;

        public const string DerivedKeyInfo = "Caldera Derived Key";

        static AuthenticationHelper()
        {
            // generate k for the input key material to HKDF
            var content = CognitoAuthHelper.CombineBytes(new[] { N.ToBigEndianByteArray(), g.ToBigEndianByteArray() });
            var messageDigest = CognitoAuthHelper.Sha256.ComputeHash(content);
            k = BigIntegerExtensions.FromUnsignedBigEndian(messageDigest);
        }

        /// <summary>
        /// Return the Tuple of (A, a) for SRP
        /// </summary>
        /// <returns></returns>
        public static Tuple<BigInteger, BigInteger> CreateAaTuple()
        {
            var a = CreateBigIntegerRandom();
            var A = BigInteger.ModPow(g, a, N);
            return Tuple.Create(A, a);
        }

        /// <summary>
        /// Generates the claim for authenticating a user through the SRP protocol
        /// </summary>
        /// <param name="username"> Username of CognitoUser</param>
        /// <param name="password"> Password of CognitoUser</param>
        /// <param name="poolName"> PoolName of CognitoUserPool (from poolID: <region>_<poolName>)</param>
        /// <param name="tupleAa"> TupleAa from CreateAaTuple</param>
        /// <param name="saltString"> salt provided in ChallengeParameters from Cognito </param>
        /// <param name="srpbString"> srpb provided in ChallengeParameters from Cognito</param>
        /// <param name="secretBlockBase64">secret block provided in ChallengeParameters from Cognito</param>
        /// <param name="formattedTimestamp">En-US Culture of Current Time</param>
        /// <returns>Returns the claim for authenticating the given user</returns>
        public static byte[] AuthenticateUser(
            string username, 
            string password, 
            string poolName,
            Tuple<BigInteger, BigInteger> tupleAa, 
            string saltString, 
            string srpbString,
            string secretBlockBase64, 
            string formattedTimestamp)
        {
            var B = BigIntegerExtensions.FromUnsignedLittleEndianHex(srpbString);
            if (B.TrueMod(N).Equals(BigInteger.Zero)) throw new ArgumentException("B mod N cannot be zero.", nameof(srpbString));
            
            var secretBlockBytes = Convert.FromBase64String(secretBlockBase64);
            var salt = BigIntegerExtensions.FromUnsignedLittleEndianHex(saltString);

            // Need to generate the key to hash the response based on our A and what AWS sent back
            var key = GetPasswordAuthenticationKey(username, password, poolName, tupleAa, B, salt);

            // HMAC our data with key (HKDF(S)) (the shared secret)
            var contentBytes = CognitoAuthHelper.CombineBytes(new [] { Encoding.UTF8.GetBytes(poolName), Encoding.UTF8.GetBytes(username),
                                               secretBlockBytes, Encoding.UTF8.GetBytes(formattedTimestamp) });

            using (var hashAlgorithm = new HMACSHA256(key))
            {
                return hashAlgorithm.ComputeHash(contentBytes);
            }
        }

        /// <summary>
        /// Creates the Password Authentication Key based on the SRP protocol
        /// </summary>
        /// <param name="userID"> Username of CognitoUser</param>
        /// <param name="userPassword">Password of CognitoUser</param>
        /// <param name="poolName">PoolName of CognitoUserPool (part of poolID after "_")</param>
        /// <param name="Aa">Returned from TupleAa</param>
        /// <param name="B">BigInteger SRPB from AWS ChallengeParameters</param>
        /// <param name="salt">BigInteger salt from AWS ChallengeParameters</param>
        /// <returns>Returns the password authentication key for the SRP protocol</returns>
        public static byte[] GetPasswordAuthenticationKey(string userID, 
            string userPassword, 
            string poolName,
            Tuple<BigInteger, BigInteger> Aa, 
            BigInteger B, 
            BigInteger salt)
        {
            // Authenticate the password
            // u = H(A, B)
            byte[] contentBytes = CognitoAuthHelper.CombineBytes(new [] { Aa.Item1.ToBigEndianByteArray(), B.ToBigEndianByteArray() });
            byte[] digest = CognitoAuthHelper.Sha256.ComputeHash(contentBytes);

            BigInteger u = BigIntegerExtensions.FromUnsignedBigEndian(digest);
            if (u.Equals(BigInteger.Zero))
            {
                throw new ArgumentException("Hash of A and B cannot be zero.");
            }

            // x = H(salt | H(poolName | userId | ":" | password))
            byte[] userIdContent = CognitoAuthHelper.CombineBytes(new byte[][] { Encoding.UTF8.GetBytes(poolName), Encoding.UTF8.GetBytes(userID),
                                                Encoding.UTF8.GetBytes(":"), Encoding.UTF8.GetBytes(userPassword)});
            byte[] userIdHash = CognitoAuthHelper.Sha256.ComputeHash(userIdContent);
            byte[] xBytes = CognitoAuthHelper.CombineBytes(new byte[][] { salt.ToBigEndianByteArray(), userIdHash });

            byte[] xDigest = CognitoAuthHelper.Sha256.ComputeHash(xBytes);
            BigInteger x = BigIntegerExtensions.FromUnsignedBigEndian(xDigest);

            // Use HKDF to get final password authentication key
            var first = (B - k * BigInteger.ModPow(g, x, N)).TrueMod(N);
            var second = BigInteger.ModPow(first, Aa.Item2 + u * x, N);
            HkdfSha256 hkdfSha256 = new HkdfSha256(u.ToBigEndianByteArray(), second.ToBigEndianByteArray());
            return hkdfSha256.Expand(Encoding.UTF8.GetBytes(DerivedKeyInfo), DerivedKeySizeBytes);
        }

        /// <summary>
        /// Create a cryptographically secure random BigInteger
        /// </summary>
        /// <returns></returns>
        public static BigInteger CreateBigIntegerRandom()
        {
            var b = new byte[SecretKeySizeBytes];
            using(var cryptoRandom = RandomNumberGenerator.Create())
            {
                cryptoRandom.GetBytes(b);
            }
            return BigIntegerExtensions.FromUnsignedBigEndian(b);
        }
    }
}