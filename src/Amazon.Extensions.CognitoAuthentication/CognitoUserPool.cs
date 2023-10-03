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
using System.Threading.Tasks;
using System.Collections.Generic;

using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using System.Linq;
using Amazon.Extensions.CognitoAuthentication.Util;
using System.Threading;

namespace Amazon.Extensions.CognitoAuthentication
{
    public partial class CognitoUserPool
    {
        /// <summary>
        /// The poolID associated with the user pool. PoolID can only be configured 
        /// through the constructor, and once set it cannot be changed.
        /// </summary>
        public string PoolID { get; private set; }

        /// <summary>
        /// The clientID associated with the user pool. ClientID can only be configured 
        /// through the constructor, and once set it cannot be changed.
        /// </summary>
        public string ClientID { get; private set; }

        /// <summary>
        /// The ClientConfiguration associated with the user pool and the ClientID.
        /// </summary>
        private CognitoUserPoolClientConfiguration ClientConfiguration { get; set; }
        
        internal IAmazonCognitoIdentityProvider Provider { get; set; }

        private string ClientSecret { get; set; }

        /// <summary>
        /// Create an instance of CognitoUserPool
        /// </summary>
        /// <param name="poolID">PoolID of the associated user pool</param>
        /// <param name="clientID">ClientID for the associated user pool</param>
        /// <param name="provider">IAmazonCognitoIdentityProvider for the specified user pool</param>
        /// <param name="clientSecret">Client secret for the corresponding clientID, if exists</param>
        public CognitoUserPool(string poolID, 
                               string clientID,
                               IAmazonCognitoIdentityProvider provider, 
                               string clientSecret = null)
        {
            if(!poolID.Contains("_"))
            {
                throw new ArgumentException($"{nameof(poolID)} should be of the form <region>_<poolname>.", nameof(poolID));
            }

            this.PoolID = poolID;
            this.ClientID = clientID;
            this.ClientSecret = clientSecret;

            this.Provider = provider;

            if (this.Provider is AmazonCognitoIdentityProviderClient eventProvider)
            {
                eventProvider.BeforeRequestEvent += CognitoAuthHelper.ServiceClientBeforeRequestEvent;
            }
        }

        /// <summary>
        /// Signs up the user with the specified parameters using an asynchronous call
        /// </summary>
        /// <param name="userID">The userID of the user being created</param>
        /// <param name="password">The password of the user being created</param>
        /// <param name="userAttributes">The user attributes of the user being created</param>
        /// <param name="validationData">The validation data of the user being created</param>
        /// <returns>Returns the delivery details for the sign up request</returns>
        public Task SignUpAsync(string userID,
                           string password,
                           IDictionary<string, string> userAttributes,
                           IDictionary<string, string> validationData)
        {
            return SignUpAsync(userID, password, userAttributes, validationData, default);
        }

        /// <summary>
        /// Signs up the user with the specified parameters using an asynchronous call
        /// </summary>
        /// <param name="userID">The userID of the user being created</param>
        /// <param name="password">The password of the user being created</param>
        /// <param name="userAttributes">The user attributes of the user being created</param>
        /// <param name="validationData">The validation data of the user being created</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the delivery details for the sign up request</returns>
        public Task SignUpAsync(string userID,
                           string password,
                           IDictionary<string, string> userAttributes,
                           IDictionary<string, string> validationData,
                           CancellationToken cancellationToken)
        {
            SignUpRequest signUpUserRequest = CreateSignUpRequest(userID, password, userAttributes, validationData);

            return Provider.SignUpAsync(signUpUserRequest, cancellationToken);
        }

        /// <summary>
        /// Internal method to aid in the sign up flow for a new user
        /// </summary>
        /// <param name="userID">The userID of the user being created</param>
        /// <param name="password">The password of the user being created</param>
        /// <param name="userAttributes">The user attributes of the user being created</param>
        /// <param name="validationData">The validation data of the user being created</param>
        /// <returns>Returns the SignUpResponse for the sign up API request using the provided information</returns>
        private SignUpRequest CreateSignUpRequest(string userID,
                                              string password,
                                              IDictionary<string, string> userAttributes,
                                              IDictionary<string, string> validationData)
        {
            List<AttributeType> userAttributesList = null;
            if (userAttributes != null)
            {
                userAttributesList = CognitoAuthHelper.CreateAttributeList(userAttributes);
            }
            else
            {
                throw new ArgumentNullException(nameof(userAttributes));
            }

            List<AttributeType> validationDataList = 
                validationData != null ? CognitoAuthHelper.CreateAttributeList(validationData) : null;

            // Create User registration request
            SignUpRequest signUpUserRequest = new SignUpRequest()
            {
                Username = userID,
                Password = password,
                ClientId = ClientID,
                UserAttributes = userAttributesList,
                ValidationData = validationDataList
            };

            if (!string.IsNullOrEmpty(ClientSecret))
            {
                signUpUserRequest.SecretHash = CognitoAuthHelper.GetUserPoolSecretHash(userID, ClientID, ClientSecret);
            }

            return signUpUserRequest;
        }

        /// <summary>
        /// Gets a CognitoUser with no userID set
        /// </summary>
        /// <returns>Returns a user with no userID set</returns>
        public virtual CognitoUser GetUser()
        {
            return new CognitoUser(null, ClientID, this, Provider, ClientSecret);
        }

        /// <summary>
        /// Gets a CognitoUser with the corresponding userID
        /// </summary>
        /// <param name="userID">The userID of the corresponding user</param>
        /// <returns>Returns a CognitoUser with the corresponding userID</returns>
        public virtual CognitoUser GetUser(string userID)
        {
            if (string.IsNullOrEmpty(userID))
            {
                return GetUser();
            }

            return new CognitoUser(userID, ClientID, this, Provider, ClientSecret);
        }

        /// <summary>
        /// Gets a CognitoUser with the corresponding userID, status and attributes
        /// </summary>
        /// <param name="userID">The userID of the corresponding user</param>
        /// <param name="status">The status of the corresponding user</param>
        /// <param name="attributes">The attributes of the corresponding user</param>
        /// <returns>Returns a CognitoUser with the corresponding userID</returns>
        public virtual CognitoUser GetUser(string userID, string status, Dictionary<string,string> attributes)
        {
            if (string.IsNullOrEmpty(userID))
            {
                return GetUser();
            }

            return new CognitoUser(userID, ClientID, this, Provider, ClientSecret, status, userID, attributes);
        }

        /// <summary>
        /// Queries Cognito and returns the CognitoUser with the corresponding userID
        /// </summary>
        /// <param name="userID">The userID of the corresponding user</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a CognitoUser with the corresponding userID, with the Status and Attributes retrieved from Cognito.</returns>
        public virtual async Task<CognitoUser> FindByIdAsync(string userID)
        {
            return await FindByIdAsync(userID, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries Cognito and returns the CognitoUser with the corresponding userID
        /// </summary>
        /// <param name="userID">The userID of the corresponding user</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a CognitoUser with the corresponding userID, with the Status and Attributes retrieved from Cognito.</returns>
        public virtual async Task<CognitoUser> FindByIdAsync(string userID, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(userID))
                throw new ArgumentException(nameof(userID));

            try
            {
                var response = await Provider.AdminGetUserAsync(new AdminGetUserRequest
                {
                    Username = userID,
                    UserPoolId = this.PoolID
                }, cancellationToken).ConfigureAwait(false);

                return new CognitoUser(response.Username, ClientID, this, Provider, ClientSecret,
                    response.UserStatus.Value, response.Username,
                    response.UserAttributes.ToDictionary(attribute => attribute.Name, attribute => attribute.Value));

            }
            catch (UserNotFoundException)
            {
                return null;
            }
        }

        /// <summary>
        /// Queries Cognito and returns the PasswordPolicyType associated with the pool.
        /// </summary>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the PasswordPolicyType of the pool.</returns>
        public async Task<PasswordPolicyType> GetPasswordPolicyTypeAsync()
        {
            return await GetPasswordPolicyTypeAsync(default).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries Cognito and returns the PasswordPolicyType associated with the pool.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the PasswordPolicyType of the pool.</returns>
        public async Task<PasswordPolicyType> GetPasswordPolicyTypeAsync(CancellationToken cancellationToken)
        {
            var response = await Provider.DescribeUserPoolAsync(new DescribeUserPoolRequest
            {
                UserPoolId = this.PoolID
            }, cancellationToken).ConfigureAwait(false);

            return response.UserPool.Policies.PasswordPolicy;
        }

        /// <summary>
        /// Queries Cognito and returns the CognitoUserPoolClientConfiguration associated with the current pool client.
        /// Caches the value in the ClientConfiguration private property.
        /// </summary>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the PasswordPolicyType of the pool.</returns>
        public async Task<CognitoUserPoolClientConfiguration> GetUserPoolClientConfiguration()
        {
            return await GetUserPoolClientConfiguration(default).ConfigureAwait(false);
        }

        /// <summary>
        /// Queries Cognito and returns the CognitoUserPoolClientConfiguration associated with the current pool client.
        /// Caches the value in the ClientConfiguration private property.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the PasswordPolicyType of the pool.</returns>
        public async Task<CognitoUserPoolClientConfiguration> GetUserPoolClientConfiguration(CancellationToken cancellationToken)
        {
            if (ClientConfiguration == null)
            {
                var response = await Provider.DescribeUserPoolClientAsync(new DescribeUserPoolClientRequest
                {
                    ClientId = this.ClientID,
                    UserPoolId = this.PoolID
                }, cancellationToken).ConfigureAwait(false);

                ClientConfiguration = new CognitoUserPoolClientConfiguration(response.UserPoolClient.ReadAttributes, response.UserPoolClient.WriteAttributes);
            }

            return ClientConfiguration;
        }

        /// <summary>
        /// Signs up the user with the specified parameters using an asynchronous call end triggers a temporary password sms or email message.
        /// </summary>
        /// <param name="userID">The userID of the user being created</param>
        /// <param name="userAttributes">The user attributes of the user being created</param>
        /// <param name="validationData">The validation data of the user being created</param>
        /// <returns>Returns the delivery details for the sign up request</returns>
        public Task AdminSignupAsync(string userID,
                           IDictionary<string, string> userAttributes,
                           IDictionary<string, string> validationData)
        {
            return AdminSignupAsync(userID, userAttributes, validationData, default);
        }

        /// <summary>
        /// Signs up the user with the specified parameters using an asynchronous call end triggers a temporary password sms or email message.
        /// </summary>
        /// <param name="userID">The userID of the user being created</param>
        /// <param name="userAttributes">The user attributes of the user being created</param>
        /// <param name="validationData">The validation data of the user being created</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the delivery details for the sign up request</returns>
        public Task AdminSignupAsync(string userID,
                           IDictionary<string, string> userAttributes,
                           IDictionary<string, string> validationData,
                           CancellationToken cancellationToken)
        {
            AdminCreateUserRequest signUpUserRequest = CreateAdminSignUpRequest(userID, userAttributes, validationData);

            return Provider.AdminCreateUserAsync(signUpUserRequest, cancellationToken);
        }

        /// <summary>
        /// Internal method to aid in the admin sign up flow for a new user
        /// </summary>
        /// <param name="userID">The userID of the user being created</param>
        /// <param name="userAttributes">The user attributes of the user being created</param>
        /// <param name="validationData">The validation data of the user being created</param>
        /// <returns>Returns the SignUpResponse for the sign up API request using the provided information</returns>
        private AdminCreateUserRequest CreateAdminSignUpRequest(string userID,
                                              IDictionary<string, string> userAttributes,
                                              IDictionary<string, string> validationData)
        {
            List<AttributeType> userAttributesList = null;
            if (userAttributes != null)
            {
                userAttributesList = CognitoAuthHelper.CreateAttributeList(userAttributes);
            }
            else
            {
                throw new ArgumentNullException(nameof(userAttributes));
            }

            List<AttributeType> validationDataList =
                validationData != null ? CognitoAuthHelper.CreateAttributeList(validationData) : null;

            // Create User registration request
            return new AdminCreateUserRequest()
            {
                Username = userID,
                UserPoolId = this.PoolID,
                UserAttributes = userAttributesList,
                ValidationData = validationDataList
            };
        }

        /// <summary>
        /// Resets the user's password to the specified <paramref name="newPassword"/> after
        /// validating the given password reset <paramref name="token"/>.
        /// </summary>
        /// <param name="userID">The ID of user whose password should be reset.</param>
        /// <param name="token">The password reset token to verify.</param>
        /// <param name="newPassword">The new password to set if reset token verification succeeds.</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="ConfirmForgotPasswordResponse"/>.
        /// </returns>
        public Task ConfirmForgotPassword(string userID, string token, string newPassword, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var request = new ConfirmForgotPasswordRequest
            {
                Username = userID,
                ClientId = ClientID,
                ConfirmationCode = token,
                Password = newPassword,

            };

            if (!string.IsNullOrEmpty(ClientSecret))
            {
                request.SecretHash = CognitoAuthHelper.GetUserPoolSecretHash(userID, ClientID, ClientSecret);
            }

            return Provider.ConfirmForgotPasswordAsync(request, cancellationToken);
        }
    }
}
