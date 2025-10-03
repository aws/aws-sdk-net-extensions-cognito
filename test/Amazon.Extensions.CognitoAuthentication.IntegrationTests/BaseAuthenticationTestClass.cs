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
using System.Collections.Generic;

using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication.Util;

namespace Amazon.Extensions.CognitoAuthentication.IntegrationTests
{
    /// <summary>
    /// Base class to be used for authentication integrations tests
    /// Allows for child classes to create, sign up, or confirm users
    /// </summary>
    public partial class BaseAuthenticationTestClass : IDisposable
    {
        protected AmazonCognitoIdentityProviderClient provider;
        protected CognitoUserPool pool;
        protected CognitoUser user;
        private readonly string _testInstanceId;

        static BaseAuthenticationTestClass()
        {
            AWSConfigs.RegionEndpoint = RegionEndpoint.USEast1;
        }

        public BaseAuthenticationTestClass()
        {
            _testInstanceId = Guid.NewGuid().ToString("N")[..8]; // Short unique identifier
            
            try
            {
                UserPoolPolicyType passwordPolicy = new UserPoolPolicyType();
                List<SchemaAttributeType> requiredAttributes = new List<SchemaAttributeType>();
                List<string> verifiedAttributes = new List<string>();

                provider = new AmazonCognitoIdentityProviderClient();

                AdminCreateUserConfigType adminCreateUser = new AdminCreateUserConfigType()
                {
                    UnusedAccountValidityDays = 8,
                    AllowAdminCreateUserOnly = false
                };

                passwordPolicy.PasswordPolicy = new PasswordPolicyType()
                {
                    MinimumLength = 8,
                    RequireNumbers = true,
                    RequireSymbols = true,
                    RequireUppercase = true,
                    RequireLowercase = true
                };

                SchemaAttributeType tempSchema = new SchemaAttributeType()
                {
                    Required = true,
                    Name = CognitoConstants.UserAttrEmail,
                    AttributeDataType = AttributeDataType.String
                };
                requiredAttributes.Add(tempSchema);
                verifiedAttributes.Add(CognitoConstants.UserAttrEmail);

                CreateUserPoolRequest createPoolRequest = new CreateUserPoolRequest
                {
                    PoolName = "testPool_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"),
                    Policies = passwordPolicy,
                    Schema = requiredAttributes,
                    AdminCreateUserConfig = adminCreateUser,
                    MfaConfiguration = "OFF",
                    AutoVerifiedAttributes = verifiedAttributes,
                    DeviceConfiguration = new DeviceConfigurationType()
                    {
                        ChallengeRequiredOnNewDevice = false,
                        DeviceOnlyRememberedOnUserPrompt = false
                    }
                };
                CreateUserPoolResponse createPoolResponse = provider.CreateUserPoolAsync(createPoolRequest).Result;
                UserPoolType userPoolCreated = createPoolResponse.UserPool;

                CreateUserPoolClientRequest clientRequest = new CreateUserPoolClientRequest()
                {
                    ClientName = "App_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"),
                    UserPoolId = userPoolCreated.Id,
                    GenerateSecret = false,

                };
                CreateUserPoolClientResponse clientResponse = provider.CreateUserPoolClientAsync(clientRequest).Result;
                UserPoolClientType clientCreated = clientResponse.UserPoolClient;

                pool = new CognitoUserPool(userPoolCreated.Id, clientCreated.ClientId, provider, "");
                
                // Log user pool creation
                Console.WriteLine($"[{_testInstanceId}] Created user pool: {createPoolRequest.PoolName} (ID: {userPoolCreated.Id}) at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{_testInstanceId}] Constructor failed: {ex.Message}");
                Dispose(); // Clean up any resources that were created
                throw;     // Re-throw the original exception so test fails as expected
            }
        }

        /// <summary>
        /// Internal method that cleans up the created user pool (along with associated client/user) 
        /// for testing
        /// </summary>
        public virtual void Dispose()
        {
            // Handle partial construction - pool might be null if constructor failed early
            if (pool?.PoolID != null)
            {
                Console.WriteLine($"[{_testInstanceId}] Disposing user pool: {pool.PoolID} at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
                try
                {
                    provider?.DeleteUserPoolAsync(new DeleteUserPoolRequest()
                    {
                        UserPoolId = pool.PoolID
                    }).Wait();

                    Console.WriteLine($"[{_testInstanceId}] Successfully disposed user pool: {pool.PoolID}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{_testInstanceId}] ERROR disposing user pool {pool.PoolID}: {ex.Message}");
                    System.Diagnostics.Debug.WriteLine($"Full exception details: {ex}");
                }
            }
            else
            {
                Console.WriteLine($"[{_testInstanceId}] Dispose called but no user pool to clean up (partial construction)");
            }

            // Always dispose the provider if it exists
            try
            {
                provider?.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{_testInstanceId}] ERROR disposing provider: {ex.Message}");
            }
        }
    }
}
