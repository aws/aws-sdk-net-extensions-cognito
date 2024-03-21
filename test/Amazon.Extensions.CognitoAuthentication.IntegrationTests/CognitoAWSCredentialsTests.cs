﻿/*
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
using System.Threading;
using Xunit;

using Amazon;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentity.Model;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

using Amazon.Extensions.CognitoAuthentication.IntegrationTests;

namespace CognitoAuthentication.IntegrationTests.NET45
{
    public class CognitoCredentialsTests : AuthenticationConfirmUserTests
    {
        private string policyArn;
        private string roleName;
        private string identityPoolId;

        private AmazonCognitoIdentityClient identityClient;
        AWSCredentials clientCredentials = FallbackCredentialsFactory.GetCredentials();
        private AmazonIdentityManagementServiceClient managementClient;

        [Fact]
        //Tests GetCognitoAWSCredentials
        public async void TestGetCognitoAWSCredentials()
        {
            string password = "PassWord1!";
            string poolRegion = user.UserPool.PoolID.Substring(0, user.UserPool.PoolID.IndexOf("_"));
            string providerName = "cognito-idp." + poolRegion + ".amazonaws.com/" + user.UserPool.PoolID;

            AuthFlowResponse context =
                await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
                {
                    Password = password
                }).ConfigureAwait(false);

            //Create identity pool
            identityClient = new AmazonCognitoIdentityClient(clientCredentials, clientRegion);
            CreateIdentityPoolResponse poolResponse =
                await identityClient.CreateIdentityPoolAsync(new CreateIdentityPoolRequest()
                {
                    AllowUnauthenticatedIdentities = false,
                    CognitoIdentityProviders = new List<CognitoIdentityProviderInfo>()
                    {
                        new CognitoIdentityProviderInfo() { ProviderName = providerName, ClientId = user.ClientID}
                    },
                    IdentityPoolName = "TestIdentityPool" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"),

                }).ConfigureAwait(false);
            identityPoolId = poolResponse.IdentityPoolId;

            //Create role for identity pool
            managementClient = new AmazonIdentityManagementServiceClient(clientCredentials, clientRegion);
            CreateRoleResponse roleResponse = managementClient.CreateRoleAsync(new CreateRoleRequest()
            {
                RoleName = "_TestRole_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"),
                AssumeRolePolicyDocument = "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect" +
                "\": \"Allow\",\"Principal\": {\"Federated\": \"cognito-identity.amazonaws.com\"}," +
                "\"Action\": \"sts:AssumeRoleWithWebIdentity\",\"Condition\": {\"StringEquals\": {" +
                "\"cognito-identity.amazonaws.com:aud\": [\"" + identityPoolId + "\"]}}}]}"
            }).Result;
            roleName = roleResponse.Role.RoleName;

            //Create and attach policy for role
            CreatePolicyResponse policyResponse = managementClient.CreatePolicyAsync(new CreatePolicyRequest()
            {
                PolicyDocument = "{\"Version\": \"2012-10-17\",\"Statement\": " +
                "[{\"Effect\": \"Allow\",\"Action\": [\"mobileanalytics:PutEvents\",\"cog" +
                "nito-sync:*\",\"cognito-identity:*\",\"s3:*\"],\"Resource\": [\"*\"]}]}",
                PolicyName = "_Cognito_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"),
            }).Result;
            policyArn = policyResponse.Policy.Arn;

            AttachRolePolicyRequest attachRequest = new AttachRolePolicyRequest()
            {
                PolicyArn = policyArn,
                RoleName = roleName
            };
            AttachRolePolicyResponse attachRolePolicyResponse = managementClient.AttachRolePolicyAsync(attachRequest).Result;

            //Set the role for the identity pool
            await identityClient.SetIdentityPoolRolesAsync(new SetIdentityPoolRolesRequest()
            {
                IdentityPoolId = identityPoolId,
                Roles = new Dictionary<string, string>()
                {
                    { "authenticated", roleResponse.Role.Arn },
                    { "unauthenticated", roleResponse.Role.Arn }
                },
            }).ConfigureAwait(false);
            
            //Create and test credentials
            CognitoAWSCredentials credentials = user.GetCognitoAWSCredentials(identityPoolId, clientRegion);

            using (var client = new AmazonS3Client(credentials, Amazon.RegionEndpoint.USEast1))
            {
                ListBucketsResponse bucketsResponse = null;

                for (var tries = 0; tries < 5; tries++)
                {
                    try
                    {
                        bucketsResponse = await client.ListBucketsAsync(new ListBucketsRequest()).ConfigureAwait(false);
                        break;
                    }
                    catch (Exception ex)
                    {
                        System.Threading.Thread.Sleep(5000);
                    }
                }

                Assert.True(null != bucketsResponse, "Failed to list buckets after 5 tries");
                Assert.Equal(bucketsResponse.HttpStatusCode, System.Net.HttpStatusCode.OK);
            }
        }

        /// <summary>
        /// Internal method that cleans up the created identity pool (along with associated 
        /// clients/roles) for testing
        /// </summary>
        public override void Dispose()
        {
            try
            {
                identityClient.DeleteIdentityPoolAsync(new DeleteIdentityPoolRequest()
                {
                    IdentityPoolId = identityPoolId
                }).GetAwaiter().GetResult();

                managementClient.DetachRolePolicyAsync(new DetachRolePolicyRequest()
                {
                    PolicyArn = policyArn,
                    RoleName = roleName
                }).GetAwaiter().GetResult();

                managementClient.DeletePolicyAsync(new DeletePolicyRequest()
                {
                    PolicyArn = policyArn
                }).GetAwaiter().GetResult();

                managementClient.DeleteRoleAsync(new DeleteRoleRequest()
                {
                    RoleName = roleName
                }).GetAwaiter().GetResult();

                identityClient.Dispose();
                managementClient.Dispose();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
            }

            base.Dispose();
        }
    }
}
