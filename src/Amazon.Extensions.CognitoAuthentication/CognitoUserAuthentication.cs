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

/* The following knowledge base was used as guide for the implementation 
 * of some of the below Cognito challenges.
 * https://aws.amazon.com/premiumsupport/knowledge-center/cognito-user-pool-remembered-devices/?nc1=h_ls
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication.Util;

namespace Amazon.Extensions.CognitoAuthentication
{
    partial class CognitoUser
    {
        /// <summary>
        /// Initiates the asynchronous SRP authentication flow
        /// </summary>
        /// <param name="srpRequest">InitiateSrpAuthRequest object containing the necessary parameters to
        /// create an InitiateAuthAsync API call for SRP authentication</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithSrpAuthAsync(InitiateSrpAuthRequest srpRequest)
        {
            return await StartWithSrpAuthAsync(srpRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Initiates the asynchronous SRP authentication flow
        /// </summary>
        /// <param name="srpRequest">InitiateSrpAuthRequest object containing the necessary parameters to
        /// create an InitiateAuthAsync API call for SRP authentication</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithSrpAuthAsync(InitiateSrpAuthRequest srpRequest, CancellationToken cancellationToken)
        {
            if (srpRequest == null || string.IsNullOrEmpty(srpRequest.Password))
            {
                throw new ArgumentNullException("Password required for authentication.", "srpRequest");
            }

            Tuple<BigInteger, BigInteger> tupleAa = AuthenticationHelper.CreateAaTuple();
            InitiateAuthRequest initiateRequest = CreateSrpAuthRequest(tupleAa);

            if (srpRequest.IsCustomAuthFlow)
            {
                initiateRequest.AuthFlow = AuthFlowType.CUSTOM_AUTH;
                initiateRequest.AuthParameters.Add(CognitoConstants.ChlgParamChallengeName, CognitoConstants.ChlgParamSrpA);
            }
            InitiateAuthResponse initiateResponse = await Provider.InitiateAuthAsync(initiateRequest, cancellationToken).ConfigureAwait(false);
            UpdateUsernameAndSecretHash(initiateResponse.ChallengeParameters);

            RespondToAuthChallengeRequest challengeRequest =
                CreateSrpPasswordVerifierAuthRequest(initiateResponse, srpRequest.Password, tupleAa);

            if (srpRequest.ClientMetadata != null)
            {
                challengeRequest.ClientMetadata = new Dictionary<string, string>(srpRequest.ClientMetadata);
            }

            bool challengeResponsesValid = challengeRequest != null && challengeRequest.ChallengeResponses != null;
            bool deviceKeyValid = Device != null && !string.IsNullOrEmpty(Device.DeviceKey);

            if (challengeResponsesValid && deviceKeyValid)
            {
                challengeRequest.ChallengeResponses[CognitoConstants.ChlgParamDeviceKey] = Device.DeviceKey;
            }

            RespondToAuthChallengeResponse verifierResponse =
                await Provider.RespondToAuthChallengeAsync(challengeRequest, cancellationToken).ConfigureAwait(false);
            var isDeviceAuthRequest = verifierResponse.AuthenticationResult == null && (!string.IsNullOrEmpty(srpRequest.DeviceGroupKey)
                || !string.IsNullOrEmpty(srpRequest.DevicePass));
            #region Device-level authentication
            if (isDeviceAuthRequest)
            {
                if (string.IsNullOrEmpty(srpRequest.DeviceGroupKey) || string.IsNullOrEmpty(srpRequest.DevicePass))
                {
                    throw new ArgumentNullException("Device Group Key and Device Pass required for authentication.", "srpRequest");
                }

                #region Device SRP Auth
                var deviceAuthRequest = CreateDeviceSrpAuthRequest(verifierResponse, tupleAa);
                var deviceAuthResponse = await Provider.RespondToAuthChallengeAsync(deviceAuthRequest, cancellationToken).ConfigureAwait(false); 
                #endregion

                #region Device Password Verifier
                var devicePasswordChallengeRequest = CreateDevicePasswordVerifierAuthRequest(deviceAuthResponse, srpRequest.DeviceGroupKey, srpRequest.DevicePass, tupleAa);
                verifierResponse = await Provider.RespondToAuthChallengeAsync(devicePasswordChallengeRequest, cancellationToken).ConfigureAwait(false);
                #endregion

            }
            #endregion

            UpdateSessionIfAuthenticationComplete(verifierResponse.ChallengeName, verifierResponse.AuthenticationResult);

            return new AuthFlowResponse(verifierResponse.Session,
                verifierResponse.AuthenticationResult,
                verifierResponse.ChallengeName,
                verifierResponse.ChallengeParameters,
                new Dictionary<string, string>(verifierResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Internal method which responds to the DEVICE_SRP_AUTH challenge in SRP authentication
        /// </summary>
        /// <param name="challenge">The response from the PASSWORD_VERIFIER challenge</param>
        /// <param name="tupleAa">Tuple of BigIntegers containing the A,a pair for the SRP protocol flow</param>
        /// <returns></returns>
        private RespondToAuthChallengeRequest CreateDeviceSrpAuthRequest(RespondToAuthChallengeResponse challenge, Tuple<BigInteger, BigInteger> tupleAa)
        {
            
            RespondToAuthChallengeRequest authChallengeRequest = new RespondToAuthChallengeRequest()
            {
                ChallengeName = ChallengeNameType.DEVICE_SRP_AUTH,
                ClientId = ClientID,
                Session = challenge.Session,
                ChallengeResponses = new Dictionary<string, string>
                {
                    {CognitoConstants.ChlgParamUsername, Username},
                    {CognitoConstants.ChlgParamDeviceKey, Device.DeviceKey},
                    {CognitoConstants.ChlgParamSrpA, tupleAa.Item1.ToString("X") },
                }

            };
            if (!string.IsNullOrEmpty(SecretHash))
            {
                authChallengeRequest.ChallengeResponses.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }
            return authChallengeRequest;
        }


        /// <summary>
        /// Internal method which responds to the DEVICE_PASSWORD_VERIFIER challenge in SRP authentication
        /// </summary>
        /// <param name="challenge">Response from the InitiateAuth challenge</param>
        /// <param name="deviceKeyGroup">Group Key for the CognitoDevice, needed for authentication</param>
        /// <param name="devicePassword">Password for the CognitoDevice, needed for authentication</param>
        /// <param name="tupleAa">Tuple of BigIntegers containing the A,a pair for the SRP protocol flow</param>
        /// <returns>Returns the RespondToAuthChallengeRequest for an SRP authentication flow</returns>
        private RespondToAuthChallengeRequest CreateDevicePasswordVerifierAuthRequest(RespondToAuthChallengeResponse challenge,
                                                                                   string deviceKeyGroup,
                                                                                   string devicePassword,
                                                                                   Tuple<BigInteger, BigInteger> tupleAa)
        {
            string deviceKey = challenge.ChallengeParameters[CognitoConstants.ChlgParamDeviceKey];
            string username = challenge.ChallengeParameters[CognitoConstants.ChlgParamUsername];
            string secretBlock = challenge.ChallengeParameters[CognitoConstants.ChlgParamSecretBlock];
            string salt = challenge.ChallengeParameters[CognitoConstants.ChlgParamSalt];
            BigInteger srpb = BigIntegerExtensions.FromUnsignedLittleEndianHex(challenge.ChallengeParameters[CognitoConstants.ChlgParamSrpB]);

            if ((srpb.TrueMod(AuthenticationHelper.N)).Equals(BigInteger.Zero))
            {
                throw new ArgumentException("SRP error, B mod N cannot be zero.", "challenge");
            }

            string timeStr = DateTime.UtcNow.ToString("ddd MMM d HH:mm:ss \"UTC\" yyyy", CultureInfo.InvariantCulture);

            var claimBytes = AuthenticationHelper.AuthenticateDevice(username, deviceKey, devicePassword, deviceKeyGroup, salt,
                challenge.ChallengeParameters[CognitoConstants.ChlgParamSrpB], secretBlock, timeStr, tupleAa);


            string claimB64 = Convert.ToBase64String(claimBytes);
            Dictionary<string, string> srpAuthResponses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                {CognitoConstants.ChlgParamPassSecretBlock, secretBlock},
                {CognitoConstants.ChlgParamPassSignature, claimB64},
                {CognitoConstants.ChlgParamUsername, username },
                {CognitoConstants.ChlgParamTimestamp, timeStr },
                {CognitoConstants.ChlgParamDeviceKey, Device.DeviceKey }
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                srpAuthResponses.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }

            RespondToAuthChallengeRequest authChallengeRequest = new RespondToAuthChallengeRequest()
            {
                ChallengeName = challenge.ChallengeName,
                ClientId = ClientID,
                Session = challenge.Session,
                ChallengeResponses = srpAuthResponses
            };

            return authChallengeRequest;
        }

        /// <summary>
        /// Initiates the asynchronous custom authentication flow
        /// </summary>
        /// <param name="customRequest">InitiateCustomAuthRequest object containing the necessary parameters to
        /// create an InitiateAuthAsync API call for custom authentication</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithCustomAuthAsync(InitiateCustomAuthRequest customRequest)
        {
            return await StartWithCustomAuthAsync(customRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Initiates the asynchronous custom authentication flow
        /// </summary>
        /// <param name="customRequest">InitiateCustomAuthRequest object containing the necessary parameters to
        /// create an InitiateAuthAsync API call for custom authentication</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithCustomAuthAsync(InitiateCustomAuthRequest customRequest, CancellationToken cancellationToken)
        {
            InitiateAuthRequest authRequest = new InitiateAuthRequest()
            {
                AuthFlow = AuthFlowType.CUSTOM_AUTH,
                AuthParameters = new Dictionary<string, string>(customRequest.AuthParameters),
                ClientId = ClientID,
                ClientMetadata = new Dictionary<string, string>(customRequest.ClientMetadata)
            };

            InitiateAuthResponse initiateResponse = await Provider.InitiateAuthAsync(authRequest, cancellationToken).ConfigureAwait(false);
            UpdateUsernameAndSecretHash(initiateResponse.ChallengeParameters);

            UpdateSessionIfAuthenticationComplete(initiateResponse.ChallengeName, initiateResponse.AuthenticationResult);

            return new AuthFlowResponse(initiateResponse.Session,
                initiateResponse.AuthenticationResult,
                initiateResponse.ChallengeName,
                initiateResponse.ChallengeParameters,
                new Dictionary<string, string>(initiateResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Uses the properties of the RespondToCustomChallengeRequest object to respond to the current 
        /// custom authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="customRequest">RespondToCustomChallengeRequest object containing the necessary parameters to
        /// respond to the current custom authentication challenge</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> RespondToCustomAuthAsync(RespondToCustomChallengeRequest customRequest)
        {
            return await RespondToCustomAuthAsync(customRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Uses the properties of the RespondToCustomChallengeRequest object to respond to the current 
        /// custom authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="customRequest">RespondToCustomChallengeRequest object containing the necessary parameters to
        /// respond to the current custom authentication challenge</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> RespondToCustomAuthAsync(RespondToCustomChallengeRequest customRequest, CancellationToken cancellationToken)
        {
            RespondToAuthChallengeRequest request = new RespondToAuthChallengeRequest()
            {
                ChallengeName = ChallengeNameType.CUSTOM_CHALLENGE,
                ClientId = ClientID,
                ChallengeResponses = new Dictionary<string, string>(customRequest.ChallengeParameters),
                ClientMetadata = new Dictionary<string, string>(customRequest.ClientMetadata),
                Session = customRequest.SessionID
            };

            RespondToAuthChallengeResponse authResponse =
                await Provider.RespondToAuthChallengeAsync(request, cancellationToken).ConfigureAwait(false);

            UpdateSessionIfAuthenticationComplete(authResponse.ChallengeName, authResponse.AuthenticationResult);

            return new AuthFlowResponse(authResponse.Session,
                authResponse.AuthenticationResult,
                authResponse.ChallengeName,
                authResponse.ChallengeParameters,
                new Dictionary<string, string>(authResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Generates a DeviceSecretVerifierConfigType object for a device associated with a CognitoUser for SRP Authentication
        /// </summary>
        /// <param name="deviceGroupKey">The DeviceKey Group for the associated CognitoDevice</param>
        /// <param name="deviceKey">The DeviceKey for the associated CognitoDevice</param>
        /// <param name="devicePass">The random password for the associated CognitoDevice</param>
        /// <returns></returns>
        public DeviceSecretVerifierConfigType GenerateDeviceVerifier(string deviceGroupKey, string devicePass, string username)
        {
            return AuthenticationHelper.GenerateDeviceVerifier(deviceGroupKey, devicePass, username);
        }

        /// <summary>
        /// Sends a confirmation request to Cognito for a new CognitoDevice
        /// </summary>
        /// <param name="accessToken">The user pool access token for from the InitiateAuth or other challenge response</param>
        /// <param name="deviceKey">The device key for the associated CognitoDevice</param>
        /// <param name="deviceName">The friendly name to be associated with the corresponding CognitoDevice</param>
        /// <param name="passwordVerifier">The password verifier generated from GenerateDeviceVerifier for the corresponding CognitoDevice</param>
        /// <param name="salt">The salt generated from GenerateDeviceVerifier for the corresponding CognitoDevice</param>
        /// <returns></returns>
        public async Task<ConfirmDeviceResponse> ConfirmDeviceAsync(string accessToken, string deviceKey, string deviceName, string passwordVerifier, string salt)
        {
            return await ConfirmDeviceAsync(accessToken, deviceKey, deviceName, passwordVerifier, salt, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a confirmation request to Cognito for a new CognitoDevice
        /// </summary>
        /// <param name="accessToken">The user pool access token for from the InitiateAuth or other challenge response</param>
        /// <param name="deviceKey">The device key for the associated CognitoDevice</param>
        /// <param name="deviceName">The friendly name to be associated with the corresponding CognitoDevice</param>
        /// <param name="passwordVerifier">The password verifier generated from GenerateDeviceVerifier for the corresponding CognitoDevice</param>
        /// <param name="salt">The salt generated from GenerateDeviceVerifier for the corresponding CognitoDevice</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns></returns>
        public async Task<ConfirmDeviceResponse> ConfirmDeviceAsync(string accessToken, string deviceKey, string deviceName, string passwordVerifier, string salt, CancellationToken cancellationToken)
        {
            var request = new ConfirmDeviceRequest
            {
                AccessToken = accessToken,
                DeviceKey = deviceKey,
                DeviceName = deviceName,
                DeviceSecretVerifierConfig = new DeviceSecretVerifierConfigType
                {
                    PasswordVerifier = passwordVerifier,
                    Salt = salt
                }
            };

            return await Provider.ConfirmDeviceAsync(request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the remembered status for a given CognitoDevice
        /// </summary>
        /// <param name="accessToken">The user pool access token for from the InitiateAuth or other challenge response</param>
        /// <param name="deviceKey">The device key for the associated CognitoDevice</param>
        /// <param name="deviceRememberedStatus">The device remembered status for the associated CognitoDevice</param>
        /// <returns></returns>
        public async Task<UpdateDeviceStatusResponse> UpdateDeviceStatusAsync(string accessToken, string deviceKey, string deviceRememberedStatus)
        {
            return await UpdateDeviceStatusAsync(accessToken, deviceKey, deviceRememberedStatus, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the remembered status for a given CognitoDevice
        /// </summary>
        /// <param name="accessToken">The user pool access token for from the InitiateAuth or other challenge response</param>
        /// <param name="deviceKey">The device key for the associated CognitoDevice</param>
        /// <param name="deviceRememberedStatus">The device remembered status for the associated CognitoDevice</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns></returns>
        public async Task<UpdateDeviceStatusResponse> UpdateDeviceStatusAsync(string accessToken, string deviceKey, string deviceRememberedStatus, CancellationToken cancellationToken)
        {
            var request = new UpdateDeviceStatusRequest
            {
                AccessToken = accessToken,
                DeviceKey = deviceKey,
                DeviceRememberedStatus = deviceRememberedStatus
            };

            return await Provider.UpdateDeviceStatusAsync(request, cancellationToken).ConfigureAwait(false);
        }
        /// <summary>
        /// Uses the properties of the RespondToSmsMfaRequest object to respond to the current MFA 
        /// authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="smsMfaRequest">RespondToSmsMfaRequest object containing the necessary parameters to
        /// respond to the current SMS MFA authentication challenge</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> RespondToSmsMfaAuthAsync(RespondToSmsMfaRequest smsMfaRequest)
        {
            return await RespondToSmsMfaAuthAsync(smsMfaRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Uses the properties of the RespondToSmsMfaRequest object to respond to the current MFA 
        /// authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="smsMfaRequest">RespondToSmsMfaRequest object containing the necessary parameters to
        /// respond to the current SMS MFA authentication challenge</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> RespondToSmsMfaAuthAsync(RespondToSmsMfaRequest smsMfaRequest, CancellationToken cancellationToken)
        {
            return await RespondToMfaAuthAsync(smsMfaRequest, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Uses the properties of the RespondToSmsMfaRequest object to respond to the current MFA 
        /// authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="mfaRequest">RespondToMfaRequest object containing the necessary parameters to
        /// respond to the current MFA authentication challenge</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public async Task<AuthFlowResponse> RespondToMfaAuthAsync(RespondToMfaRequest mfaRequest)
        {
            return await RespondToMfaAuthAsync(mfaRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Uses the properties of the RespondToSmsMfaRequest object to respond to the current MFA 
        /// authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="mfaRequest">RespondToMfaRequest object containing the necessary parameters to
        /// respond to the current MFA authentication challenge</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public async Task<AuthFlowResponse> RespondToMfaAuthAsync(RespondToMfaRequest mfaRequest, CancellationToken cancellationToken)
        {
            RespondToAuthChallengeRequest challengeRequest = new RespondToAuthChallengeRequest
            {
                ChallengeResponses = new Dictionary<string, string>
                    {
                        { GetChallengeParamCodeName(mfaRequest.ChallengeNameType), mfaRequest.MfaCode},
                        { CognitoConstants.ChlgParamUsername, Username }
                    },
                Session = mfaRequest.SessionID,
                ClientId = ClientID,
                ChallengeName = mfaRequest.ChallengeNameType
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                challengeRequest.ChallengeResponses.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }

            RespondToAuthChallengeResponse challengeResponse =
                await Provider.RespondToAuthChallengeAsync(challengeRequest, cancellationToken).ConfigureAwait(false);

            UpdateSessionIfAuthenticationComplete(challengeResponse.ChallengeName, challengeResponse.AuthenticationResult);

            return new AuthFlowResponse(challengeResponse.Session,
                challengeResponse.AuthenticationResult,
                challengeResponse.ChallengeName,
                challengeResponse.ChallengeParameters,
                new Dictionary<string, string>(challengeResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Internal method which works out which Challenge Parameter to use based on the ChallengeTypeName
        /// </summary>
        /// <param name="challengeNameType">ChallengeTypeName from the challenge</param>
        /// <returns>Returns the CognitoConstants for the given ChallengeTypeName</returns>
        private string GetChallengeParamCodeName(ChallengeNameType challengeNameType )
        {
            if (challengeNameType == ChallengeNameType.SMS_MFA) return CognitoConstants.ChlgParamSmsMfaCode;
            if (challengeNameType == ChallengeNameType.SOFTWARE_TOKEN_MFA) return CognitoConstants.ChlgParamSoftwareTokenMfaCode;

            return null;
        }

        /// <summary>
        /// Uses the properties of the RespondToNewPasswordRequiredRequest object to respond to the current new 
        /// password required authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="newPasswordRequest">RespondToNewPasswordRequiredRequest object containing the necessary 
        /// parameters to respond to the current SMS MFA authentication challenge</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual Task<AuthFlowResponse> RespondToNewPasswordRequiredAsync(RespondToNewPasswordRequiredRequest newPasswordRequest)
        {
            return RespondToNewPasswordRequiredAsync(newPasswordRequest, null, default);
        }

        /// <summary>
        /// Uses the properties of the RespondToNewPasswordRequiredRequest object to respond to the current new 
        /// password required authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="newPasswordRequest">RespondToNewPasswordRequiredRequest object containing the necessary 
        /// parameters to respond to the current SMS MFA authentication challenge</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual Task<AuthFlowResponse> RespondToNewPasswordRequiredAsync(RespondToNewPasswordRequiredRequest newPasswordRequest, CancellationToken cancellationToken)
        {
            return RespondToNewPasswordRequiredAsync(newPasswordRequest, null, cancellationToken);
        }

        /// <summary>
        /// Uses the properties of the RespondToNewPasswordRequiredRequest object to respond to the current new 
        /// password required authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="newPasswordRequest">RespondToNewPasswordRequiredRequest object containing the necessary 
        /// <param name="requiredAttributes">Optional dictionnary of attributes that may be required by the user pool
        /// Each attribute key must be prefixed by "userAttributes."
        /// parameters to respond to the current SMS MFA authentication challenge</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> RespondToNewPasswordRequiredAsync(RespondToNewPasswordRequiredRequest newPasswordRequest, Dictionary<string, string> requiredAttributes)
        {
            return await RespondToNewPasswordRequiredAsync(newPasswordRequest, requiredAttributes, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Uses the properties of the RespondToNewPasswordRequiredRequest object to respond to the current new 
        /// password required authentication challenge using an asynchronous call
        /// </summary>
        /// <param name="newPasswordRequest">RespondToNewPasswordRequiredRequest object containing the necessary 
        /// <param name="requiredAttributes">Optional dictionnary of attributes that may be required by the user pool
        /// Each attribute key must be prefixed by "userAttributes."
        /// parameters to respond to the current SMS MFA authentication challenge</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> RespondToNewPasswordRequiredAsync(RespondToNewPasswordRequiredRequest newPasswordRequest, Dictionary<string, string> requiredAttributes, CancellationToken cancellationToken)
        {
            var challengeResponses = new Dictionary<string, string>()
            {
                { CognitoConstants.ChlgParamNewPassword, newPasswordRequest.NewPassword},
                { CognitoConstants.ChlgParamUsername, Username }
            };

            if (requiredAttributes != null)
            {
                foreach (KeyValuePair<string, string> attribute in requiredAttributes)
                {
                    challengeResponses.Add(attribute.Key, attribute.Value);
                }
            }

            RespondToAuthChallengeRequest challengeRequest = new RespondToAuthChallengeRequest
            {
                
                ChallengeResponses = challengeResponses,
                Session = newPasswordRequest.SessionID,
                ClientId = ClientID,
                ChallengeName = ChallengeNameType.NEW_PASSWORD_REQUIRED
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                challengeRequest.ChallengeResponses.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }

            RespondToAuthChallengeResponse challengeResponse =
                await Provider.RespondToAuthChallengeAsync(challengeRequest, cancellationToken).ConfigureAwait(false);

            UpdateSessionIfAuthenticationComplete(challengeResponse.ChallengeName, challengeResponse.AuthenticationResult);

            return new AuthFlowResponse(challengeResponse.Session,
                challengeResponse.AuthenticationResult,
                challengeResponse.ChallengeName,
                challengeResponse.ChallengeParameters,
                new Dictionary<string, string>(challengeResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Initiates the asynchronous refresh token authentication flow
        /// </summary>
        /// <param name="refreshTokenRequest">InitiateRefreshTokenAuthRequest object containing the necessary 
        /// parameters to initiate the refresh token authentication flow</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithRefreshTokenAuthAsync(InitiateRefreshTokenAuthRequest refreshTokenRequest)
        {
            return await StartWithRefreshTokenAuthAsync(refreshTokenRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Initiates the asynchronous refresh token authentication flow
        /// </summary>
        /// <param name="refreshTokenRequest">InitiateRefreshTokenAuthRequest object containing the necessary 
        /// parameters to initiate the refresh token authentication flow</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithRefreshTokenAuthAsync(InitiateRefreshTokenAuthRequest refreshTokenRequest, CancellationToken cancellationToken)
        {
            InitiateAuthRequest initiateAuthRequest = CreateRefreshTokenAuthRequest(refreshTokenRequest.AuthFlowType);

            InitiateAuthResponse initiateResponse =
                await Provider.InitiateAuthAsync(initiateAuthRequest, cancellationToken).ConfigureAwait(false);

            // Service does not return the refresh token. Hence, set it to the old refresh token that was used.
            if (string.IsNullOrEmpty(initiateResponse.ChallengeName) && string.IsNullOrEmpty(initiateResponse.AuthenticationResult.RefreshToken))
                initiateResponse.AuthenticationResult.RefreshToken = initiateAuthRequest.AuthParameters[CognitoConstants.ChlgParamRefreshToken];

            UpdateSessionIfAuthenticationComplete(initiateResponse.ChallengeName, initiateResponse.AuthenticationResult);

            return new AuthFlowResponse(initiateResponse.Session,
                initiateResponse.AuthenticationResult,
                initiateResponse.ChallengeName,
                initiateResponse.ChallengeParameters,
                new Dictionary<string, string>(initiateResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Initiates the asynchronous ADMIN_NO_SRP_AUTH authentication flow
        /// </summary>
        /// <param name="adminAuthRequest">InitiateAdminNoSrpAuthRequest object containing the necessary 
        /// parameters to initiate the ADMIN_NO_SRP_AUTH authentication flow</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithAdminNoSrpAuthAsync(InitiateAdminNoSrpAuthRequest adminAuthRequest)
        {
            return await StartWithAdminNoSrpAuthAsync(adminAuthRequest, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Initiates the asynchronous ADMIN_NO_SRP_AUTH authentication flow
        /// </summary>
        /// <param name="adminAuthRequest">InitiateAdminNoSrpAuthRequest object containing the necessary 
        /// parameters to initiate the ADMIN_NO_SRP_AUTH authentication flow</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the AuthFlowResponse object that can be used to respond to the next challenge, 
        /// if one exists</returns>
        public virtual async Task<AuthFlowResponse> StartWithAdminNoSrpAuthAsync(InitiateAdminNoSrpAuthRequest adminAuthRequest, CancellationToken cancellationToken)
        {
            AdminInitiateAuthRequest initiateAuthRequest = CreateAdminAuthRequest(adminAuthRequest);

            AdminInitiateAuthResponse initiateResponse =
                await Provider.AdminInitiateAuthAsync(initiateAuthRequest, cancellationToken).ConfigureAwait(false);

            UpdateSessionIfAuthenticationComplete(initiateResponse.ChallengeName, initiateResponse.AuthenticationResult);

            return new AuthFlowResponse(initiateResponse.Session,
                initiateResponse.AuthenticationResult,
                initiateResponse.ChallengeName,
                initiateResponse.ChallengeParameters,
                new Dictionary<string, string>(initiateResponse.ResponseMetadata.Metadata));
        }

        /// <summary>
        /// Internal method for updating the CognitoUser SessionTokens property if properly authenticated
        /// </summary>
        private void UpdateSessionIfAuthenticationComplete(ChallengeNameType challengeName, AuthenticationResultType authResult)
        {
            if (string.IsNullOrEmpty(challengeName))
            {
                CognitoUserSession cognitoUserSession = GetCognitoUserSession(authResult);
                this.SessionTokens = cognitoUserSession;
            }
        }

        /// <summary>
        /// Interal method which creates the InitiateAuthRequest for an SRP authentication flow
        /// </summary>
        /// <param name="tupleAa">Tuple containing the A,a pair for SRP authentication</param>
        /// <returns>Returns the InitiateAuthRequest for an SRP authentication flow</returns>
        private InitiateAuthRequest CreateSrpAuthRequest(Tuple<BigInteger, BigInteger> tupleAa)
        {
            InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest()
            {
                AuthFlow = AuthFlowType.USER_SRP_AUTH,
                ClientId = ClientID,
                AuthParameters = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    { CognitoConstants.ChlgParamUsername, Username },
                    { CognitoConstants.ChlgParamSrpA, tupleAa.Item1.ToString("X") }
                }
            };

            if (!string.IsNullOrEmpty(ClientSecret))
            {
                initiateAuthRequest.AuthParameters.Add(CognitoConstants.ChlgParamSecretHash,
                                                    CognitoAuthHelper.GetUserPoolSecretHash(Username, ClientID, ClientSecret));
            }

            if (Device != null && !string.IsNullOrEmpty(Device.DeviceKey))
            {
                initiateAuthRequest.AuthParameters.Add(CognitoConstants.ChlgParamDeviceKey, Device.DeviceKey);
            }

            return initiateAuthRequest;
        }

        /// <summary>
        /// Internal mehtod which updates CognitoUser's username, secret hash, and device key from challege parameters
        /// </summary>
        /// <param name="challengeParameters">Dictionary containing the key-value pairs for challenge parameters</param>
        private void UpdateUsernameAndSecretHash(IDictionary<string, string> challengeParameters)
        {
            bool canSetUsername = string.IsNullOrEmpty(Username) || string.Equals(UserID, Username, StringComparison.Ordinal);
            bool challengeParamIsUsername = challengeParameters != null && challengeParameters.ContainsKey(CognitoConstants.ChlgParamUsername);
            bool shouldUpdate = canSetUsername || challengeParamIsUsername;

            if (!shouldUpdate)
            {
                return;
            }

            if (challengeParameters.ContainsKey(CognitoConstants.ChlgParamUsername))
            {
                Username = challengeParameters[CognitoConstants.ChlgParamUsername];
            }

            if (!string.IsNullOrEmpty(ClientSecret))
            {
                SecretHash = CognitoAuthHelper.GetUserPoolSecretHash(Username, ClientID, ClientSecret);
            }
        }

        private AdminInitiateAuthRequest CreateAdminAuthRequest(InitiateAdminNoSrpAuthRequest adminRequest)
        {
            AdminInitiateAuthRequest returnRequest = new AdminInitiateAuthRequest()
            {
                AuthFlow = AuthFlowType.ADMIN_NO_SRP_AUTH,
                ClientId = ClientID,
                UserPoolId = UserPool.PoolID,
                AuthParameters = new Dictionary<string, string>()
                {
                    { CognitoConstants.ChlgParamUsername, Username },
                    {CognitoConstants.ChlgParamPassword, adminRequest.Password }
                }
            };

            if (Device != null && !string.IsNullOrEmpty(Device.DeviceKey))
            {
                returnRequest.AuthParameters.Add(CognitoConstants.ChlgParamDeviceKey, Device.DeviceKey);
            }

            if (!string.IsNullOrEmpty(SecretHash))
            {
                returnRequest.AuthParameters.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }

            if (adminRequest.ClientMetadata != null)
            {
                returnRequest.ClientMetadata = new Dictionary<string, string>(adminRequest.ClientMetadata);
            }

            return returnRequest;
        }

        private InitiateAuthRequest CreateRefreshTokenAuthRequest(AuthFlowType authFlowType)
        {
            if (authFlowType != AuthFlowType.REFRESH_TOKEN && authFlowType != AuthFlowType.REFRESH_TOKEN_AUTH)
            {
                throw new ArgumentException("authFlowType must be either \"REFRESH_TOKEN\" or \"REFRESH_TOKEN_AUTH\"", "authFlowType");
            }

            InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest()
            {
                AuthFlow = authFlowType,
                ClientId = ClientID,
                AuthParameters = new Dictionary<string, string>()
                {
                    {CognitoConstants.ChlgParamUsername, Username },
                    {CognitoConstants.ChlgParamRefreshToken, SessionTokens.RefreshToken }
                }
            };

            if (Device != null && !string.IsNullOrEmpty(Device.DeviceKey))
            {
                initiateAuthRequest.AuthParameters.Add(CognitoConstants.ChlgParamDeviceKey, Device.DeviceKey);
            }

            if (!string.IsNullOrEmpty(SecretHash))
            {
                initiateAuthRequest.AuthParameters.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }

            return initiateAuthRequest;
        }

        /// <summary>
        /// Internal method which responds to the PASSWORD_VERIFIER challenge in SRP authentication
        /// </summary>
        /// <param name="challenge">Response from the InitiateAuth challenge</param>
        /// <param name="password">Password for the CognitoUser, needed for authentication</param>
        /// <param name="tupleAa">Tuple of BigIntegers containing the A,a pair for the SRP protocol flow</param>
        /// <returns>Returns the RespondToAuthChallengeRequest for an SRP authentication flow</returns>
        private RespondToAuthChallengeRequest CreateSrpPasswordVerifierAuthRequest(InitiateAuthResponse challenge,
                                                                                   string password,
                                                                                   Tuple<BigInteger, BigInteger> tupleAa)
        {
            string username = challenge.ChallengeParameters[CognitoConstants.ChlgParamUsername];
            string poolName = PoolName;
            string secretBlock = challenge.ChallengeParameters[CognitoConstants.ChlgParamSecretBlock];
            string salt = challenge.ChallengeParameters[CognitoConstants.ChlgParamSalt];
            BigInteger srpb = BigIntegerExtensions.FromUnsignedLittleEndianHex(challenge.ChallengeParameters[CognitoConstants.ChlgParamSrpB]);

            if ((srpb.TrueMod(AuthenticationHelper.N)).Equals(BigInteger.Zero))
            {
                throw new ArgumentException("SRP error, B mod N cannot be zero.", "challenge");
            }

            DateTime timestamp = DateTime.UtcNow;
            string timeStr = timestamp.ToString("ddd MMM d HH:mm:ss \"UTC\" yyyy", CultureInfo.InvariantCulture);

            byte[] claim = AuthenticationHelper.AuthenticateUser(username, password, poolName, tupleAa, salt,
                challenge.ChallengeParameters[CognitoConstants.ChlgParamSrpB], secretBlock, timeStr);
            string claimBase64 = Convert.ToBase64String(claim);

            Dictionary<string, string> srpAuthResponses = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                {CognitoConstants.ChlgParamPassSecretBlock, secretBlock},
                {CognitoConstants.ChlgParamPassSignature, claimBase64},
                {CognitoConstants.ChlgParamUsername, username },
                {CognitoConstants.ChlgParamTimestamp, timeStr },
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                srpAuthResponses.Add(CognitoConstants.ChlgParamSecretHash, SecretHash);
            }

            if (Device != null && !string.IsNullOrEmpty(Device.DeviceKey))
            {
                srpAuthResponses.Add(CognitoConstants.ChlgParamDeviceKey, Device.DeviceKey);
            }

            RespondToAuthChallengeRequest authChallengeRequest = new RespondToAuthChallengeRequest()
            {
                ChallengeName = challenge.ChallengeName,
                ClientId = ClientID,
                Session = challenge.Session,
                ChallengeResponses = srpAuthResponses
            };

            return authChallengeRequest;
        }

        /// <summary>
        /// Creates the CognitoAWSCredentials for accessing AWS resources. Should only be called with an authenticated user.
        /// </summary>
        /// <param name="identityPoolID">The poolID of the identity pool the user belongs to</param>
        /// <param name="identityPoolRegion">The region of the identity pool the user belongs to</param>
        /// <returns>Returns the CognitoAWSCredentials for the user to be able to access AWS resources</returns>
        public CognitoAWSCredentials GetCognitoAWSCredentials(string identityPoolID, RegionEndpoint identityPoolRegion)
        {
            EnsureUserAuthenticated();

            string poolRegion = UserPool.PoolID.Substring(0, UserPool.PoolID.IndexOf("_"));
            string providerName = "cognito-idp." + poolRegion + ".amazonaws.com/" + UserPool.PoolID;

            CognitoAWSCredentials credentials = new CognitoAWSCredentials(identityPoolID, identityPoolRegion);
            credentials.AddLogin(providerName, SessionTokens.IdToken);

            return credentials;
        }
    }
}
