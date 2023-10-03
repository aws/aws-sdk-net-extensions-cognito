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
using System.Threading;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication.Util;

namespace Amazon.Extensions.CognitoAuthentication
{
    public partial class CognitoUser
    { 
        /// <summary>
        /// The client secret for the associated client, if one is set
        /// </summary>
        private string ClientSecret { get; set; }

        /// <summary>
        /// The secret hash for the associated user, if a client secret is set
        /// </summary>
        internal string SecretHash { get; set; }

        /// <summary>
        /// The session for the associated user.
        /// </summary>
        public CognitoUserSession SessionTokens { get; set; }

        /// <summary>
        /// The CognitoDevice associated with this user, if exists
        /// </summary>
        public CognitoDevice Device { get; set; }

        /// <summary>
        /// The userID of the associated user. UserID can only be configured through the 
        /// constructor,  and once set it cannot be changed.
        /// </summary>
        public string UserID { get; private set; }

        /// <summary>
        /// The username of the associated user. Username can only be configured through the 
        /// constructor, and once set it cannot be changed.
        /// </summary>
        public string Username { get; private set; }

        /// <summary>
        /// The user pool of the associated user. UserPool can only be configured through 
        /// the constructor, and once set it cannot be changed.
        /// </summary>
        public CognitoUserPool UserPool { get; private set; }

        /// <summary>
        /// The clientID of the associated user. ClientID can only be configured through 
        /// the constructor, and once set it cannot be changed.
        /// </summary>
        public string ClientID { get; private set; }

        /// <summary>
        /// The status of the associated user. 
        /// </summary>
        public string Status { get; private set; }

        /// <summary>
        /// The IAmazonCognitoIdentityProvider client of the associated user. Provider can 
        /// only be configured through the constructor, and once set it cannot be changed.
        /// </summary>
        internal IAmazonCognitoIdentityProvider Provider { get; private set; }

        /// <summary>
        /// The attributes of the associated user. 
        /// </summary>
        public Dictionary<string, string> Attributes { get; private set; } = new Dictionary<string, string>();

        /// <summary>
        /// The settings of the associated user.
        /// </summary>
        public Dictionary<string, string> Settings { get; set; }

        /// <summary>
        /// Private property to get and set the pool name of the user pool the user 
        /// is associated with.
        /// </summary>
        private string PoolName { get; set; }

        /// <summary>
        /// Creates an instance of CognitoUser
        /// </summary>
        /// <param name="userID">UserID of the specified user</param>
        /// <param name="clientID">ClientID associated with the user pool</param>
        /// <param name="pool">CognitoUserPool this user is associated with </param>
        /// <param name="provider">IAmazonCognitoIdentityProvider for the specified user pool</param>
        /// <param name="clientSecret">Client secret for the specified client, if exists</param>
        /// <param name="username">Username for user, if different from userID</param>
        public CognitoUser(string userID, string clientID,
                           CognitoUserPool pool,
                           IAmazonCognitoIdentityProvider provider,
                           string clientSecret = null,
                           string status = null,
                           string username = null,
                           Dictionary<string, string> attributes = null)
        {
            if(pool.PoolID.Contains("_"))
            {
                this.PoolName = pool.PoolID.Split('_')[1];
            }
            else
            {
                throw new ArgumentException("Pool's poolID malformed, should be of the form <region>_<poolname>.");
            }

            this.ClientSecret = clientSecret;

            this.UserID = userID;
            if (!string.IsNullOrEmpty(username))
            {
                this.Username = username;
            }
            else
            {
                this.Username = userID;
            }

            if (!string.IsNullOrEmpty(clientSecret))
            {
                this.SecretHash = CognitoAuthHelper.GetUserPoolSecretHash(Username, clientID, clientSecret);
            }

            this.Status = status;

            this.UserPool = pool;
            this.ClientID = clientID;
            this.SessionTokens = null;

            if (attributes != null)
            {
                this.Attributes = attributes;
            }

            this.Provider = provider;

            if (this.Provider is AmazonCognitoIdentityProviderClient eventProvider)
            {
                eventProvider.BeforeRequestEvent += CognitoAuthHelper.ServiceClientBeforeRequestEvent;
            }
        }
        /// <summary>
        /// Confirms the sign up of the associated user using the provided confirmation code
        /// using an asynchronous call
        /// </summary>
        /// <param name="confirmationCode">Confirmation code sent to user via email or SMS</param>
        /// <param name="forcedAliasCreation">Boolean specifying whether forced alias creation is desired</param>
        public virtual Task ConfirmSignUpAsync(string confirmationCode, bool forcedAliasCreation)
        {
            return ConfirmSignUpAsync(confirmationCode, forcedAliasCreation, default);
        }

        /// <summary>
        /// Confirms the sign up of the associated user using the provided confirmation code
        /// using an asynchronous call
        /// </summary>
        /// <param name="confirmationCode">Confirmation code sent to user via email or SMS</param>
        /// <param name="forcedAliasCreation">Boolean specifying whether forced alias creation is desired</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task ConfirmSignUpAsync(string confirmationCode, bool forcedAliasCreation, CancellationToken cancellationToken)
        {
            ConfirmSignUpRequest confirmRequest = CreateConfirmSignUpRequest(confirmationCode, forcedAliasCreation);

            return Provider.ConfirmSignUpAsync(confirmRequest, cancellationToken);
        }

        /// <summary>
        /// Request to resend registration confirmation code for a user using an asynchronous call
        /// </summary>
        /// <returns>Returns the delivery details for the confirmation code request</returns>
        public virtual Task ResendConfirmationCodeAsync()
        {
            return ResendConfirmationCodeAsync(default);
        }

        /// <summary>
        /// Request to resend registration confirmation code for a user using an asynchronous call
        /// </summary>
        /// <returns>Returns the delivery details for the confirmation code request</returns>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task ResendConfirmationCodeAsync(CancellationToken cancellationToken)
        {
            ResendConfirmationCodeRequest resendRequest = CreateResendConfirmationCodeRequest();

            return Provider.ResendConfirmationCodeAsync(resendRequest, cancellationToken);
        }

        /// <summary>
        /// Allows the user to reset their password using an asynchronous call. Should be used in 
        /// conjunction with the ConfirmPasswordAsync method 
        /// </summary>
        public virtual Task ForgotPasswordAsync()
        {
            return ForgotPasswordAsync(default);
        }

        /// <summary>
        /// Allows the user to reset their password using an asynchronous call. Should be used in 
        /// conjunction with the ConfirmPasswordAsync method 
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task ForgotPasswordAsync(CancellationToken cancellationToken)
        {
            ForgotPasswordRequest forgotPassRequest = CreateForgotPasswordRequest();

            return Provider.ForgotPasswordAsync(forgotPassRequest, cancellationToken);
        }
        /// <summary>
        /// Confirms the user's new password using the confirmation code sent to them using
        /// an asynchronous call
        /// </summary>
        /// <param name="confirmationCode">The confirmation code sent to the user</param>
        /// <param name="newPassword">The new desired password for the user</param>
        public virtual Task ConfirmForgotPasswordAsync(string confirmationCode, string newPassword)
        {
            return ConfirmForgotPasswordAsync(confirmationCode, newPassword, default);
        }

        /// <summary>
        /// Confirms the user's new password using the confirmation code sent to them using
        /// an asynchronous call
        /// </summary>
        /// <param name="confirmationCode">The confirmation code sent to the user</param>
        /// <param name="newPassword">The new desired password for the user</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task ConfirmForgotPasswordAsync(string confirmationCode, string newPassword, CancellationToken cancellationToken)
        {
            ConfirmForgotPasswordRequest confirmResetPassRequest =
                CreateConfirmPasswordRequest(confirmationCode, newPassword);

            return Provider.ConfirmForgotPasswordAsync(confirmResetPassRequest, cancellationToken);
        }

        /// <summary>
        /// Allows an authenticated user to change their password using an
        /// asynchronous call
        /// </summary>
        /// <param name="oldPass">The user's old password</param>
        /// <param name="newPass">The desired new password</param>
        public virtual Task ChangePasswordAsync(string oldPass, string newPass)
        {
            return ChangePasswordAsync(oldPass, newPass, default);
        }

        /// <summary>
        /// Allows an authenticated user to change their password using an
        /// asynchronous call
        /// </summary>
        /// <param name="oldPass">The user's old password</param>
        /// <param name="newPass">The desired new password</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task ChangePasswordAsync(string oldPass, string newPass, CancellationToken cancellationToken)
        {
            ChangePasswordRequest changePassRequest = CreateChangePasswordRequest(oldPass, newPass);

            return Provider.ChangePasswordAsync(changePassRequest, cancellationToken);
        }

        /// <summary>
        /// Gets the details for the current user using an asynchronous call
        /// </summary>
        /// <returns>Returns a tuple containing the user attributes and settings, in that order</returns>
        public virtual Task<GetUserResponse> GetUserDetailsAsync()
        {
            return GetUserDetailsAsync(default);
        }

        /// <summary>
        /// Gets the details for the current user using an asynchronous call
        /// </summary>
        /// <returns>Returns a tuple containing the user attributes and settings, in that order</returns>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task<GetUserResponse> GetUserDetailsAsync(CancellationToken cancellationToken)
        {
            EnsureUserAuthenticated();

            GetUserRequest getUserRequest = new GetUserRequest()
            {
                AccessToken = SessionTokens.AccessToken
            };

            return Provider.GetUserAsync(getUserRequest, cancellationToken);
        }

        /// <summary>
        /// Gets the attribute verification code for the specified attribute using
        /// an asynchronous call
        /// </summary>
        /// <param name="medium">Name of the attribute the verification code is being sent to.
        /// Should be either email or phone_number.</param>
        /// <returns>Returns the delivery details for the attribute verification code request</returns>
        public virtual Task GetAttributeVerificationCodeAsync(string medium)
        {
            return GetAttributeVerificationCodeAsync(medium, default);
        }

        /// <summary>
        /// Gets the attribute verification code for the specified attribute using
        /// an asynchronous call
        /// </summary>
        /// <param name="medium">Name of the attribute the verification code is being sent to.
        /// Should be either email or phone_number.</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns the delivery details for the attribute verification code request</returns>
        public virtual Task GetAttributeVerificationCodeAsync(string medium, CancellationToken cancellationToken)
        {
            GetUserAttributeVerificationCodeRequest getAttributeCodeRequest =
                    CreateGetUserAttributeVerificationCodeRequest(medium);

            return Provider.GetUserAttributeVerificationCodeAsync(getAttributeCodeRequest, cancellationToken);
        }

        /// <summary>
        /// Sign-out from all devices associated with this user using an asynchronous call
        /// </summary>
        public virtual Task GlobalSignOutAsync()
        {
            return GlobalSignOutAsync(default);
        }

        /// <summary>
        /// Sign-out from all devices associated with this user using an asynchronous call
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task GlobalSignOutAsync(CancellationToken cancellationToken)
        {
            EnsureUserAuthenticated();

            GlobalSignOutRequest globalSignOutRequest = new GlobalSignOutRequest()
            {
                AccessToken = SessionTokens.AccessToken
            };

            SessionTokens = null;
            return Provider.GlobalSignOutAsync(globalSignOutRequest, cancellationToken);
        }
        /// <summary>
        /// Deletes the current user using an asynchronous call
        /// </summary>
        public virtual Task DeleteUserAsync()
        {
            return DeleteUserAsync(default);
        }

        /// <summary>
        /// Deletes the current user using an asynchronous call
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task DeleteUserAsync(CancellationToken cancellationToken)
        {
            EnsureUserAuthenticated();

            DeleteUserRequest deleteUserRequest = new DeleteUserRequest()
            {
                AccessToken = SessionTokens.AccessToken
            };

            return Provider.DeleteUserAsync(deleteUserRequest, cancellationToken);
        }

        /// <summary>
        /// Verifies the given attribute using an asynchronous call
        /// </summary>
        /// <param name="attributeName">Attribute to be verified. Should either be email or phone_number</param>
        /// <param name="verificationCode">The verification code for the attribute being verified</param>
        public virtual Task VerifyAttributeAsync(string attributeName, string verificationCode)
        {
            return VerifyAttributeAsync(attributeName, verificationCode, default);
        }

        /// <summary>
        /// Verifies the given attribute using an asynchronous call
        /// </summary>
        /// <param name="attributeName">Attribute to be verified. Should either be email or phone_number</param>
        /// <param name="verificationCode">The verification code for the attribute being verified</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual Task VerifyAttributeAsync(string attributeName, string verificationCode, CancellationToken cancellationToken)
        {
            VerifyUserAttributeRequest verifyUserAttributeRequest =
                CreateVerifyUserAttributeRequest(attributeName, verificationCode);

            return Provider.VerifyUserAttributeAsync(verifyUserAttributeRequest, cancellationToken);
        }

        /// <summary>
        /// Updates the user's attributes defined in the attributes parameter (one at a time)
        /// using an asynchronous call
        /// </summary>
        /// <param name="attributes">The attributes to be updated</param>
        public virtual async Task UpdateAttributesAsync(IDictionary<string, string> attributes)
        {
            await UpdateAttributesAsync(attributes, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Updates the user's attributes defined in the attributes parameter (one at a time)
        /// using an asynchronous call
        /// </summary>
        /// <param name="attributes">The attributes to be updated</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual async Task UpdateAttributesAsync(IDictionary<string, string> attributes, CancellationToken cancellationToken)
        {
            UpdateUserAttributesRequest updateUserAttributesRequest =
                CreateUpdateUserAttributesRequest(attributes);

            await Provider.UpdateUserAttributesAsync(updateUserAttributesRequest, cancellationToken).ConfigureAwait(false);

            //Update the local Attributes property
            foreach (KeyValuePair<string, string> entry in attributes)
            {
                Attributes[entry.Key] = entry.Value;
            }
        }

        /// <summary>
        /// Deletes the attributes specified in the attributeNamesToDelete list using
        /// an asynchronous call
        /// </summary>
        /// <param name="attributeNamesToDelete">List of attributes to delete</param>
        public virtual async Task DeleteAttributesAsync(IList<string> attributeNamesToDelete)
        {
            await DeleteAttributesAsync(attributeNamesToDelete, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes the attributes specified in the attributeNamesToDelete list using
        /// an asynchronous call
        /// </summary>
        /// <param name="attributeNamesToDelete">List of attributes to delete</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual async Task DeleteAttributesAsync(IList<string> attributeNamesToDelete, CancellationToken cancellationToken)
        {
            DeleteUserAttributesRequest deleteUserAttributesRequest =
                CreateDeleteUserAttributesRequest(attributeNamesToDelete);

            await Provider.DeleteUserAttributesAsync(deleteUserAttributesRequest, cancellationToken).ConfigureAwait(false);

            //Update the local Attributes property
            foreach (string attribute in attributeNamesToDelete)
            {
                if (Attributes.ContainsKey(attribute))
                {
                    Attributes.Remove(attribute);
                }
            }
        }

        /// <summary>
        /// Sets the MFAOptions to be the settings desibed in the userSettings dictionary
        /// using an asynchronous call
        /// </summary>
        /// <param name="userSettings">Dictionary for the user MFA settings of the form [attribute, delivery medium]</param>
        public virtual async Task SetUserSettingsAsync(IDictionary<string, string> userSettings)
        {
            await SetUserSettingsAsync(userSettings, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Sets the MFAOptions to be the settings desibed in the userSettings dictionary
        /// using an asynchronous call
        /// </summary>
        /// <param name="userSettings">Dictionary for the user MFA settings of the form [attribute, delivery medium]</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        public virtual async Task SetUserSettingsAsync(IDictionary<string, string> userSettings, CancellationToken cancellationToken)
        {
            SetUserSettingsRequest setUserSettingsRequest = CreateSetUserSettingsRequest(userSettings);

            await Provider.SetUserSettingsAsync(setUserSettingsRequest, cancellationToken).ConfigureAwait(false);

            //Update the local Settings property
            foreach (KeyValuePair<string, string> entry in userSettings)
            {
                Settings[entry.Key] = entry.Value;
            }
        }

        /// <summary>
        /// Lists the CognitoDevices associated with this user using an asynchronous call
        /// </summary>
        /// <param name="limit">Maxmimum number of devices to be returned in this call</param>
        /// <param name="paginationToken">Token to continue earlier search</param>
        /// <returns>Returns a list of CognitoDevices associated with this user</returns>
        [Obsolete("This method is deprecated since it only lists the first page of devices. The method ListDevicesV2Async should be used instead which allows listing additional pages of devices.")]
        public virtual async Task<List<CognitoDevice>> ListDevicesAsync(int limit, string paginationToken)
        {
            return await ListDevicesAsync(limit, paginationToken, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Lists the CognitoDevices associated with this user using an asynchronous call
        /// </summary>
        /// <param name="limit">Maxmimum number of devices to be returned in this call</param>
        /// <param name="paginationToken">Token to continue earlier search</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns a list of CognitoDevices associated with this user</returns>
        [Obsolete("This method is deprecated since it only lists the first page of devices. The method ListDevicesV2Async should be used instead which allows listing additional pages of devices.")]
        public virtual async Task<List<CognitoDevice>> ListDevicesAsync(int limit, string paginationToken, CancellationToken cancellationToken)
        {
            ListDevicesRequest listDevicesRequest = CreateListDevicesRequest(limit, paginationToken);
            ListDevicesResponse listDevicesReponse = await Provider.ListDevicesAsync(listDevicesRequest, cancellationToken).ConfigureAwait(false);
            List<CognitoDevice> devicesList = new List<CognitoDevice>();

            foreach (DeviceType device in listDevicesReponse.Devices)
            {
                devicesList.Add(new CognitoDevice(device, this));
            }

            return devicesList;
        }

        /// <summary>
        /// Executes the ListDevicesAsync service call to access device types associated with this user using an asynchronous call. 
        /// The response returned contains DeviceType objects which could be used to construct list of CognitoDevice type objects and 
        /// a PaginationToken which could be used to access remaining device types (if any).
        /// </summary>
        /// <param name="limit">Maxmimum number of devices to be returned in this call</param>
        /// <param name="paginationToken">Token to continue earlier search</param>
        /// <returns>Returns underlying ListDevicesResponse that contains list of DeviceType objects along with PaginationToken.</returns>
        public virtual async Task<ListDevicesResponse> ListDevicesV2Async(int limit, string paginationToken)
        {
            return await ListDevicesV2Async(limit, paginationToken, default).ConfigureAwait(false);
        }

        /// <summary>
        /// Executes the ListDevicesAsync service call to access device types associated with this user using an asynchronous call. 
        /// The response returned contains DeviceType objects which could be used to construct list of CognitoDevice type objects and 
        /// a PaginationToken which could be used to access remaining device types (if any).
        /// </summary>
        /// <param name="limit">Maxmimum number of devices to be returned in this call</param>
        /// <param name="paginationToken">Token to continue earlier search</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns>Returns underlying ListDevicesResponse that contains list of DeviceType objects along with PaginationToken.</returns>
        public virtual async Task<ListDevicesResponse> ListDevicesV2Async(int limit, string paginationToken, CancellationToken cancellationToken)
        {
            ListDevicesRequest listDevicesRequest = CreateListDevicesRequest(limit, paginationToken);
            return await Provider.ListDevicesAsync(listDevicesRequest, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Request code for authenticator app.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns><see cref="AssociateSoftwareTokenResponse"/> with secret code.</returns>
        public virtual async Task<AssociateSoftwareTokenResponse> AssociateSoftwareTokenAsync(CancellationToken cancellationToken)
        {
            EnsureUserAuthenticated();

            AssociateSoftwareTokenRequest request = new AssociateSoftwareTokenRequest
            {
                AccessToken = SessionTokens.AccessToken
            };

            return await Provider.AssociateSoftwareTokenAsync(request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Verify code from authenticator app.
        /// </summary>
        /// <param name="code">Code from authenticator app.</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns><see cref="VerifySoftwareTokenResponse"/> which contains token verification status.</returns>
        public virtual async Task<VerifySoftwareTokenResponse> VerifySoftwareTokenAsync(string code, CancellationToken cancellationToken) {
            if (string.IsNullOrEmpty(code))
                throw new ArgumentNullException(nameof(code));

            EnsureUserAuthenticated();
            VerifySoftwareTokenRequest request = new VerifySoftwareTokenRequest
            {
                AccessToken = SessionTokens.AccessToken,
                FriendlyDeviceName = Device?.GetDeviceName(),
                UserCode = code
            };

            return await Provider.VerifySoftwareTokenAsync(request, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Update settings for software MFA settings.
        /// </summary>
        /// <param name="isPreferred">Software MFA preferred at sign in.</param>
        /// <param name="isEnabled">Enable or disable software MFA.</param>
        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation</param>
        /// <returns></returns>
        public async Task UpdateSoftwareMfaSettingsAsync(bool isPreferred, bool isEnabled, CancellationToken cancellationToken)
        {
            EnsureUserAuthenticated();
            SetUserMFAPreferenceRequest request = new SetUserMFAPreferenceRequest {
                AccessToken = SessionTokens.AccessToken,
                SoftwareTokenMfaSettings = new SoftwareTokenMfaSettingsType() {
                    PreferredMfa = isPreferred,
                    Enabled = isEnabled
                }
            };

            await Provider.SetUserMFAPreferenceAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private ConfirmSignUpRequest CreateConfirmSignUpRequest(string confirmationCode, bool forcedAliasCreation)
        {
            ConfirmSignUpRequest confirmRequest = new ConfirmSignUpRequest()
            {
                ClientId = ClientID,
                Username = Username,
                ForceAliasCreation = forcedAliasCreation,
                ConfirmationCode = confirmationCode
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                confirmRequest.SecretHash = SecretHash;
            }

            return confirmRequest;
        }

        private ResendConfirmationCodeRequest CreateResendConfirmationCodeRequest()
        {
            ResendConfirmationCodeRequest resendRequest = new ResendConfirmationCodeRequest()
            {
                Username = Username,
                ClientId = ClientID
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                resendRequest.SecretHash = SecretHash;
            }

            return resendRequest;
        }

        private ForgotPasswordRequest CreateForgotPasswordRequest()
        {
            ForgotPasswordRequest forgotPassRequest = new ForgotPasswordRequest()
            {
                ClientId = ClientID,
                Username = Username
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                forgotPassRequest.SecretHash = SecretHash;
            }

            return forgotPassRequest;
        }

        private ConfirmForgotPasswordRequest CreateConfirmPasswordRequest(string confirmationCode, string newPassword)
        {
            ConfirmForgotPasswordRequest confirmResetPassRequest = new ConfirmForgotPasswordRequest()
            {
                Username = Username,
                ClientId = ClientID,
                Password = newPassword,
                ConfirmationCode = confirmationCode
            };

            if (!string.IsNullOrEmpty(SecretHash))
            {
                confirmResetPassRequest.SecretHash = SecretHash;
            }

            return confirmResetPassRequest;
        }

        private ChangePasswordRequest CreateChangePasswordRequest(string oldPass, string newPass)
        {
            EnsureUserAuthenticated();

            ChangePasswordRequest changePassRequest = new ChangePasswordRequest()
            {
                PreviousPassword = oldPass,
                ProposedPassword = newPass,
                AccessToken = SessionTokens.AccessToken
            };

            return changePassRequest;
        }

        private GetUserAttributeVerificationCodeRequest CreateGetUserAttributeVerificationCodeRequest(string attributeName)
        {
            EnsureUserAuthenticated();

            GetUserAttributeVerificationCodeRequest getAttributeCodeRequest = new GetUserAttributeVerificationCodeRequest()
            {
                AccessToken = SessionTokens.AccessToken,
                AttributeName = attributeName
            };

            return getAttributeCodeRequest;
        }

        
        /// <summary>
        /// Internal function that creates a CognitoUserSession based on the authentication result
        /// </summary>
        /// <param name="authResult">An authentication result during authentication flow</param>
        /// <param name="refreshTokenOverride">Optional variable to override the refreshToken manually</param>
        /// <returns>Returns a CognitoUserSession based on the authentication result</returns>
        private CognitoUserSession GetCognitoUserSession(AuthenticationResultType authResult, string refreshTokenOverride = null)
        {
            string idToken = authResult.IdToken;
            string accessToken = authResult.AccessToken;
            string refreshToken;
            DateTime currentTime = DateTime.UtcNow;

            if (!string.IsNullOrEmpty(refreshTokenOverride))
            {
                refreshToken = refreshTokenOverride;
            }
            else
            {
                refreshToken = authResult.RefreshToken;
            }

            return new CognitoUserSession(idToken, accessToken, refreshToken, currentTime, currentTime.AddSeconds(authResult.ExpiresIn));
        }

        /// <summary>
        /// Sign-out by making the invalidating user session
        /// </summary>
        public void SignOut()
        {
            this.SessionTokens = null;
        }

        private VerifyUserAttributeRequest CreateVerifyUserAttributeRequest(string attributeName, string verificationCode)
        {
            EnsureUserAuthenticated();

            VerifyUserAttributeRequest verifyUserAttributeRequest = new VerifyUserAttributeRequest()
            {
                AttributeName = attributeName,
                AccessToken = SessionTokens.AccessToken,
                Code = verificationCode
            };

            return verifyUserAttributeRequest;
        }

        private UpdateUserAttributesRequest CreateUpdateUserAttributesRequest(IDictionary<string, string> attributes)
        {
            EnsureUserAuthenticated();

            UpdateUserAttributesRequest updateUserAttributesRequest = new UpdateUserAttributesRequest()
            {
                AccessToken = SessionTokens.AccessToken,
                UserAttributes = CognitoAuthHelper.CreateAttributeList(attributes)
            };

            return updateUserAttributesRequest;
        }

        private DeleteUserAttributesRequest CreateDeleteUserAttributesRequest(IList<string> attributeNamesToDelete)
        {
            if (attributeNamesToDelete == null || attributeNamesToDelete.Count < 1)
            {
                throw new ArgumentNullException(nameof(attributeNamesToDelete), $"{nameof(attributeNamesToDelete)} cannot be null or empty.");
            }

            EnsureUserAuthenticated();

            DeleteUserAttributesRequest deleteUserAttributesRequest = new DeleteUserAttributesRequest()
            {
                AccessToken = SessionTokens.AccessToken,
                UserAttributeNames = new List<string>(attributeNamesToDelete)
            };

            return deleteUserAttributesRequest;
        }

        private SetUserSettingsRequest CreateSetUserSettingsRequest(IDictionary<string, string> userSettings)
        {
            if (userSettings == null || userSettings.Count < 1)
            {
                throw new ArgumentNullException(nameof(userSettings), $"{nameof(userSettings)} cannot be null or empty.");
            }

            EnsureUserAuthenticated();

            List<MFAOptionType> settingsList = new List<MFAOptionType>();
            foreach (KeyValuePair<string, string> setting in userSettings)
            {
                settingsList.Add(new MFAOptionType() { AttributeName = setting.Key, DeliveryMedium = setting.Value });
            }

            SetUserSettingsRequest setUserSettingsRequest = new SetUserSettingsRequest()
            {
                AccessToken = SessionTokens.AccessToken,
                MFAOptions = settingsList
            };

            return setUserSettingsRequest;
        }

        private ListDevicesRequest CreateListDevicesRequest(int limit, string paginationToken)
        {
            EnsureUserAuthenticated();

            ListDevicesRequest listDevicesRequest = new ListDevicesRequest()
            {
                AccessToken = SessionTokens.AccessToken,
                Limit = limit,
                PaginationToken = paginationToken
            };

            return listDevicesRequest;
        }

        private void EnsureUserAuthenticated()
        {
            if (SessionTokens == null || !SessionTokens.IsValid())
            {
                throw new NotAuthorizedException("User is not authenticated.");
            }
        }
    }
}