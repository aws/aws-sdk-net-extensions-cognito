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

namespace Amazon.Extensions.CognitoAuthentication
{
    public class CognitoConstants
    {
        // Challenge Parameters
        public const string ChlgParamSrpA = "SRP_A";
        public const string ChlgParamSrpB = "SRP_B";
        public const string ChlgParamSecretHash = "SECRET_HASH";
        public const string ChlgParamUsername = "USERNAME";
        public const string ChlgParamChallengeName = "CHALLENGE_NAME";
        public const string ChlgParamSalt = "SALT";
        public const string ChlgParamSecretBlock = "SECRET_BLOCK";
        public const string ChlgParamUserIDSrp = "USER_ID_FOR_SRP";
        public const string ChlgParamRefreshToken = "REFRESH_TOKEN";

        public const string ChlgParamPassSecretBlock = "PASSWORD_CLAIM_SECRET_BLOCK";
        public const string ChlgParamPassSignature = "PASSWORD_CLAIM_SIGNATURE";
        public const string ChlgParamTimestamp = "TIMESTAMP";
        public const string ChlgParamDeliveryDest = "CODE_DELIVERY_DESTINATION";
        public const string ChlgParamDeliveryMed = "CODE_DELIVERY_DELIVERY_MEDIUM";

        public const string ChlgParamSmsMfaCode = "SMS_MFA_CODE";
        public const string ChlgParamDeviceKey = "DEVICE_KEY";

        public const string ChlgParamUserAttrs = "userAttributes";
        public const string ChlgParamRequiredAttrs = "requiredAttributes";
        public const string ChlgParamUserAttrPrefix = "userAttributes.";
        public const string ChlgParamNewPassword = "NEW_PASSWORD";
        public const string ChlgParamPassword = "PASSWORD";

        // User Attributes
        public const string UserAttrEmail = "email";
        public const string UserAttrPhoneNumber = "phone_number";

        // Device Attributes
        public const string DeviceAttrName = "device_name";
        public const string DeviceAttrRemembered = "remembered";
        public const string DeviceAttrNotRemembered = "not_remembered";

        public const string DeviceChlgParamSalt = "salt";
        public const string DeviceChlgParamVerifier = "verifier";

        // User status
        public const string StatusUnconfirmed = "UNCONFIRMED";
        public const string StatusConfirmed = "CONFIRMED";
        public const string StatusArchivedd = "ARCHIVED";
        public const string StatusCompromised = "COMPROMISED";
        public const string StatusUnknown = "UNKNOWN";
        public const string StatusResetRequired = "RESET_REQUIRED";
        public const string StatusForceChangePassword = "FORCE_CHANGE_PASSWORD";
    }
}
