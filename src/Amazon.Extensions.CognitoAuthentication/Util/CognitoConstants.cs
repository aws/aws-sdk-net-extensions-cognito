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

namespace Amazon.Extensions.CognitoAuthentication.Util
{
    internal class CognitoConstants
    {
        // Challenge Parameters
        public static readonly string ChlgParamSrpA = "SRP_A";
        public static readonly string ChlgParamSrpB = "SRP_B";
        public static readonly string ChlgParamSecretHash = "SECRET_HASH";
        public static readonly string ChlgParamUsername = "USERNAME";
        public static readonly string ChlgParamChallengeName = "CHALLENGE_NAME";
        public static readonly string ChlgParamSalt = "SALT";
        public static readonly string ChlgParamSecretBlock = "SECRET_BLOCK";
        public static readonly string ChlgParamUserIDSrp = "USER_ID_FOR_SRP";
        public static readonly string ChlgParamRefreshToken = "REFRESH_TOKEN";

        public static readonly string ChlgParamPassSecretBlock = "PASSWORD_CLAIM_SECRET_BLOCK";
        public static readonly string ChlgParamPassSignature = "PASSWORD_CLAIM_SIGNATURE";
        public static readonly string ChlgParamTimestamp = "TIMESTAMP";
        public static readonly string ChlgParamDeliveryDest = "CODE_DELIVERY_DESTINATION";
        public static readonly string ChlgParamDeliveryMed = "CODE_DELIVERY_DELIVERY_MEDIUM";

        public static readonly string ChlgParamSmsMfaCode = "SMS_MFA_CODE";
        public static readonly string ChlgParamSoftwareTokenMfaCode = "SOFTWARE_TOKEN_MFA_CODE";
        public static readonly string ChlgParamEmailMfaCode = "EMAIL_OTP_CODE";
        public static readonly string ChlgParamDeviceKey = "DEVICE_KEY";

        public static readonly string ChlgParamUserAttrs = "userAttributes";
        public static readonly string ChlgParamRequiredAttrs = "requiredAttributes";
        public static readonly string ChlgParamUserAttrPrefix = "userAttributes.";
        public static readonly string ChlgParamNewPassword = "NEW_PASSWORD";
        public static readonly string ChlgParamPassword = "PASSWORD";

        // User Attributes
        public static readonly string UserAttrEmail = "email";
        public static readonly string UserAttrPhoneNumber = "phone_number";

        // Device Attributes
        public static readonly string DeviceAttrName = "device_name";
        public static readonly string DeviceAttrRemembered = "remembered";
        public static readonly string DeviceAttrNotRemembered = "not_remembered";

        public static readonly string DeviceChlgParamSalt = "salt";
        public static readonly string DeviceChlgParamVerifier = "verifier";
    }
}
