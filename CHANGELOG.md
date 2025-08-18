## Release 2025-07-29

### Amazon.Extensions.CognitoAuthentication (3.1.1)
* **BREAKING CHANGE**: Fix Auth with device and device confirmation. The third parameter in `GenerateDeviceVerifier()` method has been renamed from `username` to `deviceKey`. Existing code will compile but fail at runtime - update calls to pass the device key instead of username.

## Release 2025-06-03

### Amazon.Extensions.CognitoAuthentication (3.1.0)
* Added support for Email MFA authentication challenge.

## Release 2025-04-28

### Amazon.Extensions.CognitoAuthentication (3.0.0)
* Updating the .NET SDK dependencies to the latest version GA 4.0.0

## Release 2025-04-17

### Amazon.Extensions.CognitoAuthentication (2.5.6)
* Add support for UserContextData

## Release 2025-03-31

### Amazon.Extensions.CognitoAuthentication (3.0.0-preview.3)
* Update AWS SDK to Preview 11

## Release 2025-02-27

### Amazon.Extensions.CognitoAuthentication (3.0.0-preview.2)
* Update .NET SDK dependencies to v4.0.0-preview8

## Release 2024-10-17

### Amazon.Extensions.CognitoAuthentication (3.0.0-preview.1)
* Added .NET 8 target framework and marked as trimmable
* Updated the .NET SDK dependencies to the latest version 4.0.0-preview.4
* Add SourceLink support

## Release 2024-07-09

### Amazon.Extensions.CognitoAuthentication (2.5.5)
* Added support for analytics metadata for collecting Amazon Pinpoint metrics.

## Release 2024-05-03

### Amazon.Extensions.CognitoAuthentication (2.5.4)
* Add ClientMetadata to InitiateAuthRequest during StartWithSrpAuthAsync. Thanks [willsmith9182](https://github.com/willsmith9182).

## Release 2024-04-20

### Amazon.Extensions.CognitoAuthentication (2.5.3)
* Update User-Agent string

## Release 2023-10-03

### Amazon.Extensions.CognitoAuthentication (2.5.2)
* Pull Request [#132](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/132) Adds code improvements to make it more idiomatic.
* Pull Request [#127](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/127) Verifies the ChallengeName during SRP authentication.
* Pull Request [#126](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/126) Fixes issues with the SecretHash initialization.

Thanks [DmitryProskurin](https://github.com/DmitryProskurin) for the above changes.

## Release 2023-08-30

### Amazon.Extensions.CognitoAuthentication (2.5.1)
* Pull Request [#130](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/130) Add ConfigureAwait(false) to avoid sync context deadlocks. Thanks [Ryan Swenson](https://github.com/swensorm)

## Release 2023-06-21

### Amazon.Extensions.CognitoAuthentication (2.5.0)
* Pull Request [#123](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/123) add support for software MFA. Thanks [DmitryProskurin](https://github.com/DmitryProskurin)

## Release 2023-05-18

### Amazon.Extensions.CognitoAuthentication (2.4.2)
* Fix the binary compatibility bug introduced in 2.4.1 by restoring the public async method overloads without CancellationToken arguments.

## Release 2023-05-12

### Amazon.Extensions.CognitoAuthentication (2.4.1)
* Pull Request [#115](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/115), add optional CancellationToken arguments to async methods, thanks [GabrielHare](https://github.com/GabrielHare)

## Release 2023-03-29

### Amazon.Extensions.CognitoAuthentication (2.4.0)
* Added new ListDevicesV2Async method and obsoleted ListDevicesAsync method in CognitoUser class.

## Release 2023-03-13

### Amazon.Extensions.CognitoAuthentication (2.3.1)
* Pull Request [#108](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/108), add caching for determining assembly version number. Thanks [mojotheo](https://github.com/mojotheo)

## Release 2023-02-08

### Amazon.Extensions.CognitoAuthentication (2.3.0)
* Pull Request [#104](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/104) Allow CognitoUser to be inheritant, thanks [petrenslavik](https://github.com/petrenslavik)
* Pull Request [#97](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/97) Add support for CUSTOM_AUTH, thanks [konectech](https://github.com/konectech)

## Release 2023-01-11

### Amazon.Extensions.CognitoAuthentication (2.2.4)
* Add ClientMetadata to SRP auth flow.

## Release 2022-09-12

### Amazon.Extensions.CognitoAuthentication (2.2.3)
* Allow CognitoUser.RespondToCustomAuthAsync to include ClientMetadata.

## Release 2021-07-15

### Amazon.Extensions.CognitoAuthentication (2.2.2)
* Fixed an issue where IssuedTime and ExpirationTime for CognitoUserSession object should be in UTC when it is instantiated manually by user.
* Removed check to validate CognitoSessionTokens which checks ExpirationTime for REFRESH_TOKEN Auth Flow.

## Release 2021-04-30

### Amazon.Extensions.CognitoAuthentication (2.2.1)
* Switch all calls to DateTime.Now to DateTime.UtcNow.

## Release 2021-03-22

### Amazon.Extensions.CognitoAuthentication (2.1.0)
* Added support for TOTP challenges, supports the existing way by defaulting to SMS, but also has an additional override method to allow setting the challenge type.
* Make the methods of CognitoUser virtual so that mock test cases could be written for CognitoUser class.
