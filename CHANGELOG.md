### 2.4.2 (2023-05-18)
* Fix the binary compatibility bug introduced in 2.4.1 by restoring the public async method overloads without CancellationToken arguments.

### 2.4.1 (2023-05-12)
* Pull Request [#115](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/115), add optional CancellationToken arguments to async methods, thanks [GabrielHare](https://github.com/GabrielHare)

### 2.4.0 (2023-03-29)
* Added new ListDevicesV2Async method and obsoleted ListDevicesAsync method in CognitoUser class.

### 2.3.1 (2023-03-13)
* Pull Request [#108](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/108), add caching for determining assembly version number. Thanks [mojotheo](https://github.com/mojotheo)

### 2.3.0 (2023-02-08)
* Pull Request [#104](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/104) Allow CognitoUser to be inheritant, thanks [petrenslavik](https://github.com/petrenslavik)
* Pull Request [#97](https://github.com/aws/aws-sdk-net-extensions-cognito/pull/97) Add support for CUSTOM_AUTH, thanks [konectech](https://github.com/konectech)

### 2.2.4 (2023-01-11)
* Add ClientMetadata to SRP auth flow.

### 2.2.3 (2022-09-12)
* Allow CognitoUser.RespondToCustomAuthAsync to include ClientMetadata.

### 2.2.2 (2021-07-15)
* Fixed an issue where IssuedTime and ExpirationTime for CognitoUserSession object should be in UTC when it is instantiated manually by user.
* Removed check to validate CognitoSessionTokens which checks ExpirationTime for REFRESH_TOKEN Auth Flow.

### 2.2.1 (2021-04-30)
* Switch all calls to DateTime.Now to DateTime.UtcNow.

### 2.1.0 (2021-03-22)
* Added support for TOTP challenges, supports the existing way by defaulting to SMS, but also has an additional override method to allow setting the challenge type.
* Make the methods of CognitoUser virtual so that mock test cases could be written for CognitoUser class.