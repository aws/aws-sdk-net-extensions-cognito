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