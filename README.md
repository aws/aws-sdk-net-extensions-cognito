![.NET on AWS Banner](./logo.png ".NET on AWS")

## Amazon Cognito Authentication Extension Library

[![nuget](https://img.shields.io/nuget/v/Amazon.Extensions.CognitoAuthentication.svg)](https://www.nuget.org/packages/Amazon.Extensions.CognitoAuthentication/)

[Amazon.Extensions.CognitoAuthentication](https://www.nuget.org/packages/Amazon.Extensions.CognitoAuthentication/) simplifies the authentication process of [Amazon Cognito User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html) for .NET developers.

It allows you to use various authentication methods for Amazon Cognito User Pools with only a few short method calls, and makes the process intuitive.

[Learn more about Amazon Cognito User Pools.](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-getting-started.html)

This library targets the .NET Standard 2.0 and introduces the following dependencies:

* [AWSSDK.CognitoIdentity](https://www.nuget.org/packages/AWSSDK.CognitoIdentity/)
* [AWSSDK.CognitoIdentityProvider](https://www.nuget.org/packages/AWSSDK.CognitoIdentityProvider/)


# Getting Started

To take advantage of this library, set up an AWS account and install the AWS SDK for .NET as described in [Getting Started with the AWS SDK for .NET](https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/net-dg-setup.html).

While this library is in development, you will need to build it manually.

Create a new project in Visual Studio and add the Amazon Cognito Authentication Extension Library as a reference to the project.

Using the library to make calls to the Amazon Cognito Identity Provider API from the AWS SDK for .NET is as simple as creating the necessary **CognitoAuthentication** objects and calling the appropriate **AmazonCognitoIdentityProviderClient** methods. The principal Amazon Cognito authentication objects are:

- **CognitoUserPool** objects store information about a user pool, including the poolID, clientID, and other pool attributes.
- **CognitoUser** objects contain a user’s username, the pool they are associated with, session information, and other user properties.
- **CognitoDevice** objects include device information, such as the device key.

## Authenticating with Secure Remote Protocol (SRP)

Instead of implementing hundreds of lines of cryptographic methods yourself, you now only need to create the necessary **AmazonCognitoIdentityProviderClient**, **CognitoUserPool**, **CognitoUser**, and **InitiateSrpAuthRequest** objects and then call **StartWithSrpAuthAsync**:


```csharp
using Amazon.Runtime;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;

public async void AuthenticateWithSrpAsync()
{
    var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), FallbackRegionFactory.GetRegionEndpoint());
    var userPool = new CognitoUserPool("poolID", "clientID", provider);
    var user = new CognitoUser("username", "clientID", userPool, provider);

    var password = "userPassword";

    AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
    {
        Password = password
    }).ConfigureAwait(false);
}
```

The **AuthenticationResult** property of the **AuthFlowResponse** object contains the user’s session tokens if the user was successfully authenticated. If more challenge responses are required, this field is null and the **ChallengeName** property describes the next challenge, such as multi-factor authentication. You would then call the appropriate method to continue the authentication flow. 

## Authenticating with Multiple Forms of Authentication

Continuing the authentication flow with challenges, such as with **NewPasswordRequired** and **Multi-Factor Authentication (MFA)**, is simpler as well. 

The following code shows one way to check the challenge type and get appropriate responses for MFA and NewPasswordRequired challenges. This processing might be necessary as the authentication flow proceeds, depending on the properties of the **AuthFlowResponse** object that was retrieved earlier.

```csharp
while (authResponse.AuthenticationResult == null)
{
    if (authResponse.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
    {
        Console.WriteLine("Enter your desired new password:");
        string newPassword = Console.ReadLine();

        authResponse = 
            await user.RespondToNewPasswordRequiredAsync(new RespondToNewPasswordRequiredRequest()
            {
                SessionID = authResponse.SessionID,
                NewPassword = newPassword
            }).ConfigureAwait(false);
    }
    else if (authResponse.ChallengeName == ChallengeNameType.SMS_MFA)
    {
        Console.WriteLine("Enter the MFA Code sent to your device:");
        string mfaCode = Console.ReadLine();

        authResponse = await user.RespondToSmsMfaAuthAsync(new RespondToSmsMfaRequest()
        {
                SessionID = authResponse.SessionID,
                MfaCode = mfaCode
        }).ConfigureAwait(false);
        }
        else
        {
            Console.WriteLine("Unrecognized authentication challenge.");
            break;
        }
}
```

[Learn more about Amazon Cognito User Pool Authentication Flow.](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html)

## Authenticating with Different Levels of Authentication

After a user is authenticated by using the Amazon Cognito Authentication Extension Library, you can then allow them to access specific AWS resources.

To allow users to access specific AWS resources, you must create an identity pool through the **Amazon Cognito Federated Identities** console.

You can also specify different roles for both unauthenticated and authenticated users so that they can access different resources. 
These roles can be changed in the IAM console where you can add or remove permissions in the **Action** field of the role’s attached policy. Then, using the appropriate identity pool, user pool, and Amazon Cognito user information, calls can be made to different AWS resources.

The following code shows how a user, who was authenticated with SRP, can access various S3 buckets as permitted by the associated identity pool’s role.

```csharp
using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;

public async void GetS3BucketsAsync()
{
    var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(),
                                                            FallbackRegionFactory.GetRegionEndpoint());
    var userPool = new CognitoUserPool("poolID", "clientID", provider);
    var user = new CognitoUser("username", "clientID", userPool, provider);

    var password = "userPassword";

    await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
    {
        Password = password
    }).ConfigureAwait(false);

    var credentials = 
        user.GetCognitoAWSCredentials("identityPoolID", RegionEndpoint.<YourIdentityPoolRegion>);

    using (var client = new AmazonS3Client(credentials))
    {
        ListBucketsResponse response = 
            await client.ListBucketsAsync(new ListBucketsRequest()).ConfigureAwait(false);

        foreach (S3Bucket bucket in response.Buckets)
        {
            Console.WriteLine(bucket.BucketName);
        }
    }
}
```

## Authenticating using a Refresh Token from a Previous Session

Access and ID tokens provided by Cognito are only valid for one hour but the refresh token can be configured to be valid for much longer. Below is an example of how to retrieve new Access and ID tokens using a refresh token which is still valid.

See [here](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html) to learn more about using the tokens returned by Amazon Cognito.

```csharp
using Amazon;
using Amazon.Runtime;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;

public async void GetCredsFromRefreshAsync(string refreshToken)
{
    AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), FallbackRegionFactory.GetRegionEndpoint());
    CognitoUserPool userPool = new CognitoUserPool("poolID", "clientID", provider);

    CognitoUser user = new CognitoUser("username", "clientID", userPool, provider);

    user.SessionTokens = new CognitoUserSession(null, null, refreshToken, DateTime.UtcNow, DateTime.UtcNow.AddHours(1));

    InitiateRefreshTokenAuthRequest refreshRequest = new InitiateRefreshTokenAuthRequest()
    {
        AuthFlowType = AuthFlowType.REFRESH_TOKEN_AUTH
    };
    
    AuthFlowResponse authResponse = await user.StartWithRefreshTokenAuthAsync(refreshRequest).ConfigureAwait(false);
}
```

## Other Forms of Authentication

In addition to SRP, NewPasswordRequired, MFA and Refresh the Amazon Cognito Authentication Extension Library offers an easier authentication flow for the following:

- **Custom** – Begins with a call to StartWithCustomAuthAsync(InitiateCustomAuthRequest customRequest)
- **AdminNoSRP** – Begins with a call to StartWithAdminNoSrpAuth(InitiateAdminNoSrpAuthRequest adminAuthRequest)

# Getting Help

We use the [GitHub issues](https://github.com/aws/aws-sdk-net-extensions-cognito/issues) for tracking bugs and feature requests and have limited bandwidth to address them.

If you think you may have found a bug, please open an [issue](https://github.com/aws/aws-sdk-net-extensions-cognito/issues/new)

# Contributing

We welcome community contributions and pull requests. See
[CONTRIBUTING](./CONTRIBUTING.md) for information on how to set up a development
environment and submit code.

# Additional Resources

[AWS .NET GitHub Home Page](https://github.com/aws/dotnet)  
GitHub home for .NET development on AWS. You'll find libraries, tools, and resources to help you build .NET applications and services on AWS.

[AWS Developer Center - Explore .NET on AWS](https://aws.amazon.com/developer/language/net/)  
Find .NET code samples, step-by-step guides, videos, blog content, tools, and information about live events all in one place. 

[AWS Developer Blog - .NET](https://aws.amazon.com/blogs/developer/category/programing-language/dot-net/)  
Come and see what .NET developers at AWS are up to! Learn about new .NET software announcements, guides, and how-to's.

[@dotnetonaws](https://twitter.com/dotnetonaws)
Follow us on twitter!

# License

Libraries in this repository are licensed under the Apache 2.0 License. 

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for more information.
