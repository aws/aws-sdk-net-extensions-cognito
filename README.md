![.NET on AWS Banner](./logo.png ".NET on AWS")

## Amazon Cognito Authentication Extension Library

**This software is in development and we do not recommend using this software in production environment.**

The [Amazon Cognito](https://aws.amazon.com/cognito/) Extension Library simplifies the authentication process of [Amazon Cognito User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html) for .NET developers.

It allows you to use various authentication methods for Amazon Cognito User Pools with only a few short method calls, along with making the process intuitive.

This library targets the .NET Standard 2.0 and introduces the following dependencies:

* [AWSSDK.CognitoIdentity](https://www.nuget.org/packages/AWSSDK.CognitoIdentity/)
* [AWSSDK.CognitoIdentityProvider](https://www.nuget.org/packages/AWSSDK.CognitoIdentityProvider/)


# Getting Started

To set up an AWS account and install the AWS SDK for .NET to take advantage of this library, see [Getting Started with the AWS SDK for .NET.](https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/net-dg-setup.html) 

While this library is in development, you will need to build it manually.

Create a new project in Visual Studio and add the Amazon Cognito Authentication Extension Library as a reference to the project.

Using the library to make calls to the Amazon Cognito Identity Provider API from the AWS SDK for .NET is as simple as creating the necessary **CognitoAuthentication** objects and calling the appropriate **AmazonCognitoIdentityProviderClient** methods. The principal Amazon Cognito authentication objects are:

- **CognitoUserPool** objects store information about a user pool, including the poolID, clientID, and other pool attributes.
- **CognitoUser** objects contain a user’s username, the pool they are associated with, session information, and other user properties.
- **CognitoDevice** objects include device information, such as the device key.


## Authenticating with Secure Remote Protocol (SRP)

You can do this by checking out the [Amazon.Extensions.CognitoAuthentication](https://github.com/aws/aws-sdk-net-extensions-cognito) project at the same level as this repository, along with you ASP.NET Core web application. Your ASP.NET Core web application csproj file can then include the following lines:

```csharp
<ProjectReference Include="..\..\..\aws-aspnet-cognito-identity-provider\src\Amazon.AspNetCore.Identity.AWSCognito\Amazon.AspNetCore.Identity.AWSCognito.csproj" />
<ProjectReference Include="..\..\..\aws-sdk-net-extensions-cognito\src\Amazon.Extensions.CognitoAuthentication\Amazon.Extensions.CognitoAuthentication.csproj" />
```

## Adding Amazon Cognito as an Identity Provider

To add Amazon Cognito as an Identity Provider, make the following change to your code:

Startup.cs:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // Adds Amazon Cognito as Identity Provider
    services.AddCognitoIdentity();
    ...
}

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    // If not already enabled, you will need to enable ASP.NET Core authentication
    app.UseAuthentication();
    ...
}
```

In order to automatically inject Cognito service and user pool clients make the following changes to your appsettings.json:

```csharp
"AWS": {
    "Region": "<your region id goes here>",
    "UserPoolClientId": "<your user pool client id goes here>",
    "UserPoolClientSecret": "<your user pool client secret goes here>",
    "UserPoolId": "<your user pool id goes here>"
}
```

Alternatively, instead of using the appsettings.json you can directly inject your own instances of Amazon Cognito service and user pool clients to be used when calling AddCognitoIdentity():

```csharp
public void ConfigureServices(IServiceCollection services)
{
    ...
    // Adds your own instance of Amazon Cognito clients 
    // cognitoIdentityProvider and cognitoUserPool are variables you would have instanciated yourself
    services.AddSingleton<IAmazonCognitoIdentityProvider>(cognitoIdentityProvider);
    services.AddSingleton<CognitoUserPool>(cognitoUserPool);

    // Adds Amazon Cognito as Identity Provider
    services.AddCognitoIdentity();
    ...
}
```

## Using the CognitoUser class as your web application user class

Once Amazon Cognito is added as the default ASP.NET Core Identity Provider, you will need to make changes to your code to use the newly introduced CognitoUser class instead of the default ApplicationUser class.

These changes will be required in existing RaZor views and controllers. Here is an example with a RaZor view:

```csharp
@using Microsoft.AspNetCore.Identity
@using Amazon.Extensions.CognitoAuthentication

@inject SignInManager<CognitoUser> SignInManager
@inject UserManager<CognitoUser> UserManager
```

In addition, this library introduces two child classes of SigninManager and UserManager designed for Amazon Cognito authentication and user management workflow: CognitoSigninManager and CognitoUserManager classes.

These two classes expose additional methods designed to support Amazon Cognito features, such as sending validation data to pre-signup [AWS Lambda triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html) when registering a new user:

```csharp
/// <summary>
/// Creates the specified <paramref name="user"/> in Cognito with the given password and validation data,
/// as an asynchronous operation.
/// </summary>
/// <param name="user">The user to create.</param>
/// <param name="password">The password for the user</param>
/// <param name="validationData">The validation data to be sent to the pre sign-up lambda triggers.</param>
/// <returns>
/// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
/// of the operation.
/// </returns>
public async Task<IdentityResult> CreateAsync(TUser user, string password, IDictionary<string, string> validationData)
```

# Getting Help

We use the [GitHub issues](https://github.com/aws/aws-aspnet-cognito-identity-provider/issues) for tracking bugs and feature requests and have limited bandwidth to address them.

If you think you may have found a bug, please open an [issue](https://github.com/aws/aws-aspnet-cognito-identity-provider/issues/new)

# Contributing

We welcome community contributions and pull requests. See
[CONTRIBUTING](./CONTRIBUTING.md) for information on how to set up a development
environment and submit code.

# Additional Resources

[AWS .NET GitHub Home Page](https://github.com/aws/dotnet)  
GitHub home for .NET development on AWS. You'll find libraries, tools, and resources to help you build .NET applications and services on AWS.

[AWS Developer Center - Explore .NET on AWS](https://aws.amazon.com/developer/language/net/)  
Find all the .NET code samples, step-by-step guides, videos, blog content, tools, and information about live events that you need in one place. 

[AWS Developer Blog - .NET](https://aws.amazon.com/blogs/developer/category/programing-language/dot-net/)  
Come see what .NET developers at AWS are up to!  Learn about new .NET software announcements, guides, and how-to's.

[@awsfornet](https://twitter.com/awsfornet)  
Follow us on twitter!

# License

Libraries in this repository are licensed under the Apache 2.0 License. 

See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for more information.