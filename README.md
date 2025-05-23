![CI](https://github.com/Liftric/cognito-idp/workflows/CI/badge.svg) 
![maven-central](https://img.shields.io/maven-central/v/com.liftric/cognito-idp?label=Maven%20Central) 
![OSS Sonatype (Releases)](https://img.shields.io/nexus/r/com.liftric/cognito-idp?label=Sonatype%20OSSRH%20%28Releases%29&server=https%3A%2F%2Fs01.oss.sonatype.org)
![npm (scoped)](https://img.shields.io/npm/v/@liftric/cognito-idp)
![platforms](https://img.shields.io/badge/platforms-android%20%7C%20ios%20%7C%20jvm%20%7C%20js-blue)
# Cognito-idp

Lightweight AWS Cognito Identity Provider client for Kotlin Multiplatform and Typescript projects.

> Not all requests, errors, and auth flows are implemented.  
> Feel free to [contribute](Contributing.md) if there is something missing for you.

> Version 2 introduced breaking changes, please refer to the [migration](Migrating.md) document for help.

## Import

### Kotlin

#### Gradle 

```kotlin
sourceSets {
    val commonMain by getting {
        dependencies {
            implementation("com.liftric:cognito-idp:<version>")
        }
    }
}
```

### Typescript

#### Yarn
```bash
yarn add @liftric/cognito-idp@<version>
```
#### npm
```sh
npm i @liftric/cognito-idp@<version>
```

## How-to

### Init

#### Kotlin

```kotlin
val provider = IdentityProviderClient("<region>", "<clientId>") 
```

#### Typescript

```typescript
import {IdentityProviderClientJS} from '@liftric/cognito-idp';

const provider = new IdentityProviderClientJS('<region>', '<clientId>');
```

### Usage

#### Kotlin

All methods are suspending and return a `Result<T>`, which wraps the desired object `T` on success or a `Throwable` on failure.

```kotlin
provider.signUp("user", "password").fold(
    onSuccess = {
        // Do something
    },
    onFailure = {
        // Handle exceptions
    }
)
```

#### Typescript

All methods return a [Promise](https://developer.mozilla.org/de/docs/Web/JavaScript/Reference/Global_Objects/Promise)<T> object.

### Errors

Request related exceptions are defined as a sealed class of type `IdentityProviderException`. They contain the http `status` code and the `message`. Common AWS exceptions are implemented as subclasses. In case that we don't have implemented the exception type it will default to `IdentityProviderException.Unknown`, which will contain the AWS exception `type`.

Network related exceptions (e.g. no internet) are of type `IOException`.

### Requests 

#### Sign Up

Signs up the user.

Attributes are optional.

```kotlin
val attribute = UserAttribute("email", "name@url.tld")
signUp("<username>", "<password>", listOf(attribute)): Result<SignUpResponse>
```

#### Confirm Sign Up

Confirms the sign up (also the delivery medium).

```kotlin
confirmSignUp("<username>", "<confirmationCode>"): Result<Unit>
```

#### Resend Confirmation Code

Resends the confirmation code.

```kotlin
resendConfirmationCode("<username>"): Result<CodeDeliveryDetails>
```

#### Sign In

Signs in the users.

```kotlin
signIn("<username>", "<password>"): Result<SignInResponse>
```

#### Respond To Auth Challenge

Responds to the auth challenge of the sign in response.

```kotlin
val challengeResponses = mapOf<String, String>()
respondToAuthChallenge("<challengeName>", challengeResponses, "<session>"): Result<SignInResponse>
```

#### Refresh access token

Refreshes access token based on refresh token that's retrieved from an earlier sign in.

```kotlin
val signInResponse: SignInResponse = ... // from earlier login or refresh
val refreshToken = signInResponse.AuthenticationResult.RefreshToken
refresh(refreshToken): Result<SignInResponse>
```

#### Get Claims

You can retrieve the claims of both the IdTokens' and AccessTokens' payload by converting them to either a `CognitoIdToken` or `CognitoAccessToken`

```kotlin
val idToken = CognitoIdToken(idTokenString)
val phoneNumber = idToken.claims.phoneNumber
val sub = idToken.claims.sub
```

Custom attributes of the IdToken get mapped into `customAttributes`.

You have to drop the `custom:` prefix.

```kotlin
val twitter = idToken.claims.customAttributes["twitter"]
```

#### Get User

Returns the users attributes and metadata on success.

More info about this in the [official documentation](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html).

```kotlin
getUser("<accessToken>"): Result<GetUserResponse>
```

#### Update User Attributes

Updates the users attributes (e.g. email, phone number, ...).

```kotlin
val attributes: List<UserAttribute> = ...
updateUserAttributes("<accessToken>", attributes): Result<UpdateUserAttributesResponse>
```

#### Change Password

Updates the users password 

```kotlin
changePassword("<accessToken>", "<currentPassword>", "<newPassword>"): Result<Unit>
```

#### Forgot Password

Invokes password forgot and sends a confirmation code the the users' delivery medium.

More info about the ForgotPasswordResponse in the [official documentation](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CodeDeliveryDetailsType.html).

```kotlin
forgotPassword("<username>"): Result<ForgotPasswordResponse>
```

#### Confirm Forgot Password

Confirms forgot password.

```kotlin
confirmForgotPassword("<confirmationCode>", "<username>", "<newPassword>"): Result<Unit>
```

#### Get user Attribute Verification Code

Gets the user attribute verification code for the specified attribute name

```kotlin
getUserAttributeVerificationCode("<accessToken>", "<attributeName>", "<clientMetadata>"): Result<GetAttributeVerificationCodeResponse>
```

#### Verify User Attribute

Verifies the specified user attribute.

```kotlin
verifyUserAttribute("<accessToken>", "<attributeName>", "<confirmationCode>"): Result<Unit>
```

#### Sign Out

Signs out the user globally.

```kotlin
signOut("<accessToken>"): Result<SignOutResponse>
```

#### Revoke Token

Revokes all access tokens generated by the refresh token.

```kotlin
revokeToken("<refreshToken>"): Result<Unit>
```


#### Associate Software Token

Associate software token. Either with access token or session (not both).

```kotlin
associateSoftwareToken("<accessToken>", "<session"): Result<AssociateSoftwareTokenResponse>
```

#### Verify Software Token

Verifies software token. Either with access token or session (not both).

```kotlin
verifySoftwareToken("<accessToken>", "<friendlyDeviceName>", "<session", "<userCode>"): Result<VerifySoftwareTokenResponse>
```

#### Set User MFA Preference

Set MFA preferences.

```kotlin
val smsMfaSettings = null
val softwareTokenMfaSettings = MfaSettings(true, true)
setUserMFAPreference("<accessToken>", smsMfaSettings, softwareTokenMfaSettings): Result<Unit>
```

#### Delete User

Deletes the user from the user pool.

```kotlin
deleteUser("<accessToken>"): Result<Unit>
```

#### Social Authentication
Enables authentication via social providers (e.g., Google, Facebook) using OAuth 2.0 flows. This requires additional configuration for social providers and integration with a Cognito User Pool configured for federated identities.

Configuration
To use social authentication, initialize the IdentityProviderClient with a SocialAuthConfig containing the client ID, client secret, redirect URI, region, and user pool ID for your social provider.


```kotlin
val socialAuthConfig = SocialAuthConfig(
clientId = "<social-client-id>", // e.g., Google Client ID
clientSecret = "<social-client-secret>", // e.g., Google Client Secret
redirectUri = "<redirect-uri>", // e.g., "app://callback"
region = "<region>", // e.g., "us-east-1"
userPoolId = "<user-pool-id>" // e.g., "us-east-1_abc123"
)
val provider = IdentityProviderClient(
region = "<region>",
clientId = "<cognito-client-id>",
socialAuthConfig = socialAuthConfig
)
```

```typescript
import { IdentityProviderClientJS, SocialAuthConfig } from '@liftric/cognito-idp';

const socialAuthConfig: SocialAuthConfig = {
clientId: '<social-client-id>',
clientSecret: '<social-client-secret>',
redirectUri: '<redirect-uri>',
region: '<region>',
userPoolId: '<user-pool-id>'
};
const provider = new IdentityProviderClientJS('<region>', '<cognito-client-id>', socialAuthConfig);
```
Prerequisites
Configure your Cognito User Pool to support federated identities for the desired social provider (e.g., Google, Facebook) in the AWS Console.
Obtain the client ID, client secret, and redirect URI from the social provider’s developer console.
Ensure the redirect URI matches the one configured in both the social provider and your Cognito User Pool.
Social Login
Performs authentication by exchanging a social provider’s authorization code for Cognito tokens. The authorization code is obtained from the social provider’s OAuth flow.

```kotlin
val providerType = SocialProvider.Google // or SocialProvider.Facebook
provider.socialLogin(providerType, "<authorization-code>").fold(
onSuccess = { response ->
val idToken = response.AuthenticationResult.IdToken
// Handle successful login, e.g., store tokens
},
onFailure = { exception ->
when (exception) {
is IdentityProviderException.SocialAuthFailed -> {
// Handle social auth failure (e.g., invalid code)
}
is IdentityProviderException.InvalidSocialToken -> {
// Handle invalid token
}
else -> {
// Handle other errors (e.g., network issues)
}
}
}
)
```

```typescript
import { SocialProvider } from '@liftric/cognito-idp';

const providerType = SocialProvider.Google; // or SocialProvider.Facebook
provider.socialLogin(providerType, '<authorization-code>')
.then(response => {
const idToken = response.AuthenticationResult.IdToken;
// Handle successful login
})
.catch(error => {
if (error instanceof IdentityProviderExceptionJS.SocialAuthFailed) {
// Handle social auth failure
} else if (error instanceof IdentityProviderExceptionJS.InvalidSocialToken) {
// Handle invalid token
} else {
// Handle other errors
}
});
```
Notes
The socialLogin method exchanges the authorization code for an ID token from the social provider, validates it, and signs in or signs up the user in Cognito.
On success, the SignInResponse contains Cognito JWTs (IdToken, AccessToken, RefreshToken).
Common errors include IdentityProviderException.SocialAuthFailed (e.g., invalid authorization code) and IdentityProviderException.InvalidSocialToken (e.g., expired token).
Validate Social Token
Validates a social provider’s ID token without performing a full login. Useful for verifying tokens independently.


```kotlin
val providerType = SocialProvider.Google
provider.validateSocialToken(providerType, "<id-token>").fold(
onSuccess = {
// Token is valid
},
onFailure = { exception ->
// Handle invalid or expired token
}
)
```

```typescript
const providerType = SocialProvider.Google;
provider.validateSocialToken(providerType, '<id-token>')
.then(() => {
// Token is valid
})
.catch(error => {
// Handle invalid or expired token
});
```

## License

Cognito-idp is available under the MIT license. See the LICENSE file for more info.
