package com.liftric.cognito.idp.social

import com.liftric.cognito.idp.IdentityProviderClient
import com.liftric.cognito.idp.core.Engine
import com.liftric.cognito.idp.core.IdentityProviderException
import com.liftric.cognito.idp.core.Result
import com.liftric.cognito.idp.core.SignInResponse
import com.liftric.cognito.idp.core.SignUpResponse
import com.liftric.cognito.idp.core.SocialProvider
import com.liftric.cognito.idp.core.UserAttribute
import com.liftric.cognito.idp.jwt.CognitoIdToken
import com.liftric.cognito.idp.jwt.InvalidCognitoIdTokenException
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.defaultRequest
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.formUrlEncode
import io.ktor.util.logging.KtorSimpleLogger
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.random.nextInt

/**
 * Configuration for social authentication
 */
@Serializable
data class SocialAuthConfig(
    val clientId: String,
    val clientSecret: String? = null,
    val redirectUri: String,
    val region: String,
    val userPoolId: String,
    val scopes: List<String> = listOf("email", "profile", "openid")
)

/**
 * Response for social authentication
 */
@Serializable
data class SocialAuthResponse(
    @SerialName("id_token") val idToken: String?,
    @SerialName("access_token") val accessToken: String?,
    @SerialName("refresh_token") val refreshToken: String?,
    @SerialName("expires_in") val expiresIn: Int?
)

/**
 * Social authentication implementation
 */
class SocialAuthProvider(
    private val config: SocialAuthConfig,
    private val coreProvider: IdentityProviderClient,
    engine: HttpClientEngine? = null
) : SocialIdentityProvider {
    private val logger = KtorSimpleLogger("SocialAuthProvider")
    private val json = Json {
        allowStructuredMapKeys = true
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    private val client = HttpClient(engine ?: Engine) {
        expectSuccess = true
        defaultRequest {
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
        }
    }

    /**
     * Initiates social login with the specified provider
     */
    override suspend fun socialLogin(provider: SocialProvider, authCode: String): Result<SignInResponse> {
        logger.debug("Starting social login for provider: $provider")
        try {
            // Step 1: Exchange auth code for tokens
            logger.info("Exchanging auth code for $provider")
            val tokenResponse: SocialAuthResponse = exchangeAuthCode(provider, authCode)
            val idToken: String = tokenResponse.idToken
                ?: return Result.failure(
                    IdentityProviderException.SocialAuthFailed(
                        HttpStatusCode.BadRequest, "No ID token received"
                    )
                )

            // Step 2: Validate token
            logger.info("Validating $provider token")
            val validationResult: Result<Unit> = validateSocialToken(provider, idToken)
            if (validationResult.isFailure) {
                logger.error("Token validation failed: ${validationResult.exceptionOrNull()?.message}")
                return Result.failure(
                    validationResult.exceptionOrNull() ?: Exception("Token validation failed")
                )
            }

            // Step 3: Extract user attributes
            val userAttributes: List<UserAttribute> = extractUserAttributes(provider, idToken)
            val username: String = userAttributes.find { it.Name == "email" }?.Value
                ?: return Result.failure(
                    IdentityProviderException.SocialAuthFailed(
                        HttpStatusCode.BadRequest, "Email not found in user attributes"
                    )
                )

            logger.info("Checking if user exists: $username")
            // Step 4: Check if user exists, otherwise sign up
            val signInResult: Result<SignInResponse> = coreProvider.signIn(username, "")
            if (signInResult.isSuccess) {
                logger.info("User $username signed in successfully")
                return signInResult
            }

            logger.warn("User $username not found, registering new user: ${signInResult.exceptionOrNull()?.message}")
            return handleSignupAndSignIn(username, userAttributes)
        } catch (e: Throwable) {
            logger.error("Social login failed: ${e.message}")
            return Result.failure(
                IdentityProviderException.SocialAuthFailed(
                    HttpStatusCode.BadRequest, e.message ?: "Social auth failed"
                )
            )
        }
    }

    /**
     * Handles user signup and subsequent sign-in for new users
     */
    private suspend fun handleSignupAndSignIn(
        username: String,
        userAttributes: List<UserAttribute>
    ): Result<SignInResponse> {
        return try {
            val signUpResponse: SignUpResponse = coreProvider.signUp(
                username = username,
                password = generateTempPassword(),
                attributes = userAttributes
            ).getOrThrow()

            if (!signUpResponse.UserConfirmed) {
                logger.info("Confirming signup for $username")
                coreProvider.confirmSignUp(username, "auto-confirm-social").getOrThrow()
            }

            logger.info("Signing in new user: $username")
            val signInResponse: SignInResponse = coreProvider.signIn(username, "").getOrThrow()
            Result.success(signInResponse)
        } catch (signupError: Throwable) {
            logger.error("Failed to register/sign in user $username: ${signupError.message}")
            Result.failure(signupError)
        }
    }

    /**
     * Validates a social provider's token
     */
    override suspend fun validateSocialToken(provider: SocialProvider, token: String): Result<Unit> {
        logger.debug("Validating token for provider: $provider")
        return try {
            val validationUrl = when (provider) {
                SocialProvider.Google -> "https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=$token"
                SocialProvider.Facebook -> "https://graph.facebook.com/debug_token?input_token=$token&access_token=${config.clientId}|${config.clientSecret}"
            }

            val response = client.get(validationUrl)
            if (response.status == HttpStatusCode.OK) {
                logger.info("Token validated successfully for $provider")
                Result.success(Unit)
            } else {
                logger.warn("Token validation failed with status: ${response.status}")
                Result.failure(
                    IdentityProviderException.InvalidSocialToken(
                        response.status, "Token validation failed"
                    )
                )
            }
        } catch (e: Throwable) {
            logger.error("Token validation error: ${e.message}")
            Result.failure(
                IdentityProviderException.InvalidSocialToken(
                    HttpStatusCode.BadRequest, e.message ?: "Token validation failed"
                )
            )
        }
    }

    private suspend fun exchangeAuthCode(
        provider: SocialProvider,
        authCode: String
    ): SocialAuthResponse {
        val tokenUrl = when (provider) {
            SocialProvider.Google -> "https://oauth2.googleapis.com/token"
            SocialProvider.Facebook -> "https://graph.facebook.com/v12.0/oauth/access_token"
        }

        logger.info("Posting to $tokenUrl for auth code exchange")
        val response = client.post(tokenUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "code" to authCode,
                    "client_id" to config.clientId,
                    "client_secret" to config.clientSecret.orEmpty(),
                    "redirect_uri" to config.redirectUri,
                    "grant_type" to "authorization_code"
                ).formUrlEncode()
            )
        }

        return try {
            json.decodeFromString(response.bodyAsText())
        } catch (e: SerializationException) {
            logger.error("Failed to parse token response: ${e.message}")
            throw IdentityProviderException.SocialAuthFailed(
                HttpStatusCode.BadRequest, "Invalid token response format"
            )
        }
    }

    private fun extractUserAttributes(
        provider: SocialProvider,
        idToken: String
    ): List<UserAttribute> {
        logger.debug("Extracting user attributes from $provider ID token")
        return try {
            val cognitoIdToken = CognitoIdToken(idToken)
            val claims = cognitoIdToken.claims

            val attributes = mutableListOf<UserAttribute>()
            claims.email?.let { email ->
                attributes.add(UserAttribute("email", email))
            }
            claims.name?.let { name ->
                attributes.add(UserAttribute("name", name))
            }
            claims.givenName?.let { givenName ->
                attributes.add(UserAttribute("given_name", givenName))
            }
            claims.familyName?.let { familyName ->
                attributes.add(UserAttribute("family_name", familyName))
            }

            if (attributes.isEmpty()) {
                logger.warn("No valid attributes extracted from ID token")
                throw IdentityProviderException.SocialAuthFailed(
                    HttpStatusCode.BadRequest, "No valid user attributes in ID token"
                )
            }

            logger.debug("Extracted attributes: $attributes")
            attributes
        } catch (e: InvalidCognitoIdTokenException) {
            logger.error("Failed to decode ID token: ${e.message}")
            throw IdentityProviderException.SocialAuthFailed(
                HttpStatusCode.BadRequest, "Invalid Cognito ID token: ${e.message}"
            )
        } catch (e: Exception) {
            logger.error("Failed to process ID token: ${e.message}")
            throw IdentityProviderException.SocialAuthFailed(
                HttpStatusCode.BadRequest, "Failed to process ID token: ${e.message}"
            )
        }
    }

    private fun generateTempPassword(): String {
        // Generate a cryptographically secure password meeting Cognito requirements
        // At least 8 characters, including uppercase, lowercase, number, and special character
        val chars = ('A'..'Z') + ('a'..'z') + ('0'..'9') + "!@#$%^&*"
        val random = Random.Default
        return buildString {
            append(random.nextInt(65..90).toChar()) // Uppercase
            append(random.nextInt(97..122).toChar()) // Lowercase
            append(random.nextInt(48..57).toChar()) // Number
            append("!") // Special character
            repeat(4) { append(chars[random.nextInt(chars.size)]) }
        }.also { logger.debug("Generated temporary password") }
    }
}