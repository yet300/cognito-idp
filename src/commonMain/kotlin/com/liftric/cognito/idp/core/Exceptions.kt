package com.liftric.cognito.idp.core

import io.ktor.http.HttpStatusCode

sealed class IdentityProviderException(val status: HttpStatusCode, message: String): Exception(message) {
    class CodeMismatch(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class ConcurrentModification(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class EnableSoftwareTokenMFA(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class ExpiredCode(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class InternalError(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class InvalidLambdaResponse(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class InvalidParameter(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class InvalidPassword(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class InvalidUserPoolConfiguration(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class LimitExceeded(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class NotAuthorized(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class PasswordResetRequired(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class ResourceNotFound(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class SoftwareTokenMFANotFound(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class TooManyFailedAttempts(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class TooManyRequests(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class UnexpectedLambda(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class UserLambdaValidation(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class UserNotConfirmed(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class UserNotFound(status: HttpStatusCode, message: String): IdentityProviderException(status, message)
    class Unknown(status: HttpStatusCode, val type: String, message: String): IdentityProviderException(status, message)
    class InvalidSocialToken(status: HttpStatusCode, message: String) : IdentityProviderException(status, message)
    class SocialAuthFailed(status: HttpStatusCode, message: String) : IdentityProviderException(status, message)
}