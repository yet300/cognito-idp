@file:JsExport

import IdentityProviderExceptionJs.*
import com.liftric.cognito.idp.IdentityProviderClient
import com.liftric.cognito.idp.core.*
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.promise
import kotlin.js.Promise

/**
 * Typescript compatible [IdentityProviderClient] implementation.
 */
class IdentityProviderClientJS(region: String, clientId: String) {
    private val provider: IdentityProviderClient = IdentityProviderClient(region, clientId)

    fun signUp(
        username: String,
        password: String,
        attributes: Array<UserAttribute>? = null,
        clientMetadata: Array<MapEntry>? = null,
    ): Promise<SignUpResponse> =
        MainScope().promise {
            provider.signUp(
                username = username,
                password = password,
                attributes = attributes?.toList(),
                clientMetadata = clientMetadata?.associate { it.key to it.value }
            ).getOrWrapThrowable()
        }

    fun confirmSignUp(username: String, confirmationCode: String): Promise<Unit> =
        MainScope().promise {
            provider.confirmSignUp(
                username = username,
                confirmationCode = confirmationCode
            ).getOrWrapThrowable()
        }

    fun resendConfirmationCode(username: String): Promise<ResendConfirmationCodeResponse> =
        MainScope().promise {
            provider.resendConfirmationCode(username)
                .getOrWrapThrowable()
        }

    fun signIn(username: String, password: String): Promise<SignInResponseJS> =
        MainScope().promise {
            provider.signIn(username, password)
                .getOrWrapThrowable().let {
                    SignInResponseJS(
                        AuthenticationResult = it.AuthenticationResult,
                        ChallengeParameters = it.ChallengeParameters.toMapEntries(),
                        ChallengeName = it.ChallengeName,
                        Session = it.Session,
                    )
                }
        }

    fun refresh(refreshToken: String): Promise<SignInResponseJS> =
        MainScope().promise {
            provider.refresh(refreshToken)
                .getOrWrapThrowable().let {
                    SignInResponseJS(
                        AuthenticationResult = it.AuthenticationResult,
                        ChallengeParameters = it.ChallengeParameters.toMapEntries(),
                        ChallengeName = it.ChallengeName,
                        Session = it.Session
                    )
                }
        }

    fun getUser(accessToken: String): Promise<GetUserResponseJS> =
        MainScope().promise {
            provider.getUser(accessToken)
                .getOrWrapThrowable().let {
                    GetUserResponseJS(
                        MFAOptions = it.MFAOptions,
                        PreferredMfaSetting = it.PreferredMfaSetting,
                        UserAttributes = it.UserAttributes.toTypedArray(),
                        UserMFASettingList = it.UserMFASettingList.toTypedArray(),
                        Username = it.Username
                    )
                }
        }

    fun updateUserAttributes(
        accessToken: String,
        attributes: Array<UserAttribute>
    ): Promise<UpdateUserAttributesResponseJS> =
        MainScope().promise {
            provider.updateUserAttributes(
                accessToken = accessToken,
                attributes = attributes.toList()
            ).getOrWrapThrowable().let {
                UpdateUserAttributesResponseJS(it.CodeDeliveryDetailsList.toTypedArray())
            }
        }

    fun changePassword(
        accessToken: String,
        currentPassword: String,
        newPassword: String
    ): Promise<Unit> =
        MainScope().promise {
            provider.changePassword(
                accessToken = accessToken,
                currentPassword = currentPassword,
                newPassword = newPassword
            ).getOrWrapThrowable()
        }

    fun forgotPassword(username: String, clientMetadata: Array<MapEntry>? = null): Promise<ForgotPasswordResponse> =
        MainScope().promise {
            provider.forgotPassword(username, clientMetadata?.associate { it.key to it.value })
                .getOrWrapThrowable()
        }

    fun confirmForgotPassword(
        confirmationCode: String,
        username: String,
        password: String
    ): Promise<Unit> =
        MainScope().promise {
            provider.confirmForgotPassword(
                confirmationCode = confirmationCode,
                username = username,
                password = password
            ).getOrWrapThrowable()
        }

    fun getUserAttributeVerificationCode(
        accessToken: String,
        attributeName: String,
        clientMetadata: Array<MapEntry>? = null
    ): Promise<GetAttributeVerificationCodeResponse> =
        MainScope().promise {
            provider.getUserAttributeVerificationCode(
                accessToken = accessToken,
                attributeName = attributeName,
                clientMetadata = clientMetadata?.associate { it.key to it.value }
            ).getOrWrapThrowable()
        }

    fun verifyUserAttribute(
        accessToken: String,
        attributeName: String,
        code: String
    ): Promise<Unit> =
        MainScope().promise {
            provider.verifyUserAttribute(
                accessToken = accessToken,
                attributeName = attributeName,
                code = code
            ).getOrWrapThrowable()
        }

    fun signOut(accessToken: String): Promise<Unit> =
        MainScope().promise {
            provider.signOut(accessToken)
                .getOrWrapThrowable()
        }

    fun revokeToken(refreshToken: String): Promise<Unit> =
        MainScope().promise {
            provider.revokeToken(refreshToken)
                .getOrWrapThrowable()
        }

    fun deleteUser(accessToken: String): Promise<Unit> =
        MainScope().promise {
            provider.deleteUser(accessToken)
                .getOrWrapThrowable()
        }

    fun setUserMFAPreference(
        accessToken: String,
        smsMfaSettings: MfaSettings?,
        softwareTokenMfaSettings: MfaSettings?
    ): Promise<Unit> = MainScope().promise {
        provider.setUserMFAPreference(
            accessToken = accessToken,
            smsMfaSettings = smsMfaSettings,
            softwareTokenMfaSettings = softwareTokenMfaSettings
        ).getOrWrapThrowable()
    }

    fun respondToAuthChallenge(
        challengeName: String,
        challengeResponses: Array<MapEntry>,
        session: String
    ): Promise<SignInResponseJS> = MainScope().promise {
        provider.respondToAuthChallenge(
            challengeName,
            challengeResponses.associate { it.key to it.value },
            session
        ).getOrWrapThrowable().let {
            SignInResponseJS(
                AuthenticationResult = it.AuthenticationResult,
                ChallengeParameters = it.ChallengeParameters.toMapEntries(),
                ChallengeName = it.ChallengeName,
                Session = it.Session
            )
        }
    }

    fun associateSoftwareToken(
        accessToken: String
    ): Promise<AssociateSoftwareTokenResponse> = MainScope().promise {
        provider.associateSoftwareToken(
            accessToken = accessToken
        ).getOrWrapThrowable()
    }

    fun associateSoftwareTokenBySession(
        session: String
    ): Promise<AssociateSoftwareTokenResponse> = MainScope().promise {
        provider.associateSoftwareTokenBySession(
            session = session
        ).getOrWrapThrowable()
    }

    fun verifySoftwareToken(
        accessToken: String,
        friendlyDeviceName: String?,
        userCode: String
    ): Promise<VerifySoftwareTokenResponse> = MainScope().promise {
        provider.verifySoftwareToken(
            accessToken = accessToken,
            friendlyDeviceName = friendlyDeviceName,
            userCode = userCode
        ).getOrWrapThrowable()
    }

    fun verifySoftwareTokenBySession(
        session: String,
        friendlyDeviceName: String?,
        userCode: String
    ): Promise<VerifySoftwareTokenResponse> = MainScope().promise {
        provider.verifySoftwareTokenBySession(
            friendlyDeviceName = friendlyDeviceName,
            session = session,
            userCode = userCode
        ).getOrWrapThrowable()
    }

    private fun <T> Result<T>.getOrWrapThrowable(): T = when (value) {
        is Result.Failure -> {
            val wrapped: IdentityProviderExceptionJs = when(val t = value.exception) {
                is IdentityProviderException -> {
                    when(t) {
                        is IdentityProviderException.CodeMismatch -> CodeMismatch(t.status.value, t.message)
                        is IdentityProviderException.ConcurrentModification -> ConcurrentModification(t.status.value, t.message)
                        is IdentityProviderException.EnableSoftwareTokenMFA -> EnableSoftwareTokenMFA(t.status.value, t.message)
                        is IdentityProviderException.ExpiredCode -> ExpiredCode(t.status.value, t.message)
                        is IdentityProviderException.InternalError -> InternalError(t.status.value, t.message)
                        is IdentityProviderException.InvalidLambdaResponse -> InvalidLambdaResponse(t.status.value, t.message)
                        is IdentityProviderException.InvalidParameter -> InvalidParameter(t.status.value, t.message)
                        is IdentityProviderException.InvalidPassword -> InvalidPassword(t.status.value, t.message)
                        is IdentityProviderException.InvalidUserPoolConfiguration -> InvalidUserPoolConfiguration(t.status.value, t.message)
                        is IdentityProviderException.LimitExceeded -> LimitExceeded(t.status.value, t.message)
                        is IdentityProviderException.NotAuthorized -> NotAuthorized(t.status.value, t.message)
                        is IdentityProviderException.PasswordResetRequired -> PasswordResetRequired(t.status.value, t.message)
                        is IdentityProviderException.ResourceNotFound -> ResourceNotFound(t.status.value, t.message)
                        is IdentityProviderException.SoftwareTokenMFANotFound -> SoftwareTokenMFANotFound(t.status.value, t.message)
                        is IdentityProviderException.TooManyFailedAttempts -> TooManyFailedAttempts(t.status.value, t.message)
                        is IdentityProviderException.TooManyRequests -> TooManyRequests(t.status.value, t.message)
                        is IdentityProviderException.UnexpectedLambda -> UnexpectedLambda(t.status.value, t.message)
                        is IdentityProviderException.Unknown -> Unknown(t.status.value, t.type, t.message)
                        is IdentityProviderException.UserLambdaValidation -> UserLambdaValidation(t.status.value, t.message)
                        is IdentityProviderException.UserNotConfirmed -> UserNotConfirmed(t.status.value, t.message)
                        is IdentityProviderException.UserNotFound -> UserNotFound(t.status.value, t.message)
                        is IdentityProviderException.InvalidSocialToken -> InvalidSocialToken(t.status.value, t.message)
                        is IdentityProviderException.SocialAuthFailed -> SocialAuthFailed(t.status.value, t.message)
                    }
                }
                else -> IdentityProviderExceptionJs.NonCognitoException(t)
            }
            throw wrapped
        }
        else -> value as T
    }
}
