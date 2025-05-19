package com.liftric.cognito.idp.social

import com.liftric.cognito.idp.core.Result
import com.liftric.cognito.idp.core.SignInResponse
import com.liftric.cognito.idp.core.SocialProvider

interface SocialIdentityProvider {
    suspend fun socialLogin(provider: SocialProvider, authCode: String): Result<SignInResponse>
    suspend fun validateSocialToken(provider: SocialProvider, token: String): Result<Unit>
}