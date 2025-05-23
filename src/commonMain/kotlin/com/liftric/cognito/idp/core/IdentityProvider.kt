package com.liftric.cognito.idp.core

interface IdentityProvider {
    /**
     * Signs up a new user
     * @param username The username
     * @param password The password
     * @param attributes Optional account attributes e.g. email, phone number, ...
     * @return Result object containing SignUpResponse on success or an error on failure
     */
    suspend fun signUp(username: String, password: String, attributes: List<UserAttribute>? = null, clientMetadata: Map<String, String>? = null): Result<SignUpResponse>

    /**
     * Confirms sign up of a new user
     * @param username The username
     * @param confirmationCode The confirmation code that was sent to the users' delivery medium
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun confirmSignUp(username: String, confirmationCode: String): Result<Unit>

    /**
     * Signs in the user with the given parameters using custom authentication flow.
     * @param username The username
     * @param password The password
     * @return Result object containing SignInResponse on success or an error on failure
     */
    suspend fun customAuth(username: String, password: String): Result<SignInResponse>

    /**
     * Resends the confirmation (for confirmation of registration) to a specific user in the user pool.
     * @param username The username
     * @return Result object containing ResendConfirmationCodeResponse on success or an error on failure
     */
    suspend fun resendConfirmationCode(username: String): Result<ResendConfirmationCodeResponse>

    /**
     * Signs in the user with the given parameters
     * @param username The username
     * @param password The password
     * @return Result object containing SignInResponse on success or an error on failure
     */
    suspend fun signIn(username: String, password: String): Result<SignInResponse>

    /**
     * Responds to the auth challenge of the sign in response
     * @param challengeName The challenge name
     * @param challengeResponses The challenge responses (needed to answer the challenge)
     * @param session The session from the sign in request
     * @return Result object containing SignInResponse on success or an error on failure
     */
    suspend fun respondToAuthChallenge(
        challengeName: String,
        challengeResponses: Map<String, String>,
        session: String
    ): Result<SignInResponse>

    /**
     * Signs in the user with the given parameters
     * @param refreshToken The refresh token
     * @return Result object containing SignInResponse on success or an error on failure
     */
    suspend fun refresh(refreshToken: String): Result<SignInResponse>

    /**
     * Fetches the user object
     * @param accessToken The access token from the sign in request
     * @return Result object containing GetUserResponse on success or an error on failure
     */
    suspend fun getUser(accessToken: String): Result<GetUserResponse>

    /**
     * Updates the users attributes
     * e.g. email, phone number
     * @param accessToken The access token from the sign in request
     * @param attributes List of attributes that should be updated
     * @return Result object containing UpdateUserAttributesResponse on success or an error on failure
     */
    suspend fun updateUserAttributes(accessToken: String, attributes: List<UserAttribute>): Result<UpdateUserAttributesResponse>

    /**
     * Changes the password of the current user
     * @param accessToken The access token from the sign in request
     * @param currentPassword The password to update
     * @param newPassword The new password
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun changePassword(accessToken: String, currentPassword: String, newPassword: String): Result<Unit>

    /**
     * Invokes password forgot and sends a confirmation code the the users' delivery medium
     * @param username The username
     * @return Result object containing CodeDeliveryDetails on success or an error on failure
     */
    suspend fun forgotPassword(username: String, clientMetadata: Map<String, String>? = null): Result<ForgotPasswordResponse>

    /**
     * Confirms forgot password
     * @param username The username
     * @param password The new password that was sent to the users' delivery medium
     * @param confirmationCode The confirmation code that was sent to the users' delivery medium
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun confirmForgotPassword(confirmationCode: String, username: String, password: String): Result<Unit>

    /**
     * Gets the user attribute verification code for the specified attribute name
     * @param accessToken The access token from the sign in request
     * @param attributeName The attribute name
     * @param clientMetadata Optional key-value pairs as input for custom workflows
     * @return Result object containing Unit on CodeDeliveryDetails or an error on failure
     */
    suspend fun getUserAttributeVerificationCode(accessToken: String, attributeName: String, clientMetadata: Map<String, String>? = null): Result<GetAttributeVerificationCodeResponse>

    /**
     * Verifies the specified user attribute
     * @param accessToken The access token from the sign in request
     * @param attributeName The attribute name
     * @param code The confirmation code
     * @return Result object containing Unit on CodeDeliveryDetails or an error on failure
     */
    suspend fun verifyUserAttribute(accessToken: String, attributeName: String, code: String): Result<Unit>

    /**
     * Signs out the user globally
     * @param accessToken The access token from the sign in request
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun signOut(accessToken: String): Result<Unit>

    /**
     * Revokes all access tokens generated by the refresh token
     * @param refreshToken The refresh token from the sign in request
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun revokeToken(refreshToken: String): Result<Unit>

    /**
     * Deletes the users account
     * @param accessToken The access token from the sign in request
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun deleteUser(accessToken: String): Result<Unit>

    /**
     * Setups MFA preferences
     * @param accessToken The access token from the sign in request
     * @param smsMfaSettings SMS MFA prefrence settings
     * @param softwareTokenMfaSettings software token MFA prefrence settings
     * @return Result object containing Unit on success or an error on failure
     */
    suspend fun setUserMFAPreference(
        accessToken: String,
        smsMfaSettings: MfaSettings?,
        softwareTokenMfaSettings: MfaSettings?
    ): Result<Unit>

    /**
     * Associate a TOTP device with the user account
     * @param accessToken The access token from the sign in request
     * @return Result object containing AssociateSoftwareTokenResponse object on success or an error on failure
     */
    suspend fun associateSoftwareToken(
        accessToken: String
    ): Result<AssociateSoftwareTokenResponse>

    /**
     * Associate a TOTP device with the user account
     * @param session The session that should be passed both ways in challenge-response calls to the service. This allows authentication of the user as part of the MFA setup process.
     * @return Result object containing AssociateSoftwareTokenResponse object on success or an error on failure
     */
    suspend fun associateSoftwareTokenBySession(
        session: String
    ): Result<AssociateSoftwareTokenResponse>

    /**
     * Verifies TOTP code and mark the user's software token MFA status as "verified"
     * @param accessToken The access token from the sign in request
     * @param friendlyDeviceName Name of the device the token was generated on
     * @param userCode One-time password computed using the secret code returned by associateSoftwareToken
     * @return Result object containing VerifySoftwareTokenResponse object on success or an error on failure
     */
    suspend fun verifySoftwareToken(
        accessToken: String,
        friendlyDeviceName: String?,
        userCode: String
    ): Result<VerifySoftwareTokenResponse>

    /**
     * Verifies TOTP code and mark the user's software token MFA status as "verified"
     * @param friendlyDeviceName Name of the device the token was generated on
     * @param session The session that should be passed both ways in challenge-response calls to the service. This allows authentication of the user as part of the MFA setup process.
     * @param userCode One-time password computed using the secret code returned by associateSoftwareToken
     * @return Result object containing VerifySoftwareTokenResponse object on success or an error on failure
     */
    suspend fun verifySoftwareTokenBySession(
        session: String,
        friendlyDeviceName: String?,
        userCode: String
    ): Result<VerifySoftwareTokenResponse>

    /**
     * Initiates social login with the specified provider
     * @param provider The social provider (Google or Facebook)
     * @param authCode The authorization code from the provider
     * @return Result containing SignInResponse with Cognito JWTs on success or an error on failure
     */
    suspend fun socialLogin(provider: SocialProvider, authCode: String): Result<SignInResponse>

    /**
     * Validates a social provider's token
     * @param provider The social provider
     * @param token The token to validate
     * @return Result containing Unit on success or an error on failure
     */
    suspend fun validateSocialToken(provider: SocialProvider, token: String): Result<Unit>
}
