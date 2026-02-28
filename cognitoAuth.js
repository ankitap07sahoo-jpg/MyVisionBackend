/**
 * AWS Cognito Authentication Module
 * 
 * This module provides a wrapper around AWS Cognito User Pools
 * to handle user authentication, registration, and verification.
 * 
 * Features:
 * - Email-based sign up with verification
 * - Secure login with JWT tokens
 * - Email verification flow
 * - Token management
 * - Password reset functionality
 */

const AWS = require('aws-sdk');

// Cognito User Pool Configuration
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';

// Configuration Validation
const isCognitoConfigured = () => {
  if (!USER_POOL_ID || !CLIENT_ID) {
    console.error('❌ COGNITO CONFIGURATION MISSING!');
    console.error('Required environment variables:');
    console.error(`  - COGNITO_USER_POOL_ID: ${USER_POOL_ID ? '✓ Set' : '✗ Missing'}`);
    console.error(`  - COGNITO_CLIENT_ID: ${CLIENT_ID ? '✓ Set' : '✗ Missing'}`);
    console.error('\nPlease run: node setup-cognito.js');
    return false;
  }
  return true;
};

// Initialize Cognito Service Provider
const cognito = new AWS.CognitoIdentityServiceProvider({
  region: AWS_REGION
});

/**
 * Sign up a new user with email and password
 * Cognito will automatically send verification email
 * 
 * @param {string} email - User's email address
 * @param {string} password - User's password (must meet policy requirements)
 * @returns {object} - Sign up result with userId and status
 */
const signUpUser = async (email, password) => {
  // Check configuration first
  if (!isCognitoConfigured()) {
    return {
      success: false,
      error: 'CONFIG_ERROR',
      message: 'Cognito is not configured. Please run setup-cognito.js script first.'
    };
  }

  try {
    const params = {
      ClientId: CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [
        {
          Name: 'email',
          Value: email
        }
      ],
      // Optional: Add custom attributes if needed
      // ValidationData: []
    };

    console.log(`📝 Signing up user: ${email}`);
    const result = await cognito.signUp(params).promise();

    return {
      success: true,
      userId: result.UserSub,
      userConfirmed: result.UserConfirmed,
      codeDeliveryDetails: result.CodeDeliveryDetails,
      message: 'User registered successfully. Please check your email for verification code.'
    };

  } catch (error) {
    console.error('❌ Cognito Sign Up Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });
    
    // Handle specific Cognito errors
    switch (error.code) {
      case 'UsernameExistsException':
        return {
          success: false,
          error: 'EMAIL_EXISTS',
          message: 'An account with this email already exists.'
        };
      case 'InvalidPasswordException':
        return {
          success: false,
          error: 'INVALID_PASSWORD',
          message: 'Password does not meet requirements. Must be at least 8 characters with uppercase, lowercase, and numbers.'
        };
      case 'InvalidParameterException':
        return {
          success: false,
          error: 'INVALID_PARAMETER',
          message: error.message
        };
      default:
        return {
          success: false,
          error: 'SIGNUP_FAILED',
          message: 'Registration failed. Please try again.'
        };
    }
  }
};

/**
 * Verify user's email with the code sent by Cognito
 * 
 * @param {string} email - User's email address
 * @param {string} code - Verification code from email
 * @returns {object} - Verification result
 */
const verifyEmail = async (email, code) => {
  // Check configuration first
  if (!isCognitoConfigured()) {
    return {
      success: false,
      error: 'CONFIG_ERROR',
      message: 'Cognito is not configured. Please run setup-cognito.js script first.'
    };
  }

  try {
    const params = {
      ClientId: CLIENT_ID,
      Username: email,
      ConfirmationCode: code
    };

    console.log(`✉️ Verifying email: ${email}`);
    await cognito.confirmSignUp(params).promise();

    return {
      success: true,
      message: 'Email verified successfully. You can now login.'
    };

  } catch (error) {
    console.error('❌ Cognito Verify Email Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });

    switch (error.code) {
      case 'CodeMismatchException':
        return {
          success: false,
          error: 'INVALID_CODE',
          message: 'Invalid verification code. Please try again.'
        };
      case 'ExpiredCodeException':
        return {
          success: false,
          error: 'CODE_EXPIRED',
          message: 'Verification code has expired. Please request a new one.'
        };
      case 'NotAuthorizedException':
        return {
          success: false,
          error: 'ALREADY_VERIFIED',
          message: 'User is already verified.'
        };
      default:
        return {
          success: false,
          error: 'VERIFICATION_FAILED',
          message: 'Verification failed. Please try again.'
        };
    }
  }
};

/**
 * Sign in user with email and password
 * Returns JWT tokens (AccessToken, IdToken, RefreshToken)
 * 
 * @param {string} email - User's email address
 * @param {string} password - User's password
 * @returns {object} - Authentication result with tokens
 */
const signInUser = async (email, password) => {
  // Check configuration first
  if (!isCognitoConfigured()) {
    return {
      success: false,
      error: 'CONFIG_ERROR',
      message: 'Cognito is not configured. Please run setup-cognito.js script first.'
    };
  }

  try {
    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password
      }
    };

    console.log(`🔐 Signing in user: ${email}`);
    const result = await cognito.initiateAuth(params).promise();

    return {
      success: true,
      tokens: {
        accessToken: result.AuthenticationResult.AccessToken,
        idToken: result.AuthenticationResult.IdToken,
        refreshToken: result.AuthenticationResult.RefreshToken,
        expiresIn: result.AuthenticationResult.ExpiresIn
      },
      message: 'Login successful'
    };

  } catch (error) {
    console.error('❌ Cognito Sign In Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });

    switch (error.code) {
      case 'NotAuthorizedException':
        return {
          success: false,
          error: 'INVALID_CREDENTIALS',
          message: 'Incorrect email or password.'
        };
      case 'UserNotConfirmedException':
        return {
          success: false,
          error: 'EMAIL_NOT_VERIFIED',
          message: 'Please verify your email before logging in.',
          needsVerification: true
        };
      case 'UserNotFoundException':
        return {
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'No account found with this email.'
        };
      case 'TooManyRequestsException':
        return {
          success: false,
          error: 'TOO_MANY_ATTEMPTS',
          message: 'Too many login attempts. Please try again later.'
        };
      default:
        return {
          success: false,
          error: 'LOGIN_FAILED',
          message: 'Login failed. Please try again.'
        };
    }
  }
};

/**
 * Resend verification code to user's email
 * 
 * @param {string} email - User's email address
 * @returns {object} - Resend result
 */
const resendVerificationCode = async (email) => {
  // Check configuration first
  if (!isCognitoConfigured()) {
    return {
      success: false,
      error: 'CONFIG_ERROR',
      message: 'Cognito is not configured. Please run setup-cognito.js script first.'
    };
  }

  try {
    const params = {
      ClientId: CLIENT_ID,
      Username: email
    };

    console.log(`📧 Resending verification code: ${email}`);
    const result = await cognito.resendConfirmationCode(params).promise();

    return {
      success: true,
      codeDeliveryDetails: result.CodeDeliveryDetails,
      message: 'Verification code sent to your email.'
    };

  } catch (error) {
    console.error('❌ Cognito Resend Code Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });

    switch (error.code) {
      case 'UserNotFoundException':
        return {
          success: false,
          error: 'USER_NOT_FOUND',
          message: 'No account found with this email.'
        };
      case 'InvalidParameterException':
        return {
          success: false,
          error: 'ALREADY_VERIFIED',
          message: 'User is already verified.'
        };
      case 'LimitExceededException':
        return {
          success: false,
          error: 'LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.'
        };
      default:
        return {
          success: false,
          error: 'RESEND_FAILED',
          message: 'Failed to resend code. Please try again.'
        };
    }
  }
};

/**
 * Verify JWT token from Cognito
 * Use this for protecting API endpoints
 * 
 * @param {string} token - JWT token (AccessToken or IdToken)
 * @returns {object} - Token verification result with user info
 */
const verifyToken = async (token) => {
  try {
    const params = {
      AccessToken: token
    };

    const result = await cognito.getUser(params).promise();

    // Extract user attributes
    const attributes = {};
    result.UserAttributes.forEach(attr => {
      attributes[attr.Name] = attr.Value;
    });

    return {
      success: true,
      user: {
        username: result.Username,
        email: attributes.email,
        emailVerified: attributes.email_verified === 'true',
        sub: attributes.sub
      }
    };

  } catch (error) {
    console.error('❌ Token Verification Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });

    return {
      success: false,
      error: 'INVALID_TOKEN',
      message: 'Invalid or expired token.'
    };
  }
};

/**
 * Refresh access token using refresh token
 * 
 * @param {string} refreshToken - Refresh token from login
 * @returns {object} - New tokens
 */
const refreshAccessToken = async (refreshToken) => {
  try {
    const params = {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken
      }
    };

    const result = await cognito.initiateAuth(params).promise();

    return {
      success: true,
      tokens: {
        accessToken: result.AuthenticationResult.AccessToken,
        idToken: result.AuthenticationResult.IdToken,
        expiresIn: result.AuthenticationResult.ExpiresIn
      }
    };

  } catch (error) {
    console.error('❌ Token Refresh Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });
    return {
      success: false,
      error: 'REFRESH_FAILED',
      message: 'Failed to refresh token. Please login again.'
    };
  }
};

/**
 * Initiate password reset - sends code to email
 * 
 * @param {string} email - User's email address
 * @returns {object} - Password reset initiation result
 */
const forgotPassword = async (email) => {
  try {
    const params = {
      ClientId: CLIENT_ID,
      Username: email
    };

    const result = await cognito.forgotPassword(params).promise();

    return {
      success: true,
      codeDeliveryDetails: result.CodeDeliveryDetails,
      message: 'Password reset code sent to your email.'
    };

  } catch (error) {
    console.error('❌ Forgot Password Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });

    return {
      success: false,
      error: 'FORGOT_PASSWORD_FAILED',
      message: error.message || 'Failed to initiate password reset.'
    };
  }
};

/**
 * Confirm password reset with code
 * 
 * @param {string} email - User's email address
 * @param {string} code - Verification code from email
 * @param {string} newPassword - New password
 * @returns {object} - Password reset result
 */
const confirmForgotPassword = async (email, code, newPassword) => {
  try {
    const params = {
      ClientId: CLIENT_ID,
      Username: email,
      ConfirmationCode: code,
      Password: newPassword
    };

    await cognito.confirmForgotPassword(params).promise();

    return {
      success: true,
      message: 'Password reset successfully. You can now login with your new password.'
    };

  } catch (error) {
    console.error('❌ Confirm Forgot Password Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });

    switch (error.code) {
      case 'CodeMismatchException':
        return {
          success: false,
          error: 'INVALID_CODE',
          message: 'Invalid verification code.'
        };
      case 'ExpiredCodeException':
        return {
          success: false,
          error: 'CODE_EXPIRED',
          message: 'Verification code has expired. Please request a new one.'
        };
      default:
        return {
          success: false,
          error: 'RESET_FAILED',
          message: 'Password reset failed. Please try again.'
        };
    }
  }
};

/**
 * Sign out user (invalidate tokens)
 * 
 * @param {string} accessToken - User's access token
 * @returns {object} - Sign out result
 */
const signOutUser = async (accessToken) => {
  try {
    const params = {
      AccessToken: accessToken
    };

    await cognito.globalSignOut(params).promise();

    return {
      success: true,
      message: 'Signed out successfully.'
    };

  } catch (error) {
    console.error('❌ Sign Out Error:', {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      requestId: error.requestId
    });
    return {
      success: false,
      error: 'SIGNOUT_FAILED',
      message: 'Sign out failed.'
    };
  }
};

module.exports = {
  signUpUser,
  verifyEmail,
  signInUser,
  resendVerificationCode,
  verifyToken,
  refreshAccessToken,
  forgotPassword,
  confirmForgotPassword,
  signOutUser
};
