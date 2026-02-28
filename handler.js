const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const { generateOTP, generateOTPExpiry, sendSignupOTP, sendLoginOTP, isOTPExpired } = require("./utils/emailService");
const { extractIPAddress, getIPLocation, getDeviceFingerprint, checkRateLimit, performCognitiveCheck } = require("./utils/cognitiveCheck");

const dynamo = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();

// Fallback defaults for environment variables
const USERS_TABLE = process.env.USERS_TABLE || "myvision-users";
const JWT_SECRET = process.env.JWT_SECRET || "super_secure_fallback_secret";
const UPLOADS_BUCKET = process.env.UPLOADS_BUCKET || "myvision-uploads";

// Security constants
const MAX_OTP_ATTEMPTS = 3;
const RATE_LIMIT_WINDOW_MINUTES = 15;
const MAX_LOGIN_ATTEMPTS = 5;

/* -------------------- HEALTH CHECK -------------------- */
module.exports.hello = async () => {
  return {
    statusCode: 200,
    body: JSON.stringify({ message: "API is running" })
  };
};

/* -------------------- TEST EMAIL (FOR DEBUGGING) -------------------- */
module.exports.testEmail = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };

  try {
    const { email } = JSON.parse(event.body || '{}');
    
    if (!email) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email is required" })
      };
    }

    const testOTP = "123456";
    const result = await sendSignupOTP(email, testOTP);

    if (result.success) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          message: "Test email sent successfully! Check your inbox.",
          email,
          note: "This is a test OTP: 123456"
        })
      };
    } else {
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ 
          message: "Failed to send test email",
          error: result.error,
          tip: "Check your AWS SES configuration or SMTP settings in .env"
        })
      };
    }
  } catch (err) {
    console.error("Test email error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        message: "Error sending test email",
        error: err.message,
        tip: "Check CloudWatch logs for details"
      })
    };
  }
};

/* -------------------- RESEND OTP -------------------- */
module.exports.resendOTP = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };

  try {
    const { email } = JSON.parse(event.body);

    if (!email) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email is required" })
      };
    }

    // Get user
    const result = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: { ":email": email }
    }).promise();

    if (!result.Items || result.Items.length === 0) {
      return { 
        statusCode: 404, 
        headers, 
        body: JSON.stringify({ message: "User not found" }) 
      };
    }

    const user = result.Items[0];

    // Check if already verified
    if (user.isEmailVerified) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email already verified" })
      };
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpExpiry = generateOTPExpiry();

    // Update user with new OTP
    await dynamo.update({
      TableName: USERS_TABLE,
      Key: { userId: user.userId },
      UpdateExpression: "SET otp = :otp, otpExpiry = :expiry, otpAttempts = :zero, updatedAt = :now",
      ExpressionAttributeValues: {
        ":otp": otp,
        ":expiry": otpExpiry,
        ":zero": 0,
        ":now": new Date().toISOString()
      }
    }).promise();

    // Send OTP email
    const emailResult = await sendSignupOTP(email, otp);
    
    if (!emailResult.success) {
      console.error("Failed to send OTP email:", {
        error: emailResult.error,
        code: emailResult.code,
        email: email,
        emailFrom: process.env.EMAIL_FROM
      });
      
      // Provide specific error message
      let errorMessage = "Failed to send OTP email. ";
      if (emailResult.error && emailResult.error.includes('not verified')) {
        errorMessage += "The sender email is not verified in AWS SES. Run: node verify-ses-email.js";
      } else if (emailResult.code === 'AccessDenied') {
        errorMessage += "AWS credentials lack SES permissions.";
      } else {
        errorMessage += emailResult.error || "Please contact support.";
      }
      
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ 
          message: errorMessage,
          error: emailResult.error,
          tip: "Check CloudWatch logs or run: node verify-ses-email.js " + (process.env.EMAIL_FROM || "your-email@example.com")
        })
      };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        message: "New OTP sent to your email",
        email
      })
    };

  } catch (err) {
    console.error("Resend OTP error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: "Internal Server Error" })
    };
  }
};

/* -------------------- SIGNUP -------------------- */
module.exports.signup = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };

  try {
    const { email, password } = JSON.parse(event.body);

    // Validate input
    if (!email || !password) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email and password are required" })
      };
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Invalid email format" })
      };
    }

    // Password validation
    if (password.length < 8) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Password must be at least 8 characters long" })
      };
    }

    // Check if user already exists
    const existingUser = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: { ":email": email }
    }).promise();

    let userId;
    let isUpdatingExisting = false;

    // If user exists (verified or not), allow re-registration (overwrite account)
    if (existingUser.Items && existingUser.Items.length > 0) {
      const user = existingUser.Items[0];
      console.log(`User ${email} already exists. Allowing re-registration and overwriting account.`);
      userId = user.userId; // Reuse existing userId
      isUpdatingExisting = true;
    } else {
      // New user
      userId = uuidv4();
    }

    const passwordHash = await bcrypt.hash(password, 10);
    
    // Generate OTP for email verification
    const otp = generateOTP();
    const otpExpiry = generateOTPExpiry();

    const user = {
      userId,
      email,
      passwordHash,
      isEmailVerified: false,
      otp,
      otpExpiry,
      otpAttempts: 0,
      createdAt: isUpdatingExisting ? existingUser.Items[0].createdAt : new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await dynamo.put({
      TableName: USERS_TABLE,
      Item: user
    }).promise();

    // Send OTP to email
    console.log(`📧 Sending signup OTP to ${email}...`);
    const emailResult = await sendSignupOTP(email, otp);
    
    let responseMessage;
    let responseData = {
      userId,
      email,
      isNewUser: !isUpdatingExisting
    };
    
    if (!emailResult.success) {
      console.error("Failed to send OTP email:", {
        error: emailResult.error,
        code: emailResult.code,
        emailFrom: process.env.EMAIL_FROM
      });
      
      // Provide helpful error message
      let errorTip = "";
      if (emailResult.error && emailResult.error.includes('not verified')) {
        errorTip = " Run: node verify-ses-email.js " + (process.env.EMAIL_FROM || "your-email@example.com");
      }
      
      // If email fails (e.g., SES sandbox mode), include OTP in response for testing
      responseMessage = `Account created! Email delivery failed: ${emailResult.error}.${errorTip} Your verification code is: ${otp} (Valid for 5 minutes)`;
      responseData.otp = otp; // Include OTP in response only when email fails
      responseData.emailError = emailResult.error;
      responseData.note = "Email not sent. The sender email must be verified in AWS SES.";
    } else {
      // Email sent successfully - don't include OTP in response
      console.log(`✅ OTP email sent successfully to ${email}`);
      responseMessage = isUpdatingExisting
        ? "Account refreshed. A new verification code has been sent to your email."
        : "User registered successfully! Please check your email for the verification code.";
    }

    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({ 
        message: responseMessage,
        ...responseData
      })
    };

  } catch (err) {
    console.error("Signup error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: "Internal Server Error" })
    };
  }
};

/* -------------------- VERIFY EMAIL -------------------- */
module.exports.verifyEmail = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };

  try {
    const { email, otp } = JSON.parse(event.body);

    if (!email || !otp) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email and OTP are required" })
      };
    }

    // Get user
    const result = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: { ":email": email }
    }).promise();

    if (!result.Items || result.Items.length === 0) {
      return { statusCode: 404, headers, body: JSON.stringify({ message: "User not found" }) };
    }

    const user = result.Items[0];

    // Check if already verified
    if (user.isEmailVerified) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email already verified" })
      };
    }

    // Check OTP attempts
    if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
      return {
        statusCode: 429,
        headers,
        body: JSON.stringify({ message: "Maximum OTP attempts exceeded. Please request a new OTP." })
      };
    }

    // Check OTP expiry
    if (isOTPExpired(user.otpExpiry)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "OTP has expired. Please request a new one." })
      };
    }

    // Verify OTP
    if (user.otp !== otp) {
      // Increment failed attempts
      await dynamo.update({
        TableName: USERS_TABLE,
        Key: { userId: user.userId },
        UpdateExpression: "SET otpAttempts = otpAttempts + :inc",
        ExpressionAttributeValues: { ":inc": 1 }
      }).promise();

      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          message: "Invalid OTP",
          attemptsRemaining: MAX_OTP_ATTEMPTS - (user.otpAttempts + 1)
        })
      };
    }

    // OTP is valid - verify email and clear OTP
    await dynamo.update({
      TableName: USERS_TABLE,
      Key: { userId: user.userId },
      UpdateExpression: "SET isEmailVerified = :verified, otp = :null, otpExpiry = :null, otpAttempts = :zero, updatedAt = :now",
      ExpressionAttributeValues: {
        ":verified": true,
        ":null": null,
        ":zero": 0,
        ":now": new Date().toISOString()
      }
    }).promise();

    // Generate token
    const token = jwt.sign({ userId: user.userId, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        message: "Email verified successfully",
        token
      })
    };

  } catch (err) {
    console.error("Email verification error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: "Internal Server Error" })
    };
  }
};

/* -------------------- LOGIN WITH COGNITIVE CHECKS -------------------- */
module.exports.login = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };

  try {
    const { email, password } = JSON.parse(event.body);

    if (!email || !password) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Email and password are required" })
      };
    }

    // Get user
    const result = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: { ":email": email }
    }).promise();

    if (!result.Items || result.Items.length === 0) {
      return { statusCode: 401, headers, body: JSON.stringify({ message: "Invalid credentials" }) };
    }

    const user = result.Items[0];

    // Rate limiting check
    const loginAttempts = user.loginAttempts || [];
    const rateLimitCheck = checkRateLimit(loginAttempts, RATE_LIMIT_WINDOW_MINUTES, MAX_LOGIN_ATTEMPTS);
    
    if (rateLimitCheck.limited) {
      return {
        statusCode: 429,
        headers,
        body: JSON.stringify({ 
          message: "Too many login attempts. Please try again later.",
          retryAfter: RATE_LIMIT_WINDOW_MINUTES * 60
        })
      };
    }

    // Record login attempt
    const now = new Date().toISOString();
    await dynamo.update({
      TableName: USERS_TABLE,
      Key: { userId: user.userId },
      UpdateExpression: "SET loginAttempts = list_append(if_not_exists(loginAttempts, :empty), :attempt)",
      ExpressionAttributeValues: {
        ":empty": [],
        ":attempt": [now]
      }
    }).promise();

    // Verify password
    const valid = await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      return { statusCode: 401, headers, body: JSON.stringify({ message: "Invalid credentials" }) };
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ 
          message: "Please verify your email before logging in",
          requiresEmailVerification: true
        })
      };
    }

    // Perform cognitive checks
    const cognitiveCheck = performCognitiveCheck(event, user);

    if (cognitiveCheck.suspicious) {
      // Generate OTP for suspicious login
      const otp = generateOTP();
      const otpExpiry = generateOTPExpiry();
      
      // Store OTP and create pending session
      const sessionId = uuidv4();
      await dynamo.update({
        TableName: USERS_TABLE,
        Key: { userId: user.userId },
        UpdateExpression: "SET loginOTP = :otp, loginOTPExpiry = :expiry, loginOTPAttempts = :zero, pendingSessionId = :sessionId, pendingSessionData = :sessionData, updatedAt = :now",
        ExpressionAttributeValues: {
          ":otp": otp,
          ":expiry": otpExpiry,
          ":zero": 0,
          ":sessionId": sessionId,
          ":sessionData": JSON.stringify({
            ip: cognitiveCheck.currentIP,
            location: cognitiveCheck.currentLocation,
            device: cognitiveCheck.currentDevice,
            timestamp: now
          }),
          ":now": now
        }
      }).promise();

      // Send OTP email
      const reason = cognitiveCheck.reasons.join(', ');
      await sendLoginOTP(email, otp, reason);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          requiresOTP: true,
          sessionId,
          message: "Suspicious activity detected. Please verify the OTP sent to your email.",
          reason: cognitiveCheck.reasons
        })
      };
    }

    // Normal login - update login history
    const loginHistory = user.loginHistory || [];
    loginHistory.push({
      timestamp: now,
      ip: cognitiveCheck.currentIP,
      location: cognitiveCheck.currentLocation,
      device: cognitiveCheck.currentDevice
    });

    // Keep only last 10 logins
    const recentHistory = loginHistory.slice(-10);

    await dynamo.update({
      TableName: USERS_TABLE,
      Key: { userId: user.userId },
      UpdateExpression: "SET lastLoginTime = :time, lastLoginIP = :ip, lastLoginLocation = :location, lastLoginDevice = :device, loginHistory = :history, updatedAt = :now",
      ExpressionAttributeValues: {
        ":time": now,
        ":ip": cognitiveCheck.currentIP,
        ":location": cognitiveCheck.currentLocation,
        ":device": cognitiveCheck.currentDevice,
        ":history": recentHistory,
        ":now": now
      }
    }).promise();

    // Generate token
    const token = jwt.sign({ userId: user.userId, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    return { 
      statusCode: 200, 
      headers, 
      body: JSON.stringify({ 
        message: "Login successful", 
        token,
        user: {
          userId: user.userId,
          email: user.email
        }
      }) 
    };

  } catch (err) {
    console.error("Login error:", err);
    return { statusCode: 500, headers, body: JSON.stringify({ message: "Internal Server Error" }) };
  }
};

/* -------------------- VERIFY LOGIN OTP -------------------- */
module.exports.verifyLoginOTP = async (event) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
  };

  try {
    const { sessionId, otp } = JSON.parse(event.body);

    if (!sessionId || !otp) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "Session ID and OTP are required" })
      };
    }

    // Find user with this session ID
    const result = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "pendingSessionId = :sessionId",
      ExpressionAttributeValues: { ":sessionId": sessionId }
    }).promise();

    if (!result.Items || result.Items.length === 0) {
      return { 
        statusCode: 404, 
        headers, 
        body: JSON.stringify({ message: "Invalid session" }) 
      };
    }

    const user = result.Items[0];

    // Check OTP attempts
    if (user.loginOTPAttempts >= MAX_OTP_ATTEMPTS) {
      return {
        statusCode: 429,
        headers,
        body: JSON.stringify({ message: "Maximum OTP attempts exceeded. Please login again." })
      };
    }

    // Check OTP expiry
    if (isOTPExpired(user.loginOTPExpiry)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ message: "OTP has expired. Please login again." })
      };
    }

    // Verify OTP
    if (user.loginOTP !== otp) {
      // Increment failed attempts
      await dynamo.update({
        TableName: USERS_TABLE,
        Key: { userId: user.userId },
        UpdateExpression: "SET loginOTPAttempts = loginOTPAttempts + :inc",
        ExpressionAttributeValues: { ":inc": 1 }
      }).promise();

      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          message: "Invalid OTP",
          attemptsRemaining: MAX_OTP_ATTEMPTS - (user.loginOTPAttempts + 1)
        })
      };
    }

    // OTP is valid - complete login
    const sessionData = JSON.parse(user.pendingSessionData);
    const now = new Date().toISOString();
    
    const loginHistory = user.loginHistory || [];
    loginHistory.push({
      timestamp: now,
      ip: sessionData.ip,
      location: sessionData.location,
      device: sessionData.device
    });

    const recentHistory = loginHistory.slice(-10);

    await dynamo.update({
      TableName: USERS_TABLE,
      Key: { userId: user.userId },
      UpdateExpression: "SET lastLoginTime = :time, lastLoginIP = :ip, lastLoginLocation = :location, lastLoginDevice = :device, loginHistory = :history, loginOTP = :null, loginOTPExpiry = :null, loginOTPAttempts = :zero, pendingSessionId = :null, pendingSessionData = :null, updatedAt = :now",
      ExpressionAttributeValues: {
        ":time": now,
        ":ip": sessionData.ip,
        ":location": sessionData.location,
        ":device": sessionData.device,
        ":history": recentHistory,
        ":null": null,
        ":zero": 0,
        ":now": now
      }
    }).promise();

    // Generate token
    const token = jwt.sign({ userId: user.userId, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        message: "Login verified successfully",
        token,
        user: {
          userId: user.userId,
          email: user.email
        }
      })
    };

  } catch (err) {
    console.error("Login OTP verification error:", err);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ message: "Internal Server Error" })
    };
  }
};

/* -------------------- PROTECTED ROUTE -------------------- */
const getAuthorizationHeader = (headers = {}) => {
  const entry = Object.entries(headers).find(
    ([key]) => key && key.toLowerCase() === "authorization"
  );
  if (!entry) return "";
  return typeof entry[1] === "string" ? entry[1] : String(entry[1] || "");
};

module.exports.getUser = async (event) => {
  try {
    const authHeader = getAuthorizationHeader(event.headers);

    if (!authHeader) {
      return { statusCode: 401, body: JSON.stringify({ message: "Missing Authorization header" }) };
    }

    const [scheme, token] = authHeader.trim().split(/\s+/);
    if (!token || scheme.toLowerCase() !== "bearer") {
      return { statusCode: 401, body: JSON.stringify({ message: "Invalid Authorization format" }) };
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      console.error("JWT verification error:", err);
      return { statusCode: 403, body: JSON.stringify({ message: "Invalid or expired token" }) };
    }

    const result = await dynamo.get({
      TableName: USERS_TABLE,
      Key: { userId: decoded.userId }
    }).promise();

    if (!result.Item) {
      return { statusCode: 404, body: JSON.stringify({ message: "User not found" }) };
    }

    return { statusCode: 200, body: JSON.stringify({ message: "User fetched successfully", data: result.Item }) };

  } catch (err) {
    console.error("getUser error:", err);
    return { statusCode: 500, body: JSON.stringify({ message: "Internal Server Error" }) };
  }
};

/* -------------------- FILE UPLOAD -------------------- */
module.exports.uploadFile = async (event) => {
  const authHeader = getAuthorizationHeader(event.headers);

  if (!authHeader) {
    return { statusCode: 401, body: JSON.stringify({ message: "Missing Authorization header" }) };
  }

  const [scheme, token] = authHeader.trim().split(/\s+/);
  if (!token || scheme.toLowerCase() !== "bearer") {
    return { statusCode: 401, body: JSON.stringify({ message: "Invalid Authorization format" }) };
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    console.error("JWT verification failed for upload:", err);
    return { statusCode: 401, body: JSON.stringify({ message: "Invalid or expired token" }) };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (err) {
    console.error("Failed to parse upload body:", err);
    return { statusCode: 400, body: JSON.stringify({ message: "Invalid JSON body" }) };
  }

  const { fileName, fileContent, contentType } = payload;

  if (!fileName || !fileContent) {
    return { statusCode: 400, body: JSON.stringify({ message: "fileName and fileContent are required" }) };
  }

  const key = `${decoded.userId}/${Date.now()}-${fileName}`;

  try {
    const buffer = Buffer.from(fileContent, "base64");

    await s3.putObject({
      Bucket: UPLOADS_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType || "application/octet-stream"
    }).promise();

    const fileUrl = `https://${UPLOADS_BUCKET}.s3.amazonaws.com/${encodeURIComponent(key)}`;

    console.log("File uploaded:", { key, userId: decoded.userId });

    return {
      statusCode: 200,
      body: JSON.stringify({ message: "File uploaded successfully", url: fileUrl })
    };

  } catch (err) {
    console.error("S3 upload failed:", err);
    return { statusCode: 500, body: JSON.stringify({ message: "Internal Server Error" }) };
  }
};
