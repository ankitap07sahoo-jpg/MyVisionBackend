const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const dynamo = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();

// Fallback defaults for environment variables
const USERS_TABLE = process.env.USERS_TABLE || "myvision-users";
const JWT_SECRET = process.env.JWT_SECRET || "super_secure_fallback_secret";
const UPLOADS_BUCKET = process.env.UPLOADS_BUCKET || "myvision-uploads";

/* -------------------- HEALTH CHECK -------------------- */
module.exports.hello = async () => {
  return {
    statusCode: 200,
    body: JSON.stringify({ message: "API is running" })
  };
};

/* -------------------- SIGNUP -------------------- */
module.exports.signup = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);

    // Check if user already exists
    const existingUser = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: { ":email": email }
    }).promise();

    if (existingUser.Items && existingUser.Items.length > 0) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Email already registered" })
      };
    }

    const userId = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);

    const user = {
      userId,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    await dynamo.put({
      TableName: USERS_TABLE,
      Item: user
    }).promise();

    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: "1h" });

    return {
      statusCode: 201,
      body: JSON.stringify({ message: "Signup successful", token })
    };

  } catch (err) {
    console.error("Signup error:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal Server Error" })
    };
  }
};

/* -------------------- LOGIN -------------------- */
module.exports.login = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);

    const result = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: { ":email": email }
    }).promise();

    if (!result.Items || result.Items.length === 0) {
      return { statusCode: 401, body: JSON.stringify({ message: "Invalid credentials" }) };
    }

    const user = result.Items[0];
    const valid = await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      return { statusCode: 401, body: JSON.stringify({ message: "Invalid credentials" }) };
    }

    const token = jwt.sign({ userId: user.userId, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    return { statusCode: 200, body: JSON.stringify({ message: "Login successful", token }) };

  } catch (err) {
    console.error("Login error:", err);
    return { statusCode: 500, body: JSON.stringify({ message: "Internal Server Error" }) };
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
