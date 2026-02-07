const AWS = require('aws-sdk');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const dynamo = new AWS.DynamoDB.DocumentClient();
const { JWT_SECRET, USERS_TABLE } = process.env;
const SALT_ROUNDS = 12;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

const jsonResponse = (statusCode, payload) => ({
  statusCode,
  headers: {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  },
  body: JSON.stringify(payload),
});

const parseBody = (event) => {
  if (!event || !event.body) return null;
  try {
    return JSON.parse(event.body);
  } catch (err) {
    return null;
  }
};

const requireConfig = () => {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET not set');
  }
  if (!USERS_TABLE) {
    throw new Error('USERS_TABLE not set');
  }
};

const getUserByEmail = async (email) => {
  const result = await dynamo
    .get({ TableName: USERS_TABLE, Key: { email } })
    .promise();
  return result.Item;
};

const createUser = async ({ email, hashedPassword }) => {
  const now = new Date().toISOString();
  await dynamo
    .put({
      TableName: USERS_TABLE,
      Item: { email, hashedPassword, createdAt: now, updatedAt: now },
      ConditionExpression: 'attribute_not_exists(email)',
    })
    .promise();
};

const signJwt = (email) => jwt.sign({ sub: email, email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

const signup = async (event) => {
  try {
    requireConfig();
    const body = parseBody(event);
    if (!body || !body.email || !body.password) {
      return jsonResponse(400, { message: 'email and password are required' });
    }

    const { email, password } = body;

    const existing = await getUserByEmail(email);
    if (existing) {
      return jsonResponse(409, { message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await createUser({ email, hashedPassword });

    return jsonResponse(201, { message: 'User created' });
  } catch (err) {
    console.error('Signup failed', err);
    if (err.code === 'ConditionalCheckFailedException') {
      return jsonResponse(409, { message: 'User already exists' });
    }
    return jsonResponse(500, { message: 'Unable to create user' });
  }
};

const login = async (event) => {
  try {
    requireConfig();
    const body = parseBody(event);
    if (!body || !body.email || !body.password) {
      return jsonResponse(400, { message: 'email and password are required' });
    }

    const { email, password } = body;
    const user = await getUserByEmail(email);
    if (!user || !user.hashedPassword) {
      return jsonResponse(401, { message: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.hashedPassword);
    if (!valid) {
      return jsonResponse(401, { message: 'Invalid credentials' });
    }

    const token = signJwt(email);
    return jsonResponse(200, { token, tokenType: 'Bearer', expiresIn: JWT_EXPIRES_IN });
  } catch (err) {
    console.error('Login failed', err);
    return jsonResponse(500, { message: 'Unable to login' });
  }
};

// Lightweight JWT verification helper for future secured routes
const verifyJwt = (event) => {
  requireConfig();
  const authHeader = event?.headers?.Authorization || event?.headers?.authorization;
  if (!authHeader) {
    throw new Error('Missing Authorization header');
  }
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  return jwt.verify(token, JWT_SECRET);
};

module.exports = {
  signup,
  login,
  verifyJwt,
};
