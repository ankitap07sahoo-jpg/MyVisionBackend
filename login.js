const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getUserByEmail } = require('../../models/user');

const { JWT_SECRET } = process.env;
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
    if (!event || !event.body) {
        return null;
    }
    try {
        return JSON.parse(event.body);
    } catch (error) {
        return null;
    }
};

const generateToken = (user) => {
    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET is not configured');
    }

    return jwt.sign(
        {
            sub: user.email,
            email: user.email,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
};

exports.login = async (event) => {
    const body = parseBody(event);
    if (!body) {
        return jsonResponse(400, { message: 'Invalid request payload' });
    }

    const { email, password } = body;
    if (!email || !password) {
        return jsonResponse(400, { message: 'Email and password are required' });
    }

    try {
        const user = await getUserByEmail(email);

        if (!user || !user.hashedPassword) {
            return jsonResponse(401, { message: 'Invalid email or password' });
        }

        const passwordMatches = await bcrypt.compare(password, user.hashedPassword);

        if (!passwordMatches) {
            return jsonResponse(401, { message: 'Invalid email or password' });
        }

        const token = generateToken(user);

        return jsonResponse(200, {
            token,
            tokenType: 'Bearer',
            expiresIn: JWT_EXPIRES_IN,
        });
    } catch (error) {
        console.error('Login failed', error);
        return jsonResponse(500, { message: 'Unable to login' });
    }
};