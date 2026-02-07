const bcrypt = require('bcrypt');
const { createUser, getUserByEmail } = require('../../models/user');

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

exports.register = async (event) => {
    const body = parseBody(event);
    if (!body) {
        return jsonResponse(400, { message: 'Invalid request payload' });
    }

    const { email, password } = body;
    if (!email || !password) {
        return jsonResponse(400, { message: 'Email and password are required' });
    }

    try {
        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            return jsonResponse(409, { message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        await createUser({
            email,
            hashedPassword,
        });

        return jsonResponse(201, { message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration failed', error);

        if (error.code === 'ConditionalCheckFailedException') {
            return jsonResponse(409, { message: 'User already exists' });
        }

        return jsonResponse(500, { message: 'Error registering user' });
    }
};