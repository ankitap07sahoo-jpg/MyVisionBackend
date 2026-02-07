const { getUserByEmail } = require('../models/user');

const jsonResponse = (statusCode, payload) => ({
    statusCode,
    headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
    },
    body: JSON.stringify(payload),
});

exports.getUserDetails = async (event) => {
    const auth = event.requestContext?.authorizer || {};
    const email = auth.email || auth.sub;

    if (!email) {
        return jsonResponse(401, { message: 'Unauthorized' });
    }

    try {
        const user = await getUserByEmail(email);

        if (!user) {
            return jsonResponse(404, { message: 'User not found' });
        }

        const { hashedPassword, ...safeUser } = user;

        return jsonResponse(200, safeUser);
    } catch (error) {
        console.error('Failed to fetch user', error);
        return jsonResponse(500, { message: 'Unable to fetch user profile' });
    }
};