const jwt = require('jsonwebtoken');

const { JWT_SECRET } = process.env;

const extractToken = (event) => {
    const headerToken = event?.authorizationToken || event?.headers?.Authorization || event?.headers?.authorization;
    if (!headerToken) {
        return null;
    }

    return headerToken.startsWith('Bearer ') ? headerToken.slice(7) : headerToken;
};

const generatePolicy = (principalId, effect, resource, context = {}) => ({
    principalId,
    policyDocument: {
        Version: '2012-10-17',
        Statement: [
            {
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: resource,
            },
        ],
    },
    context,
});

exports.authorize = async (event) => {
    const token = extractToken(event);

    if (!token) {
        console.warn('Authorization token missing');
        throw 'Unauthorized';
    }

    if (!JWT_SECRET) {
        console.error('JWT_SECRET is not configured');
        throw 'Unauthorized';
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const principalId = decoded.sub || decoded.email || 'user';

        return generatePolicy(principalId, 'Allow', event.methodArn, {
            email: decoded.email || '',
            sub: decoded.sub || '',
        });
    } catch (error) {
        console.error('Authorization failed', error);
        throw 'Unauthorized';
    }
};