const AWS = require('aws-sdk');

const { DYNAMODB_TABLE } = process.env;
const dynamo = new AWS.DynamoDB.DocumentClient();

const ensureTableConfigured = () => {
    if (!DYNAMODB_TABLE) {
        throw new Error('DYNAMODB_TABLE is not configured');
    }
};

const getUserByEmail = async (email) => {
    ensureTableConfigured();

    const result = await dynamo
        .get({
            TableName: DYNAMODB_TABLE,
            Key: { email },
        })
        .promise();

    return result.Item;
};

const createUser = async ({ email, hashedPassword, metadata = {} }) => {
    ensureTableConfigured();

    const now = new Date().toISOString();
    const item = {
        email,
        hashedPassword,
        createdAt: now,
        updatedAt: now,
        ...metadata,
    };

    await dynamo
        .put({
            TableName: DYNAMODB_TABLE,
            Item: item,
            ConditionExpression: 'attribute_not_exists(email)',
        })
        .promise();

    return item;
};

module.exports = {
    getUserByEmail,
    createUser,
};