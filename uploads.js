const AWS = require('aws-sdk');
const path = require('path');

const s3 = new AWS.S3();
const { S3_BUCKET } = process.env;

const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || `${5 * 1024 * 1024}`, 10); // 5 MB default
const ALLOWED_MIME_TYPES = (process.env.ALLOWED_UPLOAD_MIME_TYPES || 'image/png,image/jpeg,application/pdf').split(',');
const SIGNED_URL_EXPIRES_SECONDS = parseInt(process.env.UPLOAD_URL_TTL || '300', 10); // 5 minutes

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

const sanitizeFileName = (fileName = '') => fileName.replace(/[^A-Za-z0-9._-]/g, '-');

exports.uploadFile = async (event) => {
    const auth = event.requestContext?.authorizer || {};
    const userId = auth.sub || auth.email;

    if (!userId) {
        return jsonResponse(401, { message: 'Unauthorized' });
    }

    const body = parseBody(event);
    const { fileName, contentType, contentLength } = body || {};

    if (!fileName || !contentType || typeof contentLength !== 'number') {
        return jsonResponse(400, { message: 'fileName, contentType, and contentLength are required' });
    }

    if (!ALLOWED_MIME_TYPES.includes(contentType)) {
        return jsonResponse(415, { message: 'Unsupported file type' });
    }

    if (contentLength <= 0 || contentLength > MAX_UPLOAD_BYTES) {
        return jsonResponse(413, { message: `File too large. Max size is ${MAX_UPLOAD_BYTES} bytes` });
    }

    if (!S3_BUCKET) {
        return jsonResponse(500, { message: 'S3 bucket not configured' });
    }

    const sanitized = sanitizeFileName(path.basename(fileName));
    const objectKey = `uploads/${userId}/${Date.now()}-${sanitized}`;

    try {
        const uploadUrl = await s3.getSignedUrlPromise('putObject', {
            Bucket: S3_BUCKET,
            Key: objectKey,
            ContentType: contentType,
            Expires: SIGNED_URL_EXPIRES_SECONDS,
        });

        return jsonResponse(200, {
            uploadUrl,
            key: objectKey,
            expiresIn: SIGNED_URL_EXPIRES_SECONDS,
            maxBytes: MAX_UPLOAD_BYTES,
            allowedMimeTypes: ALLOWED_MIME_TYPES,
        });
    } catch (error) {
        console.error('Failed to create upload URL', error);
        return jsonResponse(500, { message: 'File upload initialization failed' });
    }
};