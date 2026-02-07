# Frontend-Backend Integration Guide

## Overview
The MyVision Eye Clinic frontend is now fully integrated with the AWS Serverless backend.

## Backend API Endpoints

Base URL: `https://a4js2xzywi.execute-api.us-east-1.amazonaws.com`

### Authentication Endpoints
- **POST** `/auth/signup` - Create new user account
- **POST** `/auth/login` - Login existing user
- **GET** `/users` - Get user profile (requires JWT token)

### File Upload
- **POST** `/upload` - Upload files to S3 (requires JWT token)

## Frontend Integration Features

### 1. Authentication System
- **Login/Signup Modal** - Users can create accounts and login
- **JWT Token Management** - Tokens stored in localStorage
- **Protected Routes** - Authenticated API calls use Bearer token

### 2. Appointment Form
- Integrated with backend authentication
- Auto-creates user account on first appointment
- Validates input before submission

### 3. User Session Management
- Login state persists across page reloads
- Logout functionality clears tokens
- Auth button updates based on login status

## How to Use

### For Testing:

1. **Open the frontend:**
   ```bash
   cd Frontend
   # Open index.html in a browser (use Live Server or similar)
   ```

2. **Test Authentication:**
   - Click "Login / Signup" in navigation
   - Create an account with email and password
   - JWT token is automatically stored
   - User can access protected endpoints

3. **Test Appointment Form:**
   - Fill out the contact form
   - System auto-creates account if needed
   - Appointment data is linked to backend

### API Integration Code Structure

**API Configuration** (`script.js`):
```javascript
const API_BASE_URL = 'https://a4js2xzywi.execute-api.us-east-1.amazonaws.com';
```

**Authentication Functions:**
- `api.signup(email, password)` - Register new user
- `api.login(email, password)` - Login user
- `api.getUser()` - Fetch user profile
- `api.uploadFile(fileName, fileContent, contentType)` - Upload files

**Token Management:**
- `getToken()` - Retrieve stored JWT
- `setToken(token)` - Save JWT to localStorage
- `clearToken()` - Remove JWT (logout)

## S3 File Upload

**S3 Bucket:** `myvision-uploads`
**Endpoint:** `https://myvision-uploads.s3.us-east-1.amazonaws.com`

Files are stored with path: `{userId}/{timestamp}-{fileName}`

## CORS Configuration

CORS is enabled on both:
- API Gateway (backend)
- S3 Bucket (file uploads)

Allowed origins: `*` (all origins for development)

## Security Features

1. **JWT Authentication** - All protected routes require valid token
2. **Password Hashing** - bcrypt hashing in backend
3. **Token Expiration** - Tokens expire after 1 hour
4. **Input Validation** - Frontend and backend validation

## Testing Checklist

- ✅ Health check endpoint (`GET /`)
- ✅ User signup (`POST /auth/signup`)
- ✅ User login (`POST /auth/login`)
- ✅ Get user profile (`GET /users`)
- ✅ File upload (`POST /upload`)
- ✅ Frontend authentication modal
- ✅ JWT token persistence
- ✅ Logout functionality

## Next Steps

1. Replace `*` CORS with specific frontend domain in production
2. Add email verification for signup
3. Implement password reset flow
4. Add file upload UI in frontend
5. Store appointment data in DynamoDB
6. Add admin dashboard for managing appointments

## Troubleshooting

**Issue:** "Missing Authorization header"
- **Solution:** Ensure user is logged in before accessing protected routes

**Issue:** "Invalid or expired token"
- **Solution:** Re-login to get a fresh token

**Issue:** CORS errors
- **Solution:** CORS is already configured; check browser console for specific error

## Environment Variables

Backend requires:
```
JWT_SECRET=your_secret_key
USERS_TABLE=myvision-appointments
UPLOADS_BUCKET=myvision-uploads
```

These are configured in `serverless.yml` and `.env` file.
