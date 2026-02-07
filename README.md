# Serverless Node Backend

This project is a serverless backend application built using the Serverless Framework with Node.js. It incorporates JWT-based authentication, a DynamoDB table for user management, REST APIs via API Gateway with CORS support, and an S3 bucket for file uploads.

## Project Structure

```
serverless-node-backend
├── src
│   ├── handlers
│   │   ├── auth
│   │   │   ├── register.js
│   │   │   ├── login.js
│   │   │   └── authorize.js
│   │   ├── users.js
│   │   └── uploads.js
│   ├── lib
│   │   ├── jwt.js
│   │   ├── dynamo.js
│   │   └── s3.js
│   └── models
│       └── user.js
├── serverless.yml
├── package.json
├── .env.example
├── .gitignore
├── tests
│   ├── auth.test.js
│   └── uploads.test.js
├── static
│   └── index.html
└── README.md
```

## Features

- **User Registration**: Users can sign up with their email and password. Passwords are hashed before being stored in the database.
- **User Login**: Users can log in to receive a JWT token for authenticated sessions.
- **JWT Authentication**: Middleware to protect routes and ensure only authenticated users can access certain endpoints.
- **User Management**: Functions to retrieve user details and manage user data.
- **File Uploads**: Users can upload files to an S3 bucket, with authentication checks in place.
- **DynamoDB Integration**: All user data is stored in a DynamoDB table, allowing for scalable and efficient data management.

## Setup Instructions

1. **Clone the Repository**: 
   ```
   git clone <repository-url>
   cd serverless-node-backend
   ```

2. **Install Dependencies**: 
   ```
   npm install
   ```

3. **Configure Environment Variables**: 
   Copy `.env.example` to `.env` and fill in the required values, including AWS credentials and JWT secret.

4. **Deploy the Application**: 
   Use the Serverless Framework to deploy the application to AWS:
   ```
   serverless deploy
   ```

## API Endpoints

- **POST /auth/register**: Register a new user.
- **POST /auth/login**: Log in an existing user and receive a JWT token.
- **GET /users/{id}**: Retrieve user details by ID (protected route).
- **POST /uploads**: Upload a file to S3 (protected route).

## Usage Examples

### Register User
```bash
curl -X POST https://<api-id>.execute-api.<region>.amazonaws.com/dev/auth/register -d '{"email": "user@example.com", "password": "password123"}'
```

### Login User
```bash
curl -X POST https://<api-id>.execute-api.<region>.amazonaws.com/dev/auth/login -d '{"email": "user@example.com", "password": "password123"}'
```

### Upload File
```bash
curl -X POST https://<api-id>.execute-api.<region>.amazonaws.com/dev/uploads -H "Authorization: Bearer <token>" -F "file=@/path/to/file"
```

## Testing

Run the tests using:
```
npm test
```

## License

This project is licensed under the MIT License.