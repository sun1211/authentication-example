# Express Authentication API Guide

Complete guide for setting up and using the Express Authentication API with MongoDB session storage.

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (running locally or remote instance)
- npm or yarn package manager

## Installation

### 1. Install Dependencies

```bash
npm install express express-session connect-mongo bcryptjs
npm install -D typescript @types/express @types/express-session @types/bcryptjs ts-node nodemon
```

### 2. Setup MongoDB

**Option A: Using Docker**
```bash
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=root \
  -e MONGO_INITDB_ROOT_PASSWORD=password \
  mongo
```

**Option B: Local MongoDB Installation**
- Download and install MongoDB from [mongodb.com](https://www.mongodb.com/try/download/community)
- Start MongoDB service:
  ```bash
  # macOS
  brew services start mongodb-community
  
  # Linux
  sudo systemctl start mongod
  
  # Windows
  net start MongoDB
  ```

### 3. Environment Variables (Optional)

Create a `.env` file:
```env
MONGODB_URI=mongodb://root:password@localhost:27017/session-db?authSource=admin
SESSION_SECRET=your-super-secret-key-change-this
PORT=3000
```

## Starting the Server

### Development Mode
```bash
# Using ts-node
npx ts-node server.ts

# Using nodemon for auto-reload
npx nodemon server.ts
```

### Production Mode
```bash
# Compile TypeScript
npx tsc

# Run compiled JavaScript
node dist/server.js
```

The server will start on `http://localhost:3000`

## API Endpoints

### Public Endpoints

#### 1. Home / Status
```http
GET http://localhost:3000/
```

**Response:**
```json
{
  "message": "Authentication Demo API with MongoDB Sessions",
  "authenticated": false,
  "user": null,
  "sessionId": "abc123..."
}
```

#### 2. Register User
```http
POST http://localhost:3000/register
Content-Type: application/json

{
  "username": "john_doe",
  "password": "password123"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully",
  "userId": "1234567890",
  "username": "john_doe"
}
```

#### 3. Login
```http
POST http://localhost:3000/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "password123"
}
```

**Response (200):**
```json
{
  "message": "Login successful",
  "userId": "1234567890",
  "username": "john_doe",
  "sessionId": "abc123..."
}
```

#### 4. Check Session Status
```http
GET http://localhost:3000/session
```

**Response:**
```json
{
  "authenticated": true,
  "sessionId": "abc123...",
  "user": "john_doe",
  "loginTime": "2025-10-18T10:30:00.000Z",
  "visitCount": 3,
  "cookie": {
    "maxAge": 86400000,
    "httpOnly": true,
    "secure": false
  }
}
```

### Protected Endpoints

*Note: These require authentication (valid session cookie)*

#### 5. Get Profile
```http
GET http://localhost:3000/profile
```

**Response (200):**
```json
{
  "message": "Profile data",
  "user": {
    "id": "1234567890",
    "username": "john_doe",
    "loginTime": "2025-10-18T10:30:00.000Z",
    "visitCount": 1
  }
}
```

#### 6. Dashboard
```http
GET http://localhost:3000/dashboard
```

**Response (200):**
```json
{
  "message": "Welcome to your dashboard, john_doe!",
  "data": {
    "userId": "1234567890",
    "sessionData": "This is protected content",
    "loginTime": "2025-10-18T10:30:00.000Z",
    "visitCount": 2
  }
}
```

#### 7. Update Profile
```http
PUT http://localhost:3000/update-profile
Content-Type: application/json

{
  "username": "jane_doe",
  "password": "newpassword123"
}
```

**Response (200):**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "userId": "1234567890",
    "username": "jane_doe"
  }
}
```

#### 8. Logout
```http
POST http://localhost:3000/logout
```

**Response (200):**
```json
{
  "message": "Goodbye john_doe! Logged out successfully"
}
```

## Testing with cURL

### Register a new user
```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"test1234"}'
```

### Login and save session cookie
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"test1234"}' \
  -c cookies.txt
```

### Access protected route with session
```bash
curl http://localhost:3000/profile -b cookies.txt
```

### Logout
```bash
curl -X POST http://localhost:3000/logout -b cookies.txt
```

## Testing with Postman

1. **Register/Login**: Send POST request to register or login endpoint
2. **Save Cookie**: Postman automatically saves session cookies
3. **Access Protected Routes**: Session cookie is automatically included in subsequent requests
4. **Logout**: Send POST request to `/logout` endpoint

## Testing with JavaScript/Fetch

```javascript
// Register
await fetch('http://localhost:3000/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'testuser',
    password: 'test1234'
  })
});

// Login
await fetch('http://localhost:3000/login', {
  method: 'POST',
  credentials: 'include', // Important: Include cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'testuser',
    password: 'test1234'
  })
});

// Access protected route
await fetch('http://localhost:3000/profile', {
  credentials: 'include' // Important: Include cookies
});

// Logout
await fetch('http://localhost:3000/logout', {
  method: 'POST',
  credentials: 'include'
});
```

## Session Management

### How Sessions Work

1. **Login**: Server creates session and stores it in MongoDB
2. **Session Cookie**: Client receives `connect.sid` cookie
3. **Subsequent Requests**: Cookie automatically sent with each request
4. **Session Expiry**: Sessions expire after 24 hours of inactivity
5. **Logout**: Session destroyed and removed from MongoDB

### Session Data Stored
- `userId`: User ID
- `username`: Username
- `loginTime`: When user logged in
- `visitCount`: Number of times user accessed protected routes

## Error Responses

### 400 Bad Request
```json
{
  "error": "Username and password required"
}
```

### 401 Unauthorized
```json
{
  "error": "Authentication required"
}
```

### 404 Not Found
```json
{
  "error": "User not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "Registration failed"
}
```

## Security Notes

1. **Password Requirements**: Minimum 6 characters
2. **Password Hashing**: Uses bcrypt with salt rounds of 10
3. **Session Secret**: Change `SESSION_SECRET` in production
4. **HTTPS**: Set `cookie.secure: true` in production with HTTPS
5. **Cookie Security**: HttpOnly flag prevents XSS attacks

## MongoDB Session Storage

Sessions are stored in MongoDB collection named `sessions`:

```javascript
{
  "_id": "session-id",
  "expires": ISODate("2025-10-19T10:30:00.000Z"),
  "session": {
    "cookie": { ... },
    "userId": "1234567890",
    "username": "john_doe",
    "loginTime": "2025-10-18T10:30:00.000Z",
    "visitCount": 5
  }
}
```

### View Sessions in MongoDB
```bash
mongosh mongodb://root:password@localhost:27017/session-db?authSource=admin
db.sessions.find().pretty()
```

## Troubleshooting

### Connection Refused
- Ensure MongoDB is running
- Check MongoDB connection string
- Verify port 27017 is not blocked

### Session Not Persisting
- Check that cookies are enabled
- Use `credentials: 'include'` in fetch requests
- Verify session cookie is being sent

### Authentication Failing
- Clear browser cookies
- Check username/password are correct
- Verify user exists in database

## Production Deployment

1. Set environment variables:
   ```env
   NODE_ENV=production
   MONGODB_URI=your-production-mongodb-uri
   SESSION_SECRET=strong-random-secret
   ```

2. Enable HTTPS and secure cookies:
   ```javascript
   cookie: {
     secure: true, // Requires HTTPS
     httpOnly: true,
     sameSite: 'strict'
   }
   ```

3. Use a managed MongoDB service (MongoDB Atlas, etc.)

4. Implement rate limiting for login/register endpoints