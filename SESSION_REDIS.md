# Express Authentication API with Redis Sessions

A robust authentication system built with Express.js, TypeScript, and Redis for session management.

## Features

- 🔐 User registration and login with bcrypt password hashing
- 🎫 Session management using Redis
- 🛡️ Protected routes with authentication middleware
- 👤 User profile management
- 📊 Session tracking (visit count, login time)
- 🔍 RedisInsight admin interface included

## Tech Stack

- **Backend**: Express.js with TypeScript
- **Session Store**: Redis 7
- **Password Hashing**: bcryptjs
- **Admin Tools**: RedisInsight

## Prerequisites

- Node.js (v16 or higher)
- Docker and Docker Compose
- npm or yarn

## Project Structure

```
.
├── src/
│   ├── config/
│   │   └── redis.config.ts
│   └── index.ts (main server file)
├── docker-compose.yml
├── package.json
└── README.md
```

## How It Works

### Authentication Flow

1. **Registration**: User creates an account with username and password
   - Password is hashed using bcrypt (10 salt rounds)
   - User stored in memory (replace with MongoDB in production)

2. **Login**: User authenticates with credentials
   - Password verified against hashed version
   - Session created and stored in Redis
   - Session ID sent to client as cookie

3. **Protected Routes**: Middleware checks for valid session
   - Session retrieved from Redis using cookie
   - User data attached to request object
   - Access granted if session valid

4. **Logout**: Session destroyed from Redis
   - Cookie cleared from client
   - User logged out

### Session Management

- Sessions stored in Redis for fast access and scalability
- Session data includes:
  - `userId`: Unique user identifier
  - `username`: Current username
  - `loginTime`: Timestamp of login
  - `visitCount`: Number of protected route visits
- Default expiry: 24 hours

## Installation & Setup

### 1. Clone and Install Dependencies

```bash
# Install Node.js dependencies
npm install
```

### 2. Create Redis Configuration File

Create `src/config/redis.config.ts`:

```typescript
import { createClient } from 'redis';

let redisClient: ReturnType<typeof createClient>;

export const getRedisConnection = () => {
  if (!redisClient) {
    redisClient = createClient({
      url: 'redis://localhost:6379',
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 10) {
            return new Error('Redis connection failed');
          }
          return retries * 100;
        }
      }
    });

    redisClient.on('error', (err) => console.error('Redis Client Error', err));
    redisClient.on('connect', () => console.log('Redis Client Connected'));
    
    redisClient.connect();
  }

  return redisClient;
};
```

### 3. Create Environment Variables

Create `.env` file in project root:

```env
SESSION_SECRET=your-super-secret-key-change-this-in-production
NODE_ENV=development
PORT=3000
```

### 4. Update package.json Scripts

```json
{
  "scripts": {
    "start:express-session-redis": "NODE_ENV=test nodemon src/express_sessions_redis.ts",
    "build": "rimraf build && tsc -p tsconfig.json",
  }
}
```

## Running the Application

### 1. Start Docker Services

```bash
# Start Redis, RedisInsight, MongoDB, and Mongo Express
docker-compose up -d

# Check all services are running
docker-compose ps
```

### 2. Start the Express Server

```bash
# Development mode with hot reload
npm run dev

# Or production mode
npm run build
npm start
```

The server will start on `http://localhost:3000`

### 3. Access Admin Interfaces

- **RedisInsight**: http://localhost:5540 (Redis GUI)
- **Mongo Express**: http://localhost:8081 (MongoDB GUI)
  - Username: `admin`
  - Password: `admin`

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API info and health check |
| POST | `/register` | Register new user |
| POST | `/login` | Login user |
| GET | `/session` | Check session status |

### Protected Endpoints (Require Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/logout` | Logout current user |
| GET | `/profile` | Get user profile |
| GET | `/dashboard` | Access dashboard |
| PUT | `/update-profile` | Update username/password |
| GET | `/session-info` | Detailed session information |

## Testing the API

### Using cURL

#### 1. Register a New User

```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "secure123"}'
```

**Expected Response:**
```json
{
  "message": "User registered successfully",
  "userId": "1729267890123",
  "username": "john_doe"
}
```

#### 2. Login

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "secure123"}' \
  -c cookies.txt
```

**Expected Response:**
```json
{
  "message": "Login successful",
  "userId": "1729267890123",
  "username": "john_doe",
  "sessionId": "abc123xyz..."
}
```

> **Note**: `-c cookies.txt` saves the session cookie for subsequent requests

#### 3. Access Protected Route

```bash
curl -X GET http://localhost:3000/profile \
  -b cookies.txt
```

**Expected Response:**
```json
{
  "message": "Profile data",
  "user": {
    "id": "1729267890123",
    "username": "john_doe",
    "loginTime": "2025-10-18T10:30:00.000Z",
    "visitCount": 1
  }
}
```

#### 4. Update Profile

```bash
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"username": "john_updated", "password": "newsecure456"}'
```

#### 5. Check Session Status

```bash
curl -X GET http://localhost:3000/session \
  -b cookies.txt
```

#### 6. Logout

```bash
curl -X POST http://localhost:3000/logout \
  -b cookies.txt
```

**Expected Response:**
```json
{
  "message": "Goodbye john_doe! Logged out successfully"
}
```

### Using Postman

1. **Create a new Collection** named "Auth API"
2. **Set up requests** for each endpoint
3. **Important**: Enable "Save cookies" in Postman settings
4. Follow this testing sequence:
   - POST Register → POST Login → GET Profile → POST Logout

### Using Thunder Client (VS Code Extension)

1. Install Thunder Client extension
2. Create new request
3. Set environment with `baseUrl: http://localhost:3000`
4. Test endpoints in sequence

## Verifying Sessions in Redis

### Using RedisInsight

1. Open http://localhost:5540
2. Add database: `localhost:6379`
3. Browse keys to see session data
4. Session keys format: `sess:sessionId`

### Using Redis CLI

```bash
# Connect to Redis container
docker exec -it <redis-container-name> redis-cli

# List all session keys
KEYS sess:*

# View specific session
GET sess:abc123xyz...

# Check session TTL (time to live)
TTL sess:abc123xyz...
```

## Error Handling

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 201 | Created (registration) |
| 400 | Bad request (validation error) |
| 401 | Unauthorized (invalid credentials/no session) |
| 404 | Not found |
| 500 | Server error |

## Security Considerations

### Current Implementation (Development)

- ⚠️ In-memory user storage
- ⚠️ Cookies sent over HTTP
- ⚠️ Simple session secret

### Production Recommendations

1. **Database**: Replace in-memory users with MongoDB
2. **HTTPS**: Set `cookie.secure: true`
3. **Session Secret**: Use strong, random secret from environment
4. **Rate Limiting**: Add rate limiting to login/register
5. **Input Validation**: Use validator library
6. **CORS**: Configure properly for your frontend
7. **Helmet**: Add security headers

```typescript
// Production example
app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, // HTTPS only
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'strict'
    }
  })
);
```

## Troubleshooting

### Redis Connection Issues

```bash
# Check Redis is running
docker-compose ps

# View Redis logs
docker-compose logs cache

# Restart Redis
docker-compose restart cache
```

### Session Not Persisting

1. Check cookie is being sent in request headers
2. Verify Redis connection in server logs
3. Check session secret is consistent
4. Ensure `saveUninitialized: false` and `resave: false`

### Authentication Fails

1. Verify password meets minimum length (6 chars)
2. Check username is unique during registration
3. Ensure credentials match exactly (case-sensitive)

## Stopping the Application

```bash
# Stop Express server: Ctrl + C

# Stop Docker services
docker-compose down

# Stop and remove volumes (clears all data)
docker-compose down -v
```
