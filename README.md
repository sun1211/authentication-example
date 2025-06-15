# Node.js Authentication Methods - Complete Guide

Here's a comprehensive list of common authentication methods used in **Node.js backends**:

## 📋 Table of Contents

### **1. [Session-Based Authentication](#1-session-based-authentication---demo-example)**
- Uses server-side sessions (stored in memory, Redis, or a database).
- Relies on cookies (`express-session` + `cookie-parser`).
- **Libraries**:
  - `express-session` ✅
  - `cookie-session`
  - `connect-redis` (for Redis-based sessions)

### **2. Token-Based Authentication (JWT - JSON Web Tokens)**
- Stateless authentication using digitally signed tokens.
- Tokens are stored client-side (localStorage, cookies, or mobile storage).
- **Libraries**:
  - `jsonwebtoken` (JWT)
  - `passport-jwt` (for JWT strategy in Passport.js)

### **3. OAuth 2.0 / OpenID Connect (OIDC)**
- Delegated authentication (e.g., "Login with Google/GitHub/Facebook").
- Uses access tokens & refresh tokens.
- **Libraries**:
  - `passport-oauth2`
  - `openid-client`
  - `google-auth-library` (for Google OAuth)

### **4. API Key Authentication**
- Simple authentication using a unique API key (often in headers or query params).
- Used for server-to-server communication.
- **Libraries**: Custom middleware or `express-api-key-auth`.

### **5. Basic Authentication**
- Uses `username:password` encoded in Base64 in the `Authorization` header.
- **Libraries**:
  - `express-basic-auth`
  - Custom middleware with `Buffer.from(req.headers.authorization, 'base64')`

### **6. Passport.js (Middleware for Auth Strategies)**
- Supports multiple auth methods (Local, JWT, OAuth, etc.).
- **Strategies**:
  - `passport-local` (username/password)
  - `passport-jwt`
  - `passport-google-oauth20`
  - `passport-github`

### **7. Magic Link / Passwordless Authentication**
- Users log in via a link sent to their email.
- **Libraries**:
  - `magic-link`
  - Custom implementation with JWT + email service (Nodemailer).

### **8. Two-Factor Authentication (2FA) / Multi-Factor (MFA)**
- Uses TOTP (Time-Based OTP) or SMS-based verification.
- **Libraries**:
  - `speakeasy` (TOTP)
  - `node-2fa`
  - Twilio (for SMS-based 2FA)

### **9. LDAP / Active Directory Authentication**
- Enterprise authentication (used in corporate environments).
- **Libraries**:
  - `ldapjs`
  - `passport-ldapauth`

### **10. Social Logins (OAuth-based)**
- Login via Google, Facebook, GitHub, etc.
- **Libraries**:
  - `passport-google-oauth20`
  - `passport-facebook`
  - `passport-github2`

### **11. Firebase Authentication**
- Managed auth service by Google (supports email, phone, social logins).
- **Library**: `firebase-admin`

### **12. WebAuthn / FIDO2 (Passwordless & Biometric Auth)**
- Uses hardware security keys or biometrics (fingerprint, FaceID).
- **Libraries**:
  - `fido2-lib`
  - `simplewebauthn`

### **Common Security Middleware**
- `helmet` (Secure HTTP headers)
- `bcrypt` / `argon2` (Password hashing)
- `rate-limiter-flexible` (Prevent brute-force attacks)

---

# 1. Session-Based Authentication - Demo Example

A simple yet secure authentication system built with Express.js using session-based authentication, bcrypt password hashing, and TypeScript.

## Features

- ✅ User registration with password hashing
- ✅ Session-based login/logout
- ✅ Protected routes with middleware
- ✅ Secure session configuration
- ✅ TypeScript support
- ✅ HTTP-only cookies for security

## Running the Application

```bash
npm start
```

The server will start on `http://localhost:3000`

## API Endpoints

| Method | Endpoint | Description | Protected |
|--------|----------|-------------|-----------|
| GET | `/` | API status and auth info | No |
| POST | `/register` | Register new user | No |
| POST | `/login` | User login | No |
| POST | `/logout` | User logout | No |
| GET | `/profile` | Get user profile | Yes |
| GET | `/dashboard` | User dashboard | Yes |
| GET | `/session` | Check session status | No |

## 🔐 Session Management Deep Dive

### 1. Session Creation

Sessions are automatically created when users log in successfully:

```typescript
// Login endpoint creates session
app.post('/login', async (req: Request, res: Response) => {
  // ... password validation ...
  
  // 🎯 Session Creation
  req.session.userId = user.id;        // Store user ID
  req.session.username = user.username; // Store username
  
  // Session cookie automatically sent to client
});
```

**What happens:**
- Server generates unique session ID
- Session data stored server-side (memory by default)
- Secure HTTP-only cookie sent to client with session ID
- Client automatically sends cookie with future requests

### 2. Session Configuration & Timeout

```typescript
app.use(session({
  secret: 'your-secret-key-change-in-production', // 🔑 Signs session cookies
  resave: false,                    // Don't save unchanged sessions
  saveUninitialized: false,         // Don't save empty sessions
  cookie: {
    secure: false,                  // Set true for HTTPS in production
    httpOnly: true,                 // 🛡️ Prevents XSS attacks
    maxAge: 24 * 60 * 60 * 1000    // ⏰ 24 hours timeout
  }
}));
```

**Session Timeout Options:**

```typescript
// Different timeout configurations
maxAge: 30 * 60 * 1000,           // 30 minutes
maxAge: 2 * 60 * 60 * 1000,       // 2 hours  
maxAge: 24 * 60 * 60 * 1000,      // 24 hours
maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days
```

### 3. Session Verification

Every protected route uses the `requireAuth` middleware:

```typescript
const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  // 🔍 Session Verification
  if (req.session.userId) {
    next(); // ✅ Valid session - proceed
  } else {
    res.status(401).json({ error: 'Authentication required' }); // ❌ Invalid
  }
};

// Apply to protected routes
app.get('/dashboard', requireAuth, (req, res) => {
  // This only runs if session is valid
});
```

### 4. Session Renewal

**Session Renewal on Every Request**

```typescript
app.use(session({
  secret: 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  rolling: true, // Add this line
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}) as express.RequestHandler);
```

**Manual Session Renewal:**
```typescript
const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (req.session.userId) {
    req.session.touch(); // This will save the session and renew the cookie
    next();
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
};
```

### 5. Session Destruction

```typescript
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    // 🗑️ Clear cookie from client
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});
```

## 🔒 Security Features

### Password Security
- **bcrypt hashing** with salt rounds (10)
- **No plain text** passwords stored
- **Secure comparison** using bcrypt.compare()

### Session Security
- **HTTP-only cookies** - Prevents XSS attacks
- **Signed cookies** - Prevents tampering
- **Secure flag** - HTTPS only in production
- **Session expiration** - Automatic timeout

### Route Protection
- **Middleware-based** authentication
- **Early exit** for unauthorized requests
- **Generic error messages** - No information leakage

## 🏗️ Session Data Storage Options

### Memory Store (Default - Development Only)
```typescript
// Current setup - sessions lost on server restart
const users: User[] = []; // In-memory storage
```
**⚠️ Not for production** - Sessions lost on restart, won't scale

### Redis Store (Recommended)
```bash
npm install connect-redis redis
```
```typescript
import RedisStore from 'connect-redis';
import { createClient } from 'redis';

const redisClient = createClient();
redisClient.connect();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  // ... other options
}));
```

### MongoDB Store
```bash
npm install connect-mongo
```
```typescript
import MongoStore from 'connect-mongo';

app.use(session({
  store: MongoStore.create({
    mongoUrl: 'mongodb://localhost:27017/sessions'
  }),
  // ... other options
}));
```

### PostgreSQL Store
```bash
npm install connect-pg-simple pg
```
```typescript
import pgSession from 'connect-pg-simple';
const PostgreSQLStore = pgSession(session);

app.use(session({
  store: new PostgreSQLStore({ /* db config */ }),
  // ... other options
}));
```

### File Store
```bash
npm install session-file-store
```
```typescript
import FileStore from 'session-file-store';
const FileStoreSession = FileStore(session);

app.use(session({
  store: new FileStoreSession({ path: './sessions' }),
  // ... other options
}));
```

**Quick Recommendations:**
- **Development**: Memory Store
- **Small Apps**: File Store  
- **Production**: Redis Store
- **Existing DB**: Match your database (MongoDB/PostgreSQL)

## 📊 Session Lifecycle

```
1. User Login    →  2. Session Created  →  3. Cookie Sent
      ↓                     ↓                    ↓
   Credentials         Server Storage         Client Browser
   Validated           userId: "123"          connect.sid=abc...
                       username: "john"

4. Future Requests  →  5. Session Verified  →  6. Access Granted
      ↓                     ↓                     ↓
   Cookie Sent            Check Storage         Protected Route
   connect.sid=abc...     Find Session          Dashboard/Profile

7. Session Expires  →  8. Access Denied   →   9. Re-login Required
      ↓                     ↓                     ↓
   TTL Reached            401 Error             New Session Cycle
   Auto-cleanup           Clear Cookie          Fresh Start
```