import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection URL
// const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/session-db';
const MONGODB_URI = 'mongodb://root:password@localhost:27017/session-db?authSource=admin'

// Session configuration with MongoDB
app.use(
  session({
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      collectionName: 'sessions',
      ttl: 24 * 60 * 60, // 24 hours in seconds
      autoRemove: 'native', // Auto remove expired sessions
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  })
);

// Extend session interface
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    username?: string;
    loginTime?: Date;
    visitCount?: number;
  }
}

// User interface
interface User {
  id: string;
  username: string;
  password: string;
}

// Mock user database (use real database in production)
const users: User[] = [];

// Middleware to check authentication
const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
};

// Routes
app.get('/', (req: Request, res: Response): void => {
  res.json({
    message: 'Authentication Demo API with MongoDB Sessions',
    authenticated: !!req.session.userId,
    user: req.session.username || null,
    sessionId: req.sessionID
  });
});

// Register endpoint
app.post('/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password required' });
      return;
    }

    // Validate password length
    if (password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters' });
      return;
    }

    // Check if user already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      res.status(400).json({ error: 'Username already exists' });
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser: User = {
      id: Date.now().toString(),
      username,
      password: hashedPassword
    };

    users.push(newUser);

    res.status(201).json({
      message: 'User registered successfully',
      userId: newUser.id,
      username: newUser.username
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password required' });
      return;
    }

    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Create session with MongoDB storage
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.loginTime = new Date();
    req.session.visitCount = 1;

    res.json({
      message: 'Login successful',
      userId: user.id,
      username: user.username,
      sessionId: req.sessionID
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout endpoint
app.post('/logout', (req: Request, res: Response): void => {
  const username = req.session.username;
  
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: 'Logout failed' });
      return;
    }
    res.clearCookie('connect.sid'); // Default session cookie name
    res.json({ 
      message: username ? `Goodbye ${username}! Logged out successfully` : 'Logout successful'
    });
  });
});

// Protected route - Profile
app.get('/profile', requireAuth, (req: Request, res: Response): void => {
  const user = users.find(u => u.id === req.session.userId);
  
  // Increment visit count
  if (req.session.visitCount) {
    req.session.visitCount += 1;
  }
  
  res.json({
    message: 'Profile data',
    user: {
      id: user?.id,
      username: user?.username,
      loginTime: req.session.loginTime,
      visitCount: req.session.visitCount
    }
  });
});

// Protected route - Dashboard
app.get('/dashboard', requireAuth, (req: Request, res: Response): void => {
  res.json({
    message: `Welcome to your dashboard, ${req.session.username}!`,
    data: {
      userId: req.session.userId,
      sessionData: 'This is protected content',
      loginTime: req.session.loginTime,
      visitCount: req.session.visitCount
    }
  });
});

// Update profile endpoint
app.put('/update-profile', requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;
    const user = users.find(u => u.id === req.session.userId);

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // Update username if provided
    if (username) {
      // Check if new username already exists
      const existingUser = users.find(u => u.username === username && u.id !== user.id);
      if (existingUser) {
        res.status(400).json({ error: 'Username already exists' });
        return;
      }
      user.username = username;
      req.session.username = username;
    }

    // Update password if provided
    if (password) {
      if (password.length < 6) {
        res.status(400).json({ error: 'Password must be at least 6 characters' });
        return;
      }
      user.password = await bcrypt.hash(password, 10);
    }

    res.json({
      message: 'Profile updated successfully',
      user: {
        userId: user.id,
        username: user.username
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Check session status
app.get('/session', (req: Request, res: Response): void => {
  res.json({
    authenticated: !!req.session.userId,
    sessionId: req.sessionID,
    user: req.session.username || null,
    loginTime: req.session.loginTime || null,
    visitCount: req.session.visitCount || 0,
    cookie: req.session.cookie
  });
});

// Session info route (alias)
app.get('/session-info', (req: Request, res: Response): void => {
  res.json({
    sessionId: req.sessionID,
    isAuthenticated: !!req.session.userId,
    sessionData: req.session.userId ? {
      userId: req.session.userId,
      username: req.session.username,
      loginTime: req.session.loginTime,
      visitCount: req.session.visitCount,
    } : null,
    cookie: req.session.cookie,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Using MongoDB for session storage');
  console.log('\nAPI Endpoints:');
  console.log('POST /register - Register new user');
  console.log('POST /login - Login user');
  console.log('POST /logout - Logout user');
  console.log('GET  /profile - Get user profile (protected)');
  console.log('GET  /dashboard - Dashboard (protected)');
  console.log('PUT  /update-profile - Update profile (protected)');
  console.log('GET  /session - Check session status');
  console.log('GET  /session-info - View session details');
});

export default app;