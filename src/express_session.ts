import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration - Fix: Cast to express.RequestHandler
app.use(session({
  secret: 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}) as express.RequestHandler);

// Extend session interface
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    username?: string;
  }
}

// Mock user database (use real database in production)
interface User {
  id: string;
  username: string;
  password: string;
}

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
    message: 'Authentication Demo API',
    authenticated: !!req.session.userId,
    user: req.session.username || null
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

    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      message: 'Login successful',
      userId: user.id,
      username: user.username
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout endpoint
app.post('/logout', (req: Request, res: Response): void => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: 'Logout failed' });
      return;
    }
    res.clearCookie('connect.sid'); // Default session cookie name
    res.json({ message: 'Logout successful' });
  });
});

// Protected route
app.get('/profile', requireAuth, (req: Request, res: Response): void => {
  const user = users.find(u => u.id === req.session.userId);
  res.json({
    message: 'Profile data',
    user: {
      id: user?.id,
      username: user?.username
    }
  });
});

// Protected route - dashboard
app.get('/dashboard', requireAuth, (req: Request, res: Response): void => {
  res.json({
    message: `Welcome to your dashboard, ${req.session.username}!`,
    data: {
      userId: req.session.userId,
      sessionData: 'This is protected content'
    }
  });
});

// Check session status
app.get('/session', (req: Request, res: Response): void => {
  res.json({
    authenticated: !!req.session.userId,
    sessionId: req.sessionID,
    user: req.session.username || null,
    cookie: req.session.cookie
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('\nAPI Endpoints:');
  console.log('POST /register - Register new user');
  console.log('POST /login - Login user');
  console.log('POST /logout - Logout user');
  console.log('GET /profile - Get user profile (protected)');
  console.log('GET /dashboard - Dashboard (protected)');
  console.log('GET /session - Check session status');
});

export default app;