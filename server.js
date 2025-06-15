const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const testRoutes = require('./routes/testRoutes');
const questionRoutes = require('./routes/questionRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const blogRoutes = require('./routes/blog');
const notificationRoutes = require('./routes/notifications');
const testResultRoutes = require('./routes/testResults');
const subscriptionRoutes = require('./routes/subscriptions');
const subscriptionPlanRoutes = require('./routes/subscriptionPlanRoutes');
const iqRankingsRoutes = require('./routes/iqRankings');
const campaignRoutes = require('./routes/campaignRoutes');
const pixelRoutes = require('./routes/pixelRoutes');
const pageRoutes = require('./routes/pageRoutes');
const adminActivityRoutes = require('./routes/adminActivityRoutes');
const { setupLogger } = require('./utils/logger');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Logger Setup
const logger = setupLogger();

// Global error handler to catch path-to-regexp errors
process.on('uncaughtException', (error) => {
  if (error.message && error.message.includes('path-to-regexp')) {
    // Silently ignore path-to-regexp errors - they are not critical
    // These are usually from external bots or malicious requests
    return;
  }
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  if (reason && reason.message && reason.message.includes('path-to-regexp')) {
    // Silently ignore path-to-regexp rejections - they are not critical
    return;
  }
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Very early request interceptor to catch problematic URLs before they reach Express
const originalCreateServer = http.createServer;

http.createServer = function(...args) {
  const server = originalCreateServer.apply(this, args);
  
  const originalEmit = server.emit;
  server.emit = function(event, ...args) {
    if (event === 'request') {
      const [req, res] = args;
      
      // Check for problematic URLs at the HTTP level
      if (req.url && (
        req.url.includes('git.new') || 
        req.url.includes('pathToRegexpError') ||
        req.url.includes('://') ||
        !req.url.startsWith('/')
      )) {
        // Silently block problematic requests without logging
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Invalid request',
          message: 'The requested URL is not allowed'
        }));
        return;
      }
    }
    
    return originalEmit.apply(this, [event, ...args]);
  };
  
  return server;
};

// Helmet for HTTP security headers
app.use(helmet());

// Rate limiter for login endpoint (brute-force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Çok fazla giriş denemesi. Lütfen 15 dakika sonra tekrar deneyin.'
});
app.use('/api/auth/login', loginLimiter);

// CORS Configuration - Only allow production and local domains
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://panel.senin-domainin.com',
  'https://senin-domainin.com',
  'https://mobil.iqtestim.com', // Admin panel domain
  'https://panel.iqtestim.com',
  'https://iqtestim.com',
  'https://iqtestim-backend.vercel.app', // Backend domain
  'https://iqtestimadminpanel.vercel.app'
];

app.use(cors({
  origin: function(origin, callback) {
    // allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    // Validate origin format
    try {
      new URL(origin);
    } catch (error) {
      logger.warn(`Invalid origin format: ${origin}`);
      return callback(null, false);
    }
    
    // Check if origin is in allowed list
    const isAllowed = allowedOrigins.some(allowed => {
      return origin === allowed;
    });
    
    // Also allow Vercel preview URLs
    if (origin.includes('vercel.app')) {
      return callback(null, true);
    }
    
    if (!isAllowed) {
      logger.warn(`CORS blocked origin: ${origin}`);
      return callback(null, false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Request logging middleware to help debug path-to-regexp errors
app.use((req, res, next) => {
  // Log all requests to help identify problematic ones
  logger.info('Incoming request:', {
    method: req.method,
    url: req.originalUrl,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer'),
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  
  // Check for potentially problematic URLs
  if (req.originalUrl && (req.originalUrl.includes('http://') || req.originalUrl.includes('https://'))) {
    logger.warn('Potentially problematic URL detected:', {
      url: req.originalUrl,
      method: req.method,
      userAgent: req.get('User-Agent')
    });
  }
  
  next();
});

// Request sanitization middleware to prevent path-to-regexp errors
app.use((req, res, next) => {
  try {
    // Sanitize the URL to prevent path-to-regexp errors
    if (req.originalUrl) {
      // Check for malformed URLs that contain full URLs
      if (req.originalUrl.includes('http://') || req.originalUrl.includes('https://')) {
        logger.warn('Malformed URL detected, redirecting to root:', {
          originalUrl: req.originalUrl,
          method: req.method,
          userAgent: req.get('User-Agent')
        });
        return res.redirect('/');
      }
      
      // Check for URLs that don't start with /
      if (!req.originalUrl.startsWith('/')) {
        logger.warn('Invalid URL format, redirecting to root:', {
          originalUrl: req.originalUrl,
          method: req.method
        });
        return res.redirect('/');
      }
      
      // Check for URLs with invalid characters that might cause path-to-regexp issues
      const invalidChars = /[<>:"|?*]/;
      if (invalidChars.test(req.originalUrl)) {
        logger.warn('URL contains invalid characters, redirecting to root:', {
          originalUrl: req.originalUrl,
          method: req.method
        });
        return res.redirect('/');
      }
      
      // Check for the specific problematic URL pattern
      if (req.originalUrl.includes('git.new') || req.originalUrl.includes('pathToRegexpError')) {
        logger.warn('Blocked problematic URL pattern:', {
          originalUrl: req.originalUrl,
          method: req.method,
          userAgent: req.get('User-Agent')
        });
        return res.status(400).json({
          error: 'Invalid URL pattern',
          message: 'The requested URL contains invalid patterns'
        });
      }
      
      // Additional check for any URL that might cause path-to-regexp issues
      if (req.originalUrl.includes('://') || req.originalUrl.includes('git.new')) {
        logger.warn('Blocked URL with protocol or git.new:', {
          originalUrl: req.originalUrl,
          method: req.method
        });
        return res.status(400).json({
          error: 'Invalid URL format',
          message: 'The requested URL format is not allowed'
        });
      }
    }
    
    next();
  } catch (error) {
    logger.error('Error in request sanitization:', error);
    return res.status(400).json({
      error: 'Request validation failed',
      message: 'The request could not be processed'
    });
  }
});

// Static file serving for uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// MongoDB Connection with better error handling
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/quizaki';
    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('[INFO] MongoDB connected successfully');
  } catch (error) {
    console.error('[ERROR] MongoDB connection error:', error.message);
    process.exit(1);
  }
};

// Connect to MongoDB
connectDB();

// Routes with error handling
const setupRoutes = () => {
  try {
    logger.info('Loading routes...');
    
    // Wrap route loading in try-catch to catch path-to-regexp errors
    const loadRoute = (path, routeModule, name) => {
      try {
        logger.info(`Attempting to load ${name} routes at path: ${path}`);
        
        // Validate route module before loading
        if (!routeModule || typeof routeModule !== 'function') {
          logger.error(`Invalid route module for ${name}:`, {
            type: typeof routeModule,
            path: path,
            name: name
          });
          return false;
        }
        
        app.use(path, routeModule);
        logger.info(`${name} routes loaded successfully`);
      } catch (error) {
        logger.error(`Error loading ${name} routes:`, {
          error: error.message,
          stack: error.stack,
          path: path,
          name: name
        });
        
        if (error.message && error.message.includes('path-to-regexp')) {
          logger.error(`Path-to-regexp error in ${name} routes:`, {
            error: error.message,
            stack: error.stack,
            path: path,
            name: name
          });
          
          // Try to identify the problematic route
          if (routeModule && routeModule.stack) {
            logger.error(`Route stack for ${name}:`, routeModule.stack);
          }
        }
        
        // Continue loading other routes even if one fails
        return false;
      }
      return true;
    };
    
    // Load routes one by one to isolate the problematic one
    const routes = [
      { path: '/api/auth', module: authRoutes, name: 'Auth' },
      { path: '/api/admin', module: adminRoutes, name: 'Admin' },
      { path: '/api/tests', module: testRoutes, name: 'Test' },
      { path: '/api/questions', module: questionRoutes, name: 'Question' },
      { path: '/api/categories', module: categoryRoutes, name: 'Category' },
      { path: '/api/blog', module: blogRoutes, name: 'Blog' },
      { path: '/api/notifications', module: notificationRoutes, name: 'Notification' },
      { path: '/api/test-results', module: testResultRoutes, name: 'Test result' },
      { path: '/api/subscriptions', module: subscriptionRoutes, name: 'Subscription' },
      { path: '/api/subscription-plans', module: subscriptionPlanRoutes, name: 'Subscription plan' },
      { path: '/api/iq-rankings', module: iqRankingsRoutes, name: 'IQ ranking' },
      { path: '/api/campaigns', module: campaignRoutes, name: 'Campaign' },
      { path: '/api/pixels', module: pixelRoutes, name: 'Pixel' },
      { path: '/api/pages', module: pageRoutes, name: 'Page' },
      { path: '/api/admin-activities', module: adminActivityRoutes, name: 'Admin activity' }
    ];
    
    let successfulRoutes = 0;
    let failedRoutes = 0;
    
    for (const route of routes) {
      const result = loadRoute(route.path, route.module, route.name);
      if (result) {
        successfulRoutes++;
      } else {
        failedRoutes++;
      }
      
      // Add a small delay between route loading to help identify the problematic one
      setTimeout(() => {}, 100);
    }
    
    logger.info(`Route loading completed. Successful: ${successfulRoutes}, Failed: ${failedRoutes}`);
    
    if (failedRoutes > 0) {
      logger.warn(`Some routes failed to load. Check the logs above for details.`);
    } else {
      logger.info('All routes loaded successfully');
    }
  } catch (error) {
    logger.error('Critical error in route loading:', {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    // Don't exit the process, just log the error
    logger.error('Route loading failed, but server will continue running');
  }
};

setupRoutes();

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'IQ Test API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'IQ Test API Server',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      admin: '/api/admin',
      tests: '/api/tests',
      questions: '/api/questions',
      categories: '/api/categories',
      blog: '/api/blog',
      notifications: '/api/notifications',
      testResults: '/api/test-results',
      subscriptions: '/api/subscriptions',
      subscriptionPlans: '/api/subscription-plans',
      iqRankings: '/api/iq-rankings',
      campaigns: '/api/campaigns',
      pixels: '/api/pixels',
      pages: '/api/pages',
      adminActivities: '/api/admin-activities',
      health: '/health'
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  logger.warn(`Route not found: ${req.originalUrl}`);
  res.status(404).json({ error: 'Route not found', path: req.originalUrl });
});

// Error handling middleware with detailed logging
app.use((err, req, res, next) => {
  // Handle path-to-regexp errors specifically
  if (err.message && err.message.includes('path-to-regexp')) {
    logger.error('Path-to-regexp error detected:', {
      message: err.message,
      url: req.originalUrl,
      method: req.method,
      userAgent: req.get('User-Agent'),
      referer: req.get('Referer'),
      timestamp: new Date().toISOString()
    });
    
    return res.status(400).json({
      error: 'Invalid route format',
      message: 'The requested URL contains invalid characters',
      timestamp: new Date().toISOString()
    });
  }
  
  logger.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    body: req.body,
    headers: req.headers
  });
  
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  mongoose.connection.close(() => {
    logger.info('MongoDB connection closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  mongoose.connection.close(() => {
    logger.info('MongoDB connection closed');
    process.exit(0);
  });
});

// Start server
if (process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Server running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`Health check: http://localhost:${PORT}/health`);
  });
}

module.exports = app; 