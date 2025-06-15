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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Logger Setup
const logger = setupLogger();

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
    
    // Load routes one by one to identify the problematic one
    try {
      app.use('/api/auth', authRoutes);
      logger.info('Auth routes loaded');
    } catch (error) {
      logger.error('Error loading auth routes:', error.message);
    }
    
    try {
      app.use('/api/admin', adminRoutes);
      logger.info('Admin routes loaded');
    } catch (error) {
      logger.error('Error loading admin routes:', error.message);
    }
    
    try {
      app.use('/api/tests', testRoutes);
      logger.info('Test routes loaded');
    } catch (error) {
      logger.error('Error loading test routes:', error.message);
    }
    
    try {
      app.use('/api/questions', questionRoutes);
      logger.info('Question routes loaded');
    } catch (error) {
      logger.error('Error loading question routes:', error.message);
    }
    
    try {
      app.use('/api/categories', categoryRoutes);
      logger.info('Category routes loaded');
    } catch (error) {
      logger.error('Error loading category routes:', error.message);
    }
    
    try {
      app.use('/api/blog', blogRoutes);
      logger.info('Blog routes loaded');
    } catch (error) {
      logger.error('Error loading blog routes:', error.message);
    }
    
    try {
      app.use('/api/notifications', notificationRoutes);
      logger.info('Notification routes loaded');
    } catch (error) {
      logger.error('Error loading notification routes:', error.message);
    }
    
    try {
      app.use('/api/test-results', testResultRoutes);
      logger.info('Test result routes loaded');
    } catch (error) {
      logger.error('Error loading test result routes:', error.message);
    }
    
    try {
      app.use('/api/subscriptions', subscriptionRoutes);
      logger.info('Subscription routes loaded');
    } catch (error) {
      logger.error('Error loading subscription routes:', error.message);
    }
    
    try {
      app.use('/api/subscription-plans', subscriptionPlanRoutes);
      logger.info('Subscription plan routes loaded');
    } catch (error) {
      logger.error('Error loading subscription plan routes:', error.message);
    }
    
    try {
      app.use('/api/iq-rankings', iqRankingsRoutes);
      logger.info('IQ ranking routes loaded');
    } catch (error) {
      logger.error('Error loading IQ ranking routes:', error.message);
    }
    
    try {
      app.use('/api/campaigns', campaignRoutes);
      logger.info('Campaign routes loaded');
    } catch (error) {
      logger.error('Error loading campaign routes:', error.message);
    }
    
    try {
      app.use('/api/pixels', pixelRoutes);
      logger.info('Pixel routes loaded');
    } catch (error) {
      logger.error('Error loading pixel routes:', error.message);
    }
    
    try {
      app.use('/api/pages', pageRoutes);
      logger.info('Page routes loaded');
    } catch (error) {
      logger.error('Error loading page routes:', error.message);
    }
    
    try {
      app.use('/api/admin-activities', adminActivityRoutes);
      logger.info('Admin activity routes loaded');
    } catch (error) {
      logger.error('Error loading admin activity routes:', error.message);
    }
    
    logger.info('All routes loaded successfully');
  } catch (error) {
    logger.error('Error loading routes:', error.message);
    logger.error('Full error:', error);
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