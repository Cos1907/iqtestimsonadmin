const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const authRoutes = require('../routes/authRoutes');
const adminRoutes = require('../routes/adminRoutes');
const testRoutes = require('../routes/testRoutes');
const questionRoutes = require('../routes/questionRoutes');
const categoryRoutes = require('../routes/categoryRoutes');
const blogRoutes = require('../routes/blog');
const notificationRoutes = require('../routes/notifications');
const testResultRoutes = require('../routes/testResults');
const subscriptionRoutes = require('../routes/subscriptions');
const subscriptionPlanRoutes = require('../routes/subscriptionPlanRoutes');
const iqRankingsRoutes = require('../routes/iqRankings');
const campaignRoutes = require('../routes/campaignRoutes');
const pixelRoutes = require('../routes/pixelRoutes');
const pageRoutes = require('../routes/pageRoutes');
const adminActivityRoutes = require('../routes/adminActivityRoutes');
const { setupLogger } = require('../utils/logger');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();

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

// CORS Configuration - Only allow production and local domains
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://panel.senin-domainin.com',
  'https://senin-domainin.com',
  'https://mobil.iqtestim.com', // Admin panel domain
  'https://panel.iqtestim.com',
  'https://iqtestim.com',
  'https://iqtestim-backend.vercel.app' // Backend domain
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
app.use(express.json());
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.originalUrl}`);
  next();
});

// MongoDB Connection with better error handling
const connectDB = async () => {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error('MONGO_URI environment variable is not set');
    }
    
    await mongoose.connect(process.env.MONGO_URI);
    
    logger.info('MongoDB connected successfully');
  } catch (error) {
    logger.error('MongoDB connection error:', error.message);
    logger.error('Full error:', error);
    // Don't exit in Vercel environment
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
};

// Connect to MongoDB
connectDB();

// Apply rate limiter to login endpoint
app.use('/api/auth/login', loginLimiter);

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

// Basic route with health check
app.get('/', (req, res) => {
  try {
    res.json({
      message: 'API is running...',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      mongoStatus: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
  } catch (error) {
    logger.error('Error in root route:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  try {
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      mongoStatus: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      memory: process.memoryUsage()
    };
    
    if (mongoose.connection.readyState !== 1) {
      health.status = 'ERROR';
      health.mongoError = 'MongoDB not connected';
    }
    
    res.json(health);
  } catch (error) {
    logger.error('Error in health check:', error);
    res.status(500).json({ error: 'Health check failed', details: error.message });
  }
});

// 404 handler
app.use('*', (req, res) => {
  logger.warn(`Route not found: ${req.originalUrl}`);
  res.status(404).json({ error: 'Route not found', path: req.originalUrl });
});

// Error handling middleware with detailed logging
app.use((err, req, res, next) => {
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

module.exports = app;
