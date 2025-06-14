const AdminActivity = require('../models/AdminActivity');
const { setupLogger } = require('./logger');

const logger = setupLogger();

/**
 * Track admin activity
 * @param {Object} req - Express request object
 * @param {Object} options - Activity options
 * @param {string} options.action - Action type (login, create, update, delete, etc.)
 * @param {string} options.module - Module name (users, tests, etc.)
 * @param {string} options.description - Activity description
 * @param {Object} options.details - Additional details
 * @param {string} options.status - Status (success, error, warning)
 * @param {number} options.affectedRecords - Number of affected records
 */
const trackAdminActivity = async (req, options) => {
  try {
    // Only track if user is admin
    if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'super_admin')) {
      return;
    }

    const activity = new AdminActivity({
      adminId: req.user._id,
      adminName: req.user.name,
      adminEmail: req.user.email,
      action: options.action,
      module: options.module,
      description: options.description,
      details: options.details || {},
      status: options.status || 'success',
      affectedRecords: options.affectedRecords || 1,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    });

    await activity.save();
    logger.info(`Admin activity tracked: ${options.action} in ${options.module} by ${req.user.email}`);
  } catch (error) {
    logger.error('Error tracking admin activity:', error);
    // Don't throw error to avoid breaking the main functionality
  }
};

/**
 * Middleware to track admin activities
 * @param {Object} options - Activity options
 */
const adminActivityMiddleware = (options) => {
  return async (req, res, next) => {
    // Store original send function
    const originalSend = res.send;
    
    // Override send function to track activity after response
    res.send = function(data) {
      // Restore original send
      res.send = originalSend;
      
      // Track activity if response is successful
      if (res.statusCode >= 200 && res.statusCode < 300) {
        trackAdminActivity(req, options);
      }
      
      // Call original send
      return originalSend.call(this, data);
    };
    
    next();
  };
};

module.exports = {
  trackAdminActivity,
  adminActivityMiddleware
}; 