const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { setupLogger } = require('../utils/logger');

const logger = setupLogger();

const adminAuth = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      // Get token from header
      token = req.headers.authorization.split(' ')[1];

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Get user from the token
      req.user = await User.findById(decoded.id).select('-password');

      if (!req.user) {
        return res.status(401).json({ message: 'Not authorized, user not found' });
      }

      // Check if user is admin
      if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not authorized, admin access required' });
      }

      next();
    } catch (error) {
      logger.error('Not authorized, token failed:', error);
      return res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no token' });
  }
};

module.exports = adminAuth; 