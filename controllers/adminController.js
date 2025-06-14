const AppConfig = require('../models/AppConfig');
const { setupLogger } = require('../utils/logger');
const fs = require('fs');
const path = require('path');
const User = require('../models/User');
const Test = require('../models/Test');
const Subscription = require('../models/Subscription');
const TestResult = require('../models/TestResult');

const logger = setupLogger();
const logDir = path.join(__dirname, '..', 'logs');

// @desc    Get App Configuration
// @route   GET /api/admin/config
// @access  Private/Admin
const getAppConfig = async (req, res) => {
  try {
    let config = await AppConfig.findOne();
    if (!config) {
      config = await AppConfig.create({}); // Create default if not exists
    }
    res.status(200).json(config);
  } catch (error) {
    logger.error('Error getting app config:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Update App Configuration
// @route   PUT /api/admin/config
// @access  Private/SuperAdmin
const updateAppConfig = async (req, res) => {
  try {
    // Ensure only one config document exists
    let config = await AppConfig.findOne();
    if (!config) {
      config = await AppConfig.create({});
    }

    const updatedConfig = await AppConfig.findByIdAndUpdate(
      config._id,
      req.body,
      { new: true, runValidators: true }
    );
    
    logger.info('App config updated:', updatedConfig.toObject());
    res.status(200).json(updatedConfig);
  } catch (error) {
    logger.error('Error updating app config:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Get Error Logs
// @route   GET /api/admin/logs/error
// @access  Private/SuperAdmin
const getErrorLogs = async (req, res) => {
  const errorLogPath = path.join(logDir, 'error.log');
  fs.readFile(errorLogPath, 'utf8', (err, data) => {
    if (err) {
      logger.error('Error reading error log file:', err);
      return res.status(500).json({ message: 'Could not read error log file' });
    }
    // Split data by new line and filter out empty strings, then parse JSON
    const logs = data.split('\n').filter(line => line.trim() !== '').map(line => {
      try {
        return JSON.parse(line);
      } catch (parseErr) {
        logger.error('Error parsing log line:', parseErr, 'Line:', line);
        return { raw: line, error: 'Parsing error' };
      }
    });
    res.status(200).json(logs);
  });
};

// @desc    Get Combined Logs
// @route   GET /api/admin/logs/combined
// @access  Private/SuperAdmin
const getCombinedLogs = async (req, res) => {
  const combinedLogPath = path.join(logDir, 'combined.log');
  fs.readFile(combinedLogPath, 'utf8', (err, data) => {
    if (err) {
      logger.error('Error reading combined log file:', err);
      return res.status(500).json({ message: 'Could not read combined log file' });
    }
    const logs = data.split('\n').filter(line => line.trim() !== '').map(line => {
      try {
        return JSON.parse(line);
      } catch (parseErr) {
        logger.error('Error parsing log line:', parseErr, 'Line:', line);
        return { raw: line, error: 'Parsing error' };
      }
    });
    res.status(200).json(logs);
  });
};

// @desc    Make a user super_admin (TEMPORARY - FOR INITIAL SETUP ONLY)
// @route   PUT /api/admin/make-super-admin
// @access  Private/SuperAdmin
const makeSuperAdmin = async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.role = 'super_admin';
    await user.save();

    logger.info(`User ${user.email} role updated to super_admin by ${req.user.email}`);
    res.status(200).json({ message: `User ${user.email} is now super_admin` });
  } catch (error) {
    logger.error('Error making user super admin:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Dashboard overview stats
const dashboardOverview = async (req, res) => {
  try {
    console.log('Dashboard overview called');
    
    // Toplam kullanıcı
    const totalUsers = await User.countDocuments();
    console.log('Total users:', totalUsers);
    
    // Toplam test
    const totalTests = await Test.countDocuments();
    console.log('Total tests:', totalTests);
    
    // Toplam üyelik (abonelik)
    const totalSubscriptions = await Subscription.countDocuments();
    console.log('Total subscriptions:', totalSubscriptions);
    
    // Toplam kazanılan tutar (sadece tamamlanmış ödemeler)
    const totalRevenueAgg = await Subscription.aggregate([
      { $match: { paymentStatus: 'completed' } },
      { $group: { _id: null, total: { $sum: '$totalAmount' } } }
    ]);
    const totalRevenue = totalRevenueAgg[0]?.total || 0;
    console.log('Total revenue:', totalRevenue);
    
    // Son 24 saatte çözülen test
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const testsSolved24h = await TestResult.countDocuments({ completedAt: { $gte: since } });
    console.log('Tests solved in 24h:', testsSolved24h);

    // Son kullanıcı aktiviteleri
    const recentUsers = await User.find({})
      .sort({ createdAt: -1 })
      .limit(5)
      .select('name email createdAt role');
    console.log('Recent users count:', recentUsers.length);

    const recentTestResults = await TestResult.find({})
      .populate('user', 'name email')
      .populate('test', 'title')
      .sort({ completedAt: -1 })
      .limit(5)
      .select('user test score completedAt');
    console.log('Recent test results count:', recentTestResults.length);

    const recentSubscriptions = await Subscription.find({})
      .populate('user', 'name email')
      .populate('planId', 'name price')
      .sort({ createdAt: -1 })
      .limit(5)
      .select('user planId planDetails totalAmount paymentStatus createdAt');
    console.log('Recent subscriptions count:', recentSubscriptions.length);

    // planId yoksa planDetails.name ve planDetails.price ekle
    const recentSubscriptionsWithPlan = recentSubscriptions.map(sub => ({
      ...sub.toObject(),
      planId: sub.planId || { name: sub.planDetails?.name || sub.plan, price: sub.planDetails?.price || 0 }
    }));

    const responseData = {
      totalUsers,
      totalTests,
      totalSubscriptions,
      totalRevenue,
      testsSolved24h,
      recentUsers,
      recentTestResults,
      recentSubscriptions: recentSubscriptionsWithPlan
    };
    
    console.log('Sending response:', responseData);
    res.json(responseData);
  } catch (error) {
    console.error('Dashboard overview error:', error);
    res.status(500).json({ message: 'Dashboard verileri alınırken hata oluştu' });
  }
};

module.exports = { getAppConfig, updateAppConfig, getErrorLogs, getCombinedLogs, makeSuperAdmin, dashboardOverview }; 