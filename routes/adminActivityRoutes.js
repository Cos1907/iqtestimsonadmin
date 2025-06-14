const express = require('express');
const router = express.Router();
const AdminActivity = require('../models/AdminActivity');
const adminAuth = require('../middleware/adminAuth');

// Get admin activities (admin only)
router.get('/', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      adminId, 
      action, 
      module, 
      status, 
      startDate, 
      endDate,
      sortBy = 'createdAt', 
      sortOrder = 'desc' 
    } = req.query;
    
    const query = {};
    
    if (adminId) {
      query.adminId = adminId;
    }
    
    if (action) {
      query.action = action;
    }
    
    if (module) {
      query.module = module;
    }
    
    if (status) {
      query.status = status;
    }
    
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) {
        query.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        query.createdAt.$lte = new Date(endDate);
      }
    }
    
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
    
    const activities = await AdminActivity.find(query)
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('adminId', 'name email');
    
    const total = await AdminActivity.countDocuments(query);
    
    res.json({
      activities,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching admin activities:', error);
    res.status(500).json({ message: 'Admin aktiviteleri getirilirken hata oluştu' });
  }
});

// Get admin activity analytics (admin only)
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    const dateFilter = {};
    if (startDate || endDate) {
      dateFilter.createdAt = {};
      if (startDate) {
        dateFilter.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        dateFilter.createdAt.$lte = new Date(endDate);
      }
    }
    
    // Total activities
    const totalActivities = await AdminActivity.countDocuments(dateFilter);
    
    // Activities by action type
    const activitiesByAction = await AdminActivity.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$action', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    // Activities by module
    const activitiesByModule = await AdminActivity.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$module', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    // Activities by admin
    const activitiesByAdmin = await AdminActivity.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$adminId', count: { $sum: 1 }, adminName: { $first: '$adminName' } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    // Activities by status
    const activitiesByStatus = await AdminActivity.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    
    // Recent activities (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentActivities = await AdminActivity.find({
      createdAt: { $gte: sevenDaysAgo }
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .populate('adminId', 'name email');
    
    // Daily activity for last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const dailyActivity = await AdminActivity.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
      }
    ]);
    
    res.json({
      totalActivities,
      activitiesByAction,
      activitiesByModule,
      activitiesByAdmin,
      activitiesByStatus,
      recentActivities,
      dailyActivity
    });
  } catch (error) {
    console.error('Error fetching admin activity analytics:', error);
    res.status(500).json({ message: 'Admin aktivite analitikleri getirilirken hata oluştu' });
  }
});

// Get current admin's activities
router.get('/my-activities', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    const activities = await AdminActivity.find({ adminId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await AdminActivity.countDocuments({ adminId: req.user.id });
    
    res.json({
      activities,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching my activities:', error);
    res.status(500).json({ message: 'Aktiviteleriniz getirilirken hata oluştu' });
  }
});

// Create admin activity (internal use)
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      action,
      module,
      description,
      details = {},
      status = 'success',
      affectedRecords = 1
    } = req.body;
    
    const activity = new AdminActivity({
      adminId: req.user.id,
      adminName: req.user.name,
      adminEmail: req.user.email,
      action,
      module,
      description,
      details,
      status,
      affectedRecords,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    await activity.save();
    
    res.status(201).json({
      message: 'Aktivite kaydedildi',
      activity
    });
  } catch (error) {
    console.error('Error creating admin activity:', error);
    res.status(500).json({ message: 'Aktivite kaydedilirken hata oluştu' });
  }
});

// Get activity statistics for dashboard
router.get('/stats/dashboard', adminAuth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    const thisWeek = new Date(today);
    thisWeek.setDate(thisWeek.getDate() - 7);
    
    const thisMonth = new Date(today);
    thisMonth.setMonth(thisMonth.getMonth() - 1);
    
    // Today's activities
    const todayActivities = await AdminActivity.countDocuments({
      createdAt: { $gte: today }
    });
    
    // Yesterday's activities
    const yesterdayActivities = await AdminActivity.countDocuments({
      createdAt: { $gte: yesterday, $lt: today }
    });
    
    // This week's activities
    const thisWeekActivities = await AdminActivity.countDocuments({
      createdAt: { $gte: thisWeek }
    });
    
    // This month's activities
    const thisMonthActivities = await AdminActivity.countDocuments({
      createdAt: { $gte: thisMonth }
    });
    
    // Most active modules today
    const todayModuleStats = await AdminActivity.aggregate([
      {
        $match: {
          createdAt: { $gte: today }
        }
      },
      {
        $group: {
          _id: '$module',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 5
      }
    ]);
    
    // Recent activities
    const recentActivities = await AdminActivity.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('adminId', 'name email');
    
    res.json({
      todayActivities,
      yesterdayActivities,
      thisWeekActivities,
      thisMonthActivities,
      todayModuleStats,
      recentActivities
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ message: 'Dashboard istatistikleri getirilirken hata oluştu' });
  }
});

module.exports = router; 