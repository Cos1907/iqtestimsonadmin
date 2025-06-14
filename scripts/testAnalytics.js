const mongoose = require('mongoose');
const AdminActivity = require('../models/AdminActivity');
const User = require('../models/User');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/quizaki', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const testAnalytics = async () => {
  try {
    console.log('Testing analytics functionality...');
    
    // Check if we have admin activities
    const totalActivities = await AdminActivity.countDocuments();
    console.log(`Total admin activities in database: ${totalActivities}`);
    
    if (totalActivities === 0) {
      console.log('No activities found. Please run createSampleActivities.js first.');
      return;
    }
    
    // Test dashboard stats aggregation
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todayActivities = await AdminActivity.countDocuments({
      createdAt: { $gte: today }
    });
    
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    const yesterdayActivities = await AdminActivity.countDocuments({
      createdAt: { $gte: yesterday, $lt: today }
    });
    
    console.log(`Today's activities: ${todayActivities}`);
    console.log(`Yesterday's activities: ${yesterdayActivities}`);
    
    // Test analytics aggregation
    const activitiesByAction = await AdminActivity.aggregate([
      { $group: { _id: '$action', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    console.log('Activities by action:', activitiesByAction);
    
    const activitiesByModule = await AdminActivity.aggregate([
      { $group: { _id: '$module', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    console.log('Activities by module:', activitiesByModule);
    
    // Test recent activities
    const recentActivities = await AdminActivity.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('adminId', 'name email');
    
    console.log('Recent activities:', recentActivities.length);
    
    console.log('Analytics test completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Error testing analytics:', error);
    process.exit(1);
  }
};

testAnalytics(); 