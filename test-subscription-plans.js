const express = require('express');
const mongoose = require('mongoose');
const SubscriptionPlan = require('./models/SubscriptionPlan');
const adminAuth = require('./middleware/adminAuth');

// Test the subscription plans endpoint
async function testSubscriptionPlans() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/quizaki');
    console.log('Connected to MongoDB');

    // Count existing plans
    const count = await SubscriptionPlan.countDocuments();
    console.log('Existing subscription plans:', count);

    // Get all plans
    const plans = await SubscriptionPlan.find({});
    console.log('Plans:', plans.map(p => ({ id: p._id, name: p.name, isActive: p.isActive })));

    // Test the route logic
    const query = {};
    const sortOptions = { createdAt: -1 };
    
    const testPlans = await SubscriptionPlan.find(query)
      .sort(sortOptions)
      .limit(10)
      .skip(0)
      .exec();
    
    console.log('Test query result:', testPlans.length, 'plans found');

    mongoose.connection.close();
  } catch (error) {
    console.error('Test failed:', error);
    mongoose.connection.close();
  }
}

testSubscriptionPlans(); 