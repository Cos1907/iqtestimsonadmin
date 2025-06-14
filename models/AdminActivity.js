const mongoose = require('mongoose');

const adminActivitySchema = new mongoose.Schema({
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Admin ID gereklidir']
  },
  adminName: {
    type: String,
    required: [true, 'Admin adı gereklidir']
  },
  adminEmail: {
    type: String,
    required: [true, 'Admin email gereklidir']
  },
  action: {
    type: String,
    required: [true, 'Aksiyon türü gereklidir'],
    enum: [
      'login', 'logout', 'create', 'update', 'delete', 'publish', 'unpublish',
      'feature', 'unfeature', 'export', 'import', 'bulk_action', 'settings_change',
      'user_management', 'content_management', 'analytics_view', 'report_generate'
    ]
  },
  module: {
    type: String,
    required: [true, 'Modül adı gereklidir'],
    enum: [
      'dashboard', 'users', 'tests', 'questions', 'categories', 'subscriptions',
      'subscription_plans', 'notifications', 'test_results', 'blog', 'pages',
      'campaigns', 'pixels', 'analytics', 'settings', 'auth'
    ]
  },
  description: {
    type: String,
    required: [true, 'Aksiyon açıklaması gereklidir']
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  },
  status: {
    type: String,
    enum: ['success', 'error', 'warning'],
    default: 'success'
  },
  affectedRecords: {
    type: Number,
    default: 1
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes
adminActivitySchema.index({ adminId: 1, createdAt: -1 });
adminActivitySchema.index({ action: 1, createdAt: -1 });
adminActivitySchema.index({ module: 1, createdAt: -1 });
adminActivitySchema.index({ createdAt: -1 });

module.exports = mongoose.model('AdminActivity', adminActivitySchema); 