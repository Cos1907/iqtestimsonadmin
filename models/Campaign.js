const mongoose = require('mongoose');

const campaignSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  type: {
    type: String,
    enum: ['affiliate', 'referral', 'promotional', 'social', 'email', 'banner', 'popup'],
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'draft', 'paused'],
    default: 'draft'
  },
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date
  },
  budget: {
    amount: {
      type: Number,
      default: 0
    },
    currency: {
      type: String,
      default: 'TRY'
    },
    spent: {
      type: Number,
      default: 0
    }
  },
  targetAudience: {
    ageRange: {
      min: Number,
      max: Number
    },
    gender: {
      type: String,
      enum: ['all', 'male', 'female']
    },
    interests: [String],
    location: [String]
  },
  trackingCode: {
    type: String,
    unique: true,
    required: true
  },
  conversionGoals: {
    type: String,
    enum: ['registration', 'test_completion', 'subscription', 'app_download', 'custom'],
    required: true
  },
  customGoal: {
    type: String
  },
  commission: {
    type: Number,
    default: 0
  },
  commissionType: {
    type: String,
    enum: ['percentage', 'fixed'],
    default: 'percentage'
  },
  trackingMetrics: {
    impressions: {
      type: Number,
      default: 0
    },
    clicks: {
      type: Number,
      default: 0
    },
    conversions: {
      type: Number,
      default: 0
    },
    revenue: {
      type: Number,
      default: 0
    }
  },
  creativeAssets: {
    bannerUrl: String,
    landingPageUrl: String,
    description: String
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

// Index for better query performance
campaignSchema.index({ status: 1, isActive: 1 });
campaignSchema.index({ trackingCode: 1 });
campaignSchema.index({ startDate: 1, endDate: 1 });

module.exports = mongoose.model('Campaign', campaignSchema); 