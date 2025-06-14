const mongoose = require('mongoose');

const subscriptionPlanSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    default: 'TRY',
    enum: ['TRY', 'USD', 'EUR']
  },
  duration: {
    type: Number,
    required: true,
    min: 1,
    comment: 'Duration in days'
  },
  durationType: {
    type: String,
    required: true,
    enum: ['days', 'weeks', 'months', 'years'],
    default: 'months'
  },
  features: [{
    title: {
      type: String,
      required: true
    },
    description: String,
    included: {
      type: Boolean,
      default: true
    }
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  isPopular: {
    type: Boolean,
    default: false
  },
  sortOrder: {
    type: Number,
    default: 0
  },
  // iOS App Store product ID
  iosProductId: {
    type: String,
    required: true,
    unique: true
  },
  // Android Google Play product ID
  androidProductId: {
    type: String,
    required: true,
    unique: true
  },
  // Test completion score range for this plan
  minScore: {
    type: Number,
    min: 0,
    max: 200
  },
  maxScore: {
    type: Number,
    min: 0,
    max: 200
  },
  // Visual customization
  color: {
    type: String,
    default: '#1976d2'
  },
  icon: {
    type: String,
    default: 'star'
  },
  // Analytics
  totalPurchases: {
    type: Number,
    default: 0
  },
  totalRevenue: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Index for efficient queries
subscriptionPlanSchema.index({ isActive: 1, sortOrder: 1 });
subscriptionPlanSchema.index({ minScore: 1, maxScore: 1 });
subscriptionPlanSchema.index({ iosProductId: 1 });
subscriptionPlanSchema.index({ androidProductId: 1 });

// Virtual for formatted price
subscriptionPlanSchema.virtual('formattedPrice').get(function() {
  const currencySymbols = {
    'TRY': '₺',
    'USD': '$',
    'EUR': '€'
  };
  return `${currencySymbols[this.currency]}${this.price}`;
});

// Virtual for duration text
subscriptionPlanSchema.virtual('durationText').get(function() {
  const durationMap = {
    'days': 'gün',
    'weeks': 'hafta',
    'months': 'ay',
    'years': 'yıl'
  };
  return `${this.duration} ${durationMap[this.durationType]}`;
});

// Method to check if plan is suitable for a test score
subscriptionPlanSchema.methods.isSuitableForScore = function(score) {
  return score >= this.minScore && score <= this.maxScore;
};

// Static method to get plans for a specific score
subscriptionPlanSchema.statics.getPlansForScore = function(score) {
  return this.find({
    isActive: true,
    minScore: { $lte: score },
    maxScore: { $gte: score }
  }).sort({ sortOrder: 1, price: 1 });
};

// Static method to get popular plans
subscriptionPlanSchema.statics.getPopularPlans = function() {
  return this.find({
    isActive: true,
    isPopular: true
  }).sort({ sortOrder: 1 });
};

// Pre-save middleware to ensure maxScore is greater than minScore
subscriptionPlanSchema.pre('save', function(next) {
  if (this.maxScore <= this.minScore) {
    return next(new Error('maxScore must be greater than minScore'));
  }
  next();
});

module.exports = mongoose.model('SubscriptionPlan', subscriptionPlanSchema); 