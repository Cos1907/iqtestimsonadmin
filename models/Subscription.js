const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  plan: {
    type: String,
    required: true,
    enum: ['free', 'basic', 'premium', 'enterprise']
  },
  planDetails: {
    name: {
      type: String,
      required: true
    },
    price: {
      type: Number,
      required: true
    },
    currency: {
      type: String,
      default: 'TRY'
    },
    duration: {
      type: Number, // in days
      required: true
    },
    features: [{
      type: String
    }],
    maxTests: {
      type: Number
    },
    maxQuestions: {
      type: Number
    },
    prioritySupport: {
      type: Boolean,
      default: false
    },
    customBranding: {
      type: Boolean,
      default: false
    },
    analytics: {
      type: Boolean,
      default: false
    }
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'cancelled', 'expired', 'pending'],
    default: 'active'
  },
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date,
    required: true
  },
  autoRenew: {
    type: Boolean,
    default: true
  },
  paymentMethod: {
    type: String,
    enum: ['credit_card', 'paypal', 'bank_transfer', 'crypto'],
    required: true
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'refunded'],
    default: 'pending'
  },
  transactionId: {
    type: String
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'TRY'
  },
  discount: {
    type: Number,
    default: 0
  },
  tax: {
    type: Number,
    default: 0
  },
  totalAmount: {
    type: Number,
    required: true
  },
  billingAddress: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  usage: {
    testsTaken: {
      type: Number,
      default: 0
    },
    questionsCreated: {
      type: Number,
      default: 0
    },
    storageUsed: {
      type: Number, // in MB
      default: 0
    }
  },
  limits: {
    maxTests: {
      type: Number
    },
    maxQuestions: {
      type: Number
    },
    maxStorage: {
      type: Number // in MB
    }
  },
  isTrial: {
    type: Boolean,
    default: false
  },
  trialEndDate: {
    type: Date
  },
  cancellationReason: {
    type: String
  },
  cancelledAt: {
    type: Date
  },
  reactivatedAt: {
    type: Date
  },
  notes: {
    type: String
  },
  planId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SubscriptionPlan',
    required: false
  },
}, {
  timestamps: true
});

// Indexes for efficient queries
subscriptionSchema.index({ user: 1, status: 1 });
subscriptionSchema.index({ status: 1, endDate: 1 });
subscriptionSchema.index({ plan: 1, status: 1 });

// Virtual for checking if subscription is active
subscriptionSchema.virtual('isActive').get(function() {
  return this.status === 'active' && new Date() <= this.endDate;
});

// Virtual for days remaining
subscriptionSchema.virtual('daysRemaining').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.endDate);
  const diffTime = end - now;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

module.exports = mongoose.model('Subscription', subscriptionSchema); 