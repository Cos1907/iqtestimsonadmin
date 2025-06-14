const mongoose = require('mongoose');

const pixelSchema = new mongoose.Schema({
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
    enum: ['facebook', 'google', 'tiktok', 'twitter', 'linkedin', 'custom'],
    required: true
  },
  pixelId: {
    type: String,
    required: true,
    unique: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'testing'],
    default: 'testing'
  },
  events: [{
    name: {
      type: String,
      required: true
    },
    description: String,
    isActive: {
      type: Boolean,
      default: true
    },
    customParameters: [{
      key: String,
      value: String
    }]
  }],
  trackingEvents: {
    pageView: {
      type: Boolean,
      default: true
    },
    registration: {
      type: Boolean,
      default: true
    },
    testStart: {
      type: Boolean,
      default: true
    },
    testCompletion: {
      type: Boolean,
      default: true
    },
    subscription: {
      type: Boolean,
      default: true
    },
    purchase: {
      type: Boolean,
      default: true
    }
  },
  conversionValue: {
    registration: {
      type: Number,
      default: 0
    },
    testCompletion: {
      type: Number,
      default: 0
    },
    subscription: {
      type: Number,
      default: 0
    },
    purchase: {
      type: Number,
      default: 0
    }
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
pixelSchema.index({ status: 1, isActive: 1 });
pixelSchema.index({ pixelId: 1 });
pixelSchema.index({ type: 1 });

module.exports = mongoose.model('Pixel', pixelSchema); 