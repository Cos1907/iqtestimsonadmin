const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'super_admin'],
    default: 'user',
  },
  // Profil bilgileri
  age: {
    type: String,
    default: '',
  },
  gender: {
    type: String,
    enum: ['Erkek', 'Kadın', 'Diğer', ''],
    default: '',
  },
  selectedAvatar: {
    type: String,
    default: 'avatar1.png',
  },
  emailVerified: {
    type: Boolean,
    default: false,
  },
  emailVerificationToken: {
    type: String,
  },
  emailVerificationExpires: {
    type: Date,
  },
  purchasedTests: [
    {
      testId: { type: mongoose.Schema.Types.ObjectId, ref: 'Test' },
      purchasedAt: { type: Date, default: Date.now },
    },
  ],
  results: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Result' }],
  certificates: [
    {
      testId: { type: mongoose.Schema.Types.ObjectId, ref: 'Test' },
      certificateLink: String,
    },
  ],
  subscriptions: [
    {
      subscriptionId: { type: mongoose.Schema.Types.ObjectId, ref: 'PricePackage' },
      startDate: Date,
      endDate: Date,
      status: { type: String, enum: ['active', 'expired', 'cancelled'], default: 'active' },
    },
  ],
  // Push notification fields
  expoPushToken: {
    type: String,
    default: null,
  },
  platform: {
    type: String,
    enum: ['ios', 'android', 'web'],
    default: null,
  },
  lastTokenUpdate: {
    type: Date,
    default: null,
  },
  notificationPreferences: {
    enabled: {
      type: Boolean,
      default: true,
    },
    types: {
      info: { type: Boolean, default: true },
      success: { type: Boolean, default: true },
      warning: { type: Boolean, default: true },
      error: { type: Boolean, default: true },
      promotion: { type: Boolean, default: true },
      test_result: { type: Boolean, default: true },
      system: { type: Boolean, default: true },
    },
    quietHours: {
      enabled: { type: Boolean, default: false },
      start: { type: String, default: '22:00' },
      end: { type: String, default: '08:00' },
    },
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Hash password before saving
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password
UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema); 