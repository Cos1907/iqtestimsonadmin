const mongoose = require('mongoose');

const TestSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
  },
  category: {
    type: String,
    required: true,
    enum: ['Genel Kültür', 'Bilim', 'Tarih', 'Spor', 'Müzik', 'Film', 'Coğrafya', 'Edebiyat', 'Teknoloji'],
  },
  difficulty: {
    type: String,
    enum: ['kolay', 'orta', 'zor'],
    default: 'orta',
  },
  timeLimit: {
    type: Number, // in minutes
    default: 20,
  },
  questions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Question'
  }],
  image: {
    type: String, // URL or path to test image
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  isNew: {
    type: Boolean,
    default: false,
  },
  participants: {
    type: Number,
    default: 0,
  },
  rating: {
    type: Number,
    default: 0,
  },
  ratingCount: {
    type: Number,
    default: 0,
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
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

// Update the updatedAt field before saving
TestSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Test', TestSchema); 