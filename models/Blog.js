const mongoose = require('mongoose');

const blogSchema = new mongoose.Schema({
  title: {
    tr: { type: String, required: true, trim: true },
    en: { type: String, required: true, trim: true }
  },
  content: {
    tr: { type: String, required: true },
    en: { type: String, required: true }
  },
  excerpt: {
    tr: { type: String, trim: true },
    en: { type: String, trim: true }
  },
  language: {
    type: String,
    required: true,
    enum: ['tr', 'en'],
    default: 'tr'
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['Genel', 'Eğitim', 'Teknoloji', 'Sağlık', 'Spor', 'Bilim', 'Kültür']
  },
  tags: [{
    type: String,
    trim: true
  }],
  featuredImage: {
    type: String
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  isFeatured: {
    type: Boolean,
    default: false
  },
  viewCount: {
    type: Number,
    default: 0
  },
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    content: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  seoTitle: {
    tr: { type: String },
    en: { type: String }
  },
  seoDescription: {
    tr: { type: String },
    en: { type: String }
  },
  seoKeywords: [{
    type: String
  }]
}, {
  timestamps: true
});

// Index for search
blogSchema.index({ 'title.tr': 'text', 'title.en': 'text', 'content.tr': 'text', 'content.en': 'text', tags: 'text' });

module.exports = mongoose.model('Blog', blogSchema); 