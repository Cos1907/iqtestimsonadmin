const mongoose = require('mongoose');

const pageSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Sayfa başlığı gereklidir'],
    trim: true,
    maxlength: [200, 'Başlık 200 karakterden uzun olamaz']
  },
  slug: {
    type: String,
    required: [true, 'URL slug gereklidir'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^[a-z0-9-]+$/, 'Slug sadece küçük harf, rakam ve tire içerebilir']
  },
  content: {
    type: String,
    required: [true, 'Sayfa içeriği gereklidir']
  },
  excerpt: {
    type: String,
    maxlength: [500, 'Özet 500 karakterden uzun olamaz']
  },
  metaTitle: {
    type: String,
    maxlength: [60, 'Meta başlık 60 karakterden uzun olamaz']
  },
  metaDescription: {
    type: String,
    maxlength: [160, 'Meta açıklama 160 karakterden uzun olamaz']
  },
  metaKeywords: [{
    type: String,
    trim: true
  }],
  template: {
    type: String,
    enum: ['default', 'landing', 'contact', 'about', 'privacy', 'terms'],
    default: 'default'
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  isFeatured: {
    type: Boolean,
    default: false
  },
  sortOrder: {
    type: Number,
    default: 0
  },
  viewCount: {
    type: Number,
    default: 0
  },
  featuredImage: {
    type: String
  },
  tags: [{
    type: String,
    trim: true
  }],
  category: {
    type: String,
    enum: ['general', 'information', 'legal', 'marketing', 'help'],
    default: 'general'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes
pageSchema.index({ slug: 1 });
pageSchema.index({ isPublished: 1 });
pageSchema.index({ category: 1 });
pageSchema.index({ tags: 1 });
pageSchema.index({ createdAt: -1 });

// Virtual for URL
pageSchema.virtual('url').get(function() {
  return `/pages/${this.slug}`;
});

// Method to increment view count
pageSchema.methods.incrementViewCount = function() {
  this.viewCount += 1;
  return this.save();
};

// Static method to get published pages
pageSchema.statics.getPublishedPages = function() {
  return this.find({ isPublished: true }).sort({ sortOrder: 1, createdAt: -1 });
};

// Static method to get featured pages
pageSchema.statics.getFeaturedPages = function() {
  return this.find({ isPublished: true, isFeatured: true }).sort({ sortOrder: 1, createdAt: -1 });
};

// Pre-save middleware to generate slug if not provided
pageSchema.pre('save', function(next) {
  if (!this.slug && this.title) {
    this.slug = this.title
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim('-');
  }
  next();
});

module.exports = mongoose.model('Page', pageSchema); 