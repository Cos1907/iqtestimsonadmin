const express = require('express');
const router = express.Router();
const Blog = require('../models/Blog');
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure multer for image uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, '../uploads/blog');
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'blog-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    // Check file type
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Sadece resim dosyaları yüklenebilir!'));
    }
  }
});

// Image upload endpoint
router.post('/upload-image', adminAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Lütfen bir resim dosyası seçin' });
    }

    // Return the file path that can be accessed via URL
    const imageUrl = `/uploads/blog/${req.file.filename}`;
    
    res.json({
      success: true,
      imageUrl: imageUrl,
      filename: req.file.filename,
      message: 'Resim başarıyla yüklendi'
    });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ message: 'Resim yüklenirken hata oluştu' });
  }
});

// Serve uploaded images
router.get('/uploads/blog/:filename', (req, res) => {
  const filePath = path.join(__dirname, '../uploads/blog', req.params.filename);
  res.sendFile(filePath);
});

// Get all blog posts for admin panel (with language filtering)
router.get('/admin/all', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, category, search, featured, language = 'tr' } = req.query;
    
    const query = { language };
    
    if (category) {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.isFeatured = true;
    }
    
    if (search) {
      query.$text = { $search: search };
    }
    
    const blogs = await Blog.find(query)
      .populate('author', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Blog.countDocuments(query);
    
    res.json({
      blogs,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Blog yazıları yüklenirken hata oluştu' });
  }
});

// Get all blog posts (public)
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, category, search, featured, language = 'tr' } = req.query;
    
    const query = { isPublished: true, language };
    
    if (category) {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.isFeatured = true;
    }
    
    if (search) {
      query.$text = { $search: search };
    }
    
    const blogs = await Blog.find(query)
      .populate('author', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Blog.countDocuments(query);
    
    res.json({
      blogs,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Blog yazıları yüklenirken hata oluştu' });
  }
});

// Get single blog post (public)
router.get('/:id', async (req, res) => {
  try {
    const { language = 'tr' } = req.query;
    const blog = await Blog.findOne({ _id: req.params.id, language })
      .populate('author', 'name email')
      .populate('comments.user', 'name email');
    
    if (!blog) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    if (!blog.isPublished) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    // Increment view count
    blog.viewCount += 1;
    await blog.save();
    
    res.json(blog);
  } catch (error) {
    res.status(500).json({ message: 'Blog yazısı yüklenirken hata oluştu' });
  }
});

// Create blog post (admin only)
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      title,
      content,
      excerpt,
      category,
      tags,
      featuredImage,
      isPublished,
      isFeatured,
      seoTitle,
      seoDescription,
      seoKeywords,
      language = 'tr'
    } = req.body;
    
    const blog = new Blog({
      title: {
        tr: language === 'tr' ? title : '',
        en: language === 'en' ? title : ''
      },
      content: {
        tr: language === 'tr' ? content : '',
        en: language === 'en' ? content : ''
      },
      excerpt: {
        tr: language === 'tr' ? excerpt : '',
        en: language === 'en' ? excerpt : ''
      },
      language,
      author: req.user.id,
      category,
      tags,
      featuredImage,
      isPublished: isPublished || false,
      isFeatured: isFeatured || false,
      seoTitle: {
        tr: language === 'tr' ? seoTitle : '',
        en: language === 'en' ? seoTitle : ''
      },
      seoDescription: {
        tr: language === 'tr' ? seoDescription : '',
        en: language === 'en' ? seoDescription : ''
      },
      seoKeywords
    });
    
    await blog.save();
    
    const populatedBlog = await Blog.findById(blog._id)
      .populate('author', 'name email');
    
    res.status(201).json(populatedBlog);
  } catch (error) {
    res.status(500).json({ message: 'Blog yazısı oluşturulurken hata oluştu' });
  }
});

// Update blog post (admin only)
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const {
      title,
      content,
      excerpt,
      category,
      tags,
      featuredImage,
      isPublished,
      isFeatured,
      seoTitle,
      seoDescription,
      seoKeywords,
      language = 'tr'
    } = req.body;
    
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    // Update language-specific fields
    if (title) {
      blog.title[language] = title;
    }
    if (content) {
      blog.content[language] = content;
    }
    if (excerpt) {
      blog.excerpt[language] = excerpt;
    }
    if (seoTitle) {
      blog.seoTitle[language] = seoTitle;
    }
    if (seoDescription) {
      blog.seoDescription[language] = seoDescription;
    }
    
    blog.category = category || blog.category;
    blog.tags = tags || blog.tags;
    blog.featuredImage = featuredImage || blog.featuredImage;
    blog.isPublished = isPublished !== undefined ? isPublished : blog.isPublished;
    blog.isFeatured = isFeatured !== undefined ? isFeatured : blog.isFeatured;
    blog.seoKeywords = seoKeywords || blog.seoKeywords;
    
    await blog.save();
    
    const updatedBlog = await Blog.findById(blog._id)
      .populate('author', 'name email');
    
    res.json(updatedBlog);
  } catch (error) {
    res.status(500).json({ message: 'Blog yazısı güncellenirken hata oluştu' });
  }
});

// Delete blog post (admin only)
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    await Blog.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Blog yazısı başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Blog yazısı silinirken hata oluştu' });
  }
});

// Add comment to blog post (authenticated users)
router.post('/:id/comments', auth, async (req, res) => {
  try {
    const { content } = req.body;
    
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    if (!blog.isPublished) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    blog.comments.push({
      user: req.user.id,
      content
    });
    
    await blog.save();
    
    const updatedBlog = await Blog.findById(blog._id)
      .populate('author', 'name email')
      .populate('comments.user', 'name email');
    
    res.json(updatedBlog);
  } catch (error) {
    res.status(500).json({ message: 'Yorum eklenirken hata oluştu' });
  }
});

// Like/unlike blog post (authenticated users)
router.post('/:id/like', auth, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ message: 'Blog yazısı bulunamadı' });
    }
    
    const likeIndex = blog.likes.indexOf(req.user.id);
    
    if (likeIndex > -1) {
      // Unlike
      blog.likes.splice(likeIndex, 1);
    } else {
      // Like
      blog.likes.push(req.user.id);
    }
    
    await blog.save();
    
    res.json({ likes: blog.likes.length, isLiked: likeIndex === -1 });
  } catch (error) {
    res.status(500).json({ message: 'İşlem sırasında hata oluştu' });
  }
});

// Get blog statistics (admin only)
router.get('/stats/overview', adminAuth, async (req, res) => {
  try {
    const totalPosts = await Blog.countDocuments();
    const publishedPosts = await Blog.countDocuments({ isPublished: true });
    const draftPosts = await Blog.countDocuments({ isPublished: false });
    const featuredPosts = await Blog.countDocuments({ isFeatured: true });
    
    const totalViews = await Blog.aggregate([
      { $group: { _id: null, totalViews: { $sum: '$viewCount' } } }
    ]);
    
    const totalLikes = await Blog.aggregate([
      { $group: { _id: null, totalLikes: { $sum: { $size: '$likes' } } } }
    ]);
    
    const totalComments = await Blog.aggregate([
      { $group: { _id: null, totalComments: { $sum: { $size: '$comments' } } } }
    ]);
    
    const categoryStats = await Blog.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    res.json({
      totalPosts,
      publishedPosts,
      draftPosts,
      featuredPosts,
      totalViews: totalViews[0]?.totalViews || 0,
      totalLikes: totalLikes[0]?.totalLikes || 0,
      totalComments: totalComments[0]?.totalComments || 0,
      categoryStats
    });
  } catch (error) {
    res.status(500).json({ message: 'İstatistikler yüklenirken hata oluştu' });
  }
});

module.exports = router; 