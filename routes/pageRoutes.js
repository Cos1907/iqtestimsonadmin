const express = require('express');
const router = express.Router();
const Page = require('../models/Page');
const adminAuth = require('../middleware/adminAuth');
const auth = require('../middleware/auth');

// Get all pages (admin only)
router.get('/', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, isPublished, category, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
    
    const query = {};
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } },
        { slug: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (isPublished !== undefined && isPublished !== 'all') {
      query.isPublished = isPublished === 'true';
    }
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
    
    const pages = await Page.find(query)
      .populate('createdBy', 'name email')
      .populate('updatedBy', 'name email')
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Page.countDocuments(query);
    
    res.json({
      pages,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching pages:', error);
    res.status(500).json({ message: 'Sayfalar getirilirken hata oluştu' });
  }
});

// Get published pages (public)
router.get('/public', async (req, res) => {
  try {
    const { category, featured, limit = 10 } = req.query;
    
    let query = { isPublished: true };
    
    if (category) {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.isFeatured = true;
    }
    
    const pages = await Page.find(query)
      .select('title slug excerpt featuredImage category tags createdAt')
      .sort({ sortOrder: 1, createdAt: -1 })
      .limit(parseInt(limit))
      .exec();
    
    res.json(pages);
  } catch (error) {
    console.error('Error fetching public pages:', error);
    res.status(500).json({ message: 'Sayfalar getirilirken hata oluştu' });
  }
});

// Get page by slug (public)
router.get('/public/:slug', async (req, res) => {
  try {
    const page = await Page.findOne({ slug: req.params.slug, isPublished: true })
      .populate('createdBy', 'name email');
    
    if (!page) {
      return res.status(404).json({ message: 'Sayfa bulunamadı' });
    }
    
    // Increment view count
    await page.incrementViewCount();
    
    res.json(page);
  } catch (error) {
    console.error('Error fetching page:', error);
    res.status(500).json({ message: 'Sayfa getirilirken hata oluştu' });
  }
});

// Get page by ID (admin only)
router.get('/:id', adminAuth, async (req, res) => {
  try {
    const page = await Page.findById(req.params.id)
      .populate('createdBy', 'name email')
      .populate('updatedBy', 'name email');
    
    if (!page) {
      return res.status(404).json({ message: 'Sayfa bulunamadı' });
    }
    
    res.json(page);
  } catch (error) {
    console.error('Error fetching page:', error);
    res.status(500).json({ message: 'Sayfa getirilirken hata oluştu' });
  }
});

// Create new page (admin only)
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      title,
      slug,
      content,
      excerpt,
      metaTitle,
      metaDescription,
      metaKeywords,
      template,
      isPublished,
      isFeatured,
      sortOrder,
      featuredImage,
      tags,
      category
    } = req.body;
    
    // Check if slug already exists
    if (slug) {
      const existingPage = await Page.findOne({ slug });
      if (existingPage) {
        return res.status(400).json({ 
          message: 'Bu URL slug\'ı zaten kullanılıyor' 
        });
      }
    }
    
    const page = new Page({
      title,
      slug,
      content,
      excerpt,
      metaTitle,
      metaDescription,
      metaKeywords,
      template,
      isPublished,
      isFeatured,
      sortOrder,
      featuredImage,
      tags,
      category,
      createdBy: req.user.id
    });
    
    await page.save();
    
    res.status(201).json({
      message: 'Sayfa başarıyla oluşturuldu',
      page
    });
  } catch (error) {
    console.error('Error creating page:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Geçersiz veri formatı',
        errors: Object.values(error.errors).map(err => err.message)
      });
    }
    
    res.status(500).json({ message: 'Sayfa oluşturulurken hata oluştu' });
  }
});

// Update page (admin only)
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const {
      title,
      slug,
      content,
      excerpt,
      metaTitle,
      metaDescription,
      metaKeywords,
      template,
      isPublished,
      isFeatured,
      sortOrder,
      featuredImage,
      tags,
      category
    } = req.body;
    
    const page = await Page.findById(req.params.id);
    
    if (!page) {
      return res.status(404).json({ message: 'Sayfa bulunamadı' });
    }
    
    // Check if slug already exists (excluding current page)
    if (slug && slug !== page.slug) {
      const existingPage = await Page.findOne({ slug, _id: { $ne: req.params.id } });
      if (existingPage) {
        return res.status(400).json({ 
          message: 'Bu URL slug\'ı zaten kullanılıyor' 
        });
      }
    }
    
    // Update fields
    page.title = title || page.title;
    page.slug = slug || page.slug;
    page.content = content || page.content;
    page.excerpt = excerpt || page.excerpt;
    page.metaTitle = metaTitle || page.metaTitle;
    page.metaDescription = metaDescription || page.metaDescription;
    page.metaKeywords = metaKeywords || page.metaKeywords;
    page.template = template || page.template;
    page.isPublished = isPublished !== undefined ? isPublished : page.isPublished;
    page.isFeatured = isFeatured !== undefined ? isFeatured : page.isFeatured;
    page.sortOrder = sortOrder !== undefined ? sortOrder : page.sortOrder;
    page.featuredImage = featuredImage || page.featuredImage;
    page.tags = tags || page.tags;
    page.category = category || page.category;
    page.updatedBy = req.user.id;
    
    await page.save();
    
    res.json({
      message: 'Sayfa başarıyla güncellendi',
      page
    });
  } catch (error) {
    console.error('Error updating page:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Geçersiz veri formatı',
        errors: Object.values(error.errors).map(err => err.message)
      });
    }
    
    res.status(500).json({ message: 'Sayfa güncellenirken hata oluştu' });
  }
});

// Delete page (admin only)
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const page = await Page.findById(req.params.id);
    
    if (!page) {
      return res.status(404).json({ message: 'Sayfa bulunamadı' });
    }
    
    await Page.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Sayfa başarıyla silindi' });
  } catch (error) {
    console.error('Error deleting page:', error);
    res.status(500).json({ message: 'Sayfa silinirken hata oluştu' });
  }
});

// Toggle page published status (admin only)
router.patch('/:id/toggle-publish', adminAuth, async (req, res) => {
  try {
    const page = await Page.findById(req.params.id);
    
    if (!page) {
      return res.status(404).json({ message: 'Sayfa bulunamadı' });
    }
    
    page.isPublished = !page.isPublished;
    page.updatedBy = req.user.id;
    await page.save();
    
    res.json({
      message: `Sayfa ${page.isPublished ? 'yayınlandı' : 'taslak yapıldı'}`,
      page
    });
  } catch (error) {
    console.error('Error toggling page publish status:', error);
    res.status(500).json({ message: 'Sayfa durumu değiştirilirken hata oluştu' });
  }
});

// Toggle page featured status (admin only)
router.patch('/:id/toggle-featured', adminAuth, async (req, res) => {
  try {
    const page = await Page.findById(req.params.id);
    
    if (!page) {
      return res.status(404).json({ message: 'Sayfa bulunamadı' });
    }
    
    page.isFeatured = !page.isFeatured;
    page.updatedBy = req.user.id;
    await page.save();
    
    res.json({
      message: `Sayfa ${page.isFeatured ? 'öne çıkarıldı' : 'öne çıkarma kaldırıldı'}`,
      page
    });
  } catch (error) {
    console.error('Error toggling page featured status:', error);
    res.status(500).json({ message: 'Sayfa durumu değiştirilirken hata oluştu' });
  }
});

// Get page analytics (admin only)
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const totalPages = await Page.countDocuments();
    const publishedPages = await Page.countDocuments({ isPublished: true });
    const featuredPages = await Page.countDocuments({ isFeatured: true });
    const draftPages = await Page.countDocuments({ isPublished: false });
    
    const totalViews = await Page.aggregate([
      { $group: { _id: null, total: { $sum: '$viewCount' } } }
    ]);
    
    const pagesByCategory = await Page.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]);
    
    const mostViewedPages = await Page.find({ isPublished: true })
      .sort({ viewCount: -1 })
      .limit(5)
      .select('title slug viewCount');
    
    res.json({
      totalPages,
      publishedPages,
      featuredPages,
      draftPages,
      totalViews: totalViews[0]?.total || 0,
      pagesByCategory,
      mostViewedPages
    });
  } catch (error) {
    console.error('Error fetching page analytics:', error);
    res.status(500).json({ message: 'Analitik veriler getirilirken hata oluştu' });
  }
});

module.exports = router; 