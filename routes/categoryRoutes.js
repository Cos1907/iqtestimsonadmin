const express = require('express');
const router = express.Router();
const Category = require('../models/Category');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');

// Get all categories (public for tests, admin only for management)
router.get('/', async (req, res) => {
  try {
    const { isActive } = req.query;
    
    let query = {};
    if (isActive !== undefined) {
      query.isActive = isActive === 'true';
    }
    
    const categories = await Category.find(query)
      .populate('createdBy', 'name email')
      .sort({ sortOrder: 1, name: 1 });
    
    res.json({ categories });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Kategoriler yüklenirken hata oluştu' });
  }
});

// Get category by ID
router.get('/:id', async (req, res) => {
  try {
    const category = await Category.findById(req.params.id)
      .populate('createdBy', 'name email');
    
    if (!category) {
      return res.status(404).json({ message: 'Kategori bulunamadı' });
    }
    
    res.json(category);
  } catch (error) {
    console.error('Error fetching category:', error);
    res.status(500).json({ message: 'Kategori yüklenirken hata oluştu' });
  }
});

// Create new category (admin only)
router.post('/', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const { name, description, color, icon, isActive, sortOrder } = req.body;
    
    const category = new Category({
      name,
      description,
      color: color || '#FF9900',
      icon,
      isActive: isActive !== undefined ? isActive : true,
      sortOrder: sortOrder || 0,
      createdBy: req.user.id
    });
    
    await category.save();
    
    res.status(201).json(category);
  } catch (error) {
    console.error('Error creating category:', error);
    if (error.code === 11000) {
      res.status(400).json({ message: 'Bu kategori adı zaten kullanılıyor' });
    } else {
      res.status(500).json({ message: 'Kategori oluşturulurken hata oluştu', error: error.message });
    }
  }
});

// Update category (admin only)
router.put('/:id', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const { name, description, color, icon, isActive, sortOrder } = req.body;
    
    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ message: 'Kategori bulunamadı' });
    }
    
    if (name) category.name = name;
    if (description !== undefined) category.description = description;
    if (color) category.color = color;
    if (icon !== undefined) category.icon = icon;
    if (isActive !== undefined) category.isActive = isActive;
    if (sortOrder !== undefined) category.sortOrder = sortOrder;
    
    await category.save();
    
    res.json({ message: 'Kategori güncellendi', category });
  } catch (error) {
    console.error('Error updating category:', error);
    if (error.code === 11000) {
      res.status(400).json({ message: 'Bu kategori adı zaten kullanılıyor' });
    } else {
      res.status(500).json({ message: 'Kategori güncellenirken hata oluştu', error: error.message });
    }
  }
});

// Delete category (admin only)
router.delete('/:id', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ message: 'Kategori bulunamadı' });
    }
    
    // Check if category is being used by tests or questions
    const Test = require('../models/Test');
    const Question = require('../models/Question');
    
    const testCount = await Test.countDocuments({ category: category.name });
    const questionCount = await Question.countDocuments({ category: category.name });
    
    if (testCount > 0 || questionCount > 0) {
      return res.status(400).json({ 
        message: 'Bu kategori testlerde veya sorularda kullanılıyor. Önce bunları güncelleyin.',
        testCount,
        questionCount
      });
    }
    
    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Kategori silindi' });
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ message: 'Kategori silinirken hata oluştu' });
  }
});

// Toggle category status (admin only)
router.patch('/:id/toggle', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ message: 'Kategori bulunamadı' });
    }
    
    category.isActive = !category.isActive;
    await category.save();
    
    res.json({ message: 'Kategori durumu güncellendi', category });
  } catch (error) {
    console.error('Error toggling category:', error);
    res.status(500).json({ message: 'Kategori durumu güncellenirken hata oluştu' });
  }
});

// Get category statistics
router.get('/stats/usage', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const Test = require('../models/Test');
    const Question = require('../models/Question');
    
    const categories = await Category.find({ isActive: true });
    const stats = [];
    
    for (const category of categories) {
      const testCount = await Test.countDocuments({ category: category.name });
      const questionCount = await Question.countDocuments({ category: category.name });
      
      stats.push({
        category: category.name,
        testCount,
        questionCount,
        totalUsage: testCount + questionCount
      });
    }
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching category stats:', error);
    res.status(500).json({ message: 'Kategori istatistikleri yüklenirken hata oluştu' });
  }
});

module.exports = router; 