const express = require('express');
const router = express.Router();
const SubscriptionPlan = require('../models/SubscriptionPlan');
const adminAuth = require('../middleware/adminAuth');
const auth = require('../middleware/auth');

// Get all subscription plans (admin only)
router.get('/', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, isActive, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
    
    const query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (isActive !== undefined && isActive !== 'all') {
      query.isActive = isActive === 'true';
    }
    
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;
    
    // Test: Get all plans without any filters
    const allPlans = await SubscriptionPlan.find({});
    console.log('All plans in DB:', allPlans.length);
    
    const plans = await SubscriptionPlan.find(query)
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await SubscriptionPlan.countDocuments(query);
    
    console.log('Query:', query);
    console.log('Found plans with query:', plans.length);
    console.log('Total with query:', total);
    
    res.json({
      plans,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching subscription plans:', error);
    res.status(500).json({ message: 'Abonelik planları getirilirken hata oluştu' });
  }
});

// Get subscription plans for mobile app (public)
router.get('/public', async (req, res) => {
  try {
    const { score, platform } = req.query;
    
    let query = { isActive: true };
    
    // If score is provided, filter by score range
    if (score) {
      const scoreNum = parseInt(score);
      query.minScore = { $lte: scoreNum };
      query.maxScore = { $gte: scoreNum };
    }
    
    const plans = await SubscriptionPlan.find(query)
      .sort({ sortOrder: 1, price: 1 })
      .select('-totalPurchases -totalRevenue'); // Don't send analytics data to mobile
    
    // Add platform-specific product ID
    const plansWithProductId = plans.map(plan => {
      const planObj = plan.toObject();
      planObj.productId = platform === 'ios' ? plan.iosProductId : plan.androidProductId;
      return planObj;
    });
    
    res.json(plansWithProductId);
  } catch (error) {
    console.error('Error fetching public subscription plans:', error);
    res.status(500).json({ message: 'Abonelik planları getirilirken hata oluştu' });
  }
});

// Get popular subscription plans
router.get('/popular', async (req, res) => {
  try {
    const plans = await SubscriptionPlan.getPopularPlans()
      .select('-totalPurchases -totalRevenue');
    
    res.json(plans);
  } catch (error) {
    console.error('Error fetching popular subscription plans:', error);
    res.status(500).json({ message: 'Popüler abonelik planları getirilirken hata oluştu' });
  }
});

// Get subscription plan by ID (admin only)
router.get('/:id', adminAuth, async (req, res) => {
  try {
    const plan = await SubscriptionPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({ message: 'Abonelik planı bulunamadı' });
    }
    
    res.json(plan);
  } catch (error) {
    console.error('Error fetching subscription plan:', error);
    res.status(500).json({ message: 'Abonelik planı getirilirken hata oluştu' });
  }
});

// Create new subscription plan (admin only)
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      name,
      description,
      price,
      currency,
      duration,
      durationType,
      features,
      isActive,
      isPopular,
      sortOrder,
      iosProductId,
      androidProductId,
      minScore,
      maxScore,
      color,
      icon
    } = req.body;
    
    // Check if product IDs already exist
    const existingPlan = await SubscriptionPlan.findOne({
      $or: [
        { iosProductId },
        { androidProductId }
      ]
    });
    
    if (existingPlan) {
      return res.status(400).json({ 
        message: 'Bu iOS veya Android ürün ID\'si zaten kullanılıyor' 
      });
    }
    
    const plan = new SubscriptionPlan({
      name,
      description,
      price,
      currency,
      duration,
      durationType,
      features,
      isActive,
      isPopular,
      sortOrder,
      iosProductId,
      androidProductId,
      minScore,
      maxScore,
      color,
      icon
    });
    
    await plan.save();
    
    res.status(201).json({
      message: 'Abonelik planı başarıyla oluşturuldu',
      plan
    });
  } catch (error) {
    console.error('Error creating subscription plan:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Geçersiz veri formatı',
        errors: Object.values(error.errors).map(err => err.message)
      });
    }
    
    res.status(500).json({ message: 'Abonelik planı oluşturulurken hata oluştu' });
  }
});

// Update subscription plan (admin only)
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const {
      name,
      description,
      price,
      currency,
      duration,
      durationType,
      features,
      isActive,
      isPopular,
      sortOrder,
      iosProductId,
      androidProductId,
      minScore,
      maxScore,
      color,
      icon
    } = req.body;
    
    const plan = await SubscriptionPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({ message: 'Abonelik planı bulunamadı' });
    }
    
    // Check if product IDs already exist (excluding current plan)
    const existingPlan = await SubscriptionPlan.findOne({
      _id: { $ne: req.params.id },
      $or: [
        { iosProductId },
        { androidProductId }
      ]
    });
    
    if (existingPlan) {
      return res.status(400).json({ 
        message: 'Bu iOS veya Android ürün ID\'si zaten kullanılıyor' 
      });
    }
    
    // Update fields
    plan.name = name || plan.name;
    plan.description = description || plan.description;
    plan.price = price !== undefined ? price : plan.price;
    plan.currency = currency || plan.currency;
    plan.duration = duration || plan.duration;
    plan.durationType = durationType || plan.durationType;
    plan.features = features || plan.features;
    plan.isActive = isActive !== undefined ? isActive : plan.isActive;
    plan.isPopular = isPopular !== undefined ? isPopular : plan.isPopular;
    plan.sortOrder = sortOrder !== undefined ? sortOrder : plan.sortOrder;
    plan.iosProductId = iosProductId || plan.iosProductId;
    plan.androidProductId = androidProductId || plan.androidProductId;
    plan.minScore = minScore !== undefined ? minScore : plan.minScore;
    plan.maxScore = maxScore !== undefined ? maxScore : plan.maxScore;
    plan.color = color || plan.color;
    plan.icon = icon || plan.icon;
    
    await plan.save();
    
    res.json({
      message: 'Abonelik planı başarıyla güncellendi',
      plan
    });
  } catch (error) {
    console.error('Error updating subscription plan:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Geçersiz veri formatı',
        errors: Object.values(error.errors).map(err => err.message)
      });
    }
    
    res.status(500).json({ message: 'Abonelik planı güncellenirken hata oluştu' });
  }
});

// Delete subscription plan (admin only)
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const plan = await SubscriptionPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({ message: 'Abonelik planı bulunamadı' });
    }
    
    await SubscriptionPlan.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Abonelik planı başarıyla silindi' });
  } catch (error) {
    console.error('Error deleting subscription plan:', error);
    res.status(500).json({ message: 'Abonelik planı silinirken hata oluştu' });
  }
});

// Toggle plan active status (admin only)
router.patch('/:id/toggle', adminAuth, async (req, res) => {
  try {
    const plan = await SubscriptionPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({ message: 'Abonelik planı bulunamadı' });
    }
    
    plan.isActive = !plan.isActive;
    await plan.save();
    
    res.json({
      message: `Abonelik planı ${plan.isActive ? 'aktif' : 'pasif'} hale getirildi`,
      plan
    });
  } catch (error) {
    console.error('Error toggling subscription plan:', error);
    res.status(500).json({ message: 'Abonelik planı durumu değiştirilirken hata oluştu' });
  }
});

// Get subscription plan analytics (admin only)
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const totalPlans = await SubscriptionPlan.countDocuments();
    const activePlans = await SubscriptionPlan.countDocuments({ isActive: true });
    const popularPlans = await SubscriptionPlan.countDocuments({ isPopular: true });
    
    const totalRevenue = await SubscriptionPlan.aggregate([
      { $group: { _id: null, total: { $sum: '$totalRevenue' } } }
    ]);
    
    const totalPurchases = await SubscriptionPlan.aggregate([
      { $group: { _id: null, total: { $sum: '$totalPurchases' } } }
    ]);
    
    const plansByPrice = await SubscriptionPlan.aggregate([
      { $group: { _id: '$currency', plans: { $sum: 1 }, avgPrice: { $avg: '$price' } } }
    ]);
    
    res.json({
      totalPlans,
      activePlans,
      popularPlans,
      totalRevenue: totalRevenue[0]?.total || 0,
      totalPurchases: totalPurchases[0]?.total || 0,
      plansByPrice
    });
  } catch (error) {
    console.error('Error fetching subscription plan analytics:', error);
    res.status(500).json({ message: 'Analitik veriler getirilirken hata oluştu' });
  }
});

// Update plan purchase count and revenue (for in-app purchase tracking)
router.patch('/:id/purchase', auth, async (req, res) => {
  try {
    const { amount } = req.body;
    
    const plan = await SubscriptionPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json({ message: 'Abonelik planı bulunamadı' });
    }
    
    plan.totalPurchases += 1;
    plan.totalRevenue += amount || plan.price;
    
    await plan.save();
    
    res.json({
      message: 'Satın alma kaydedildi',
      plan
    });
  } catch (error) {
    console.error('Error updating plan purchase:', error);
    res.status(500).json({ message: 'Satın alma kaydedilirken hata oluştu' });
  }
});

module.exports = router; 