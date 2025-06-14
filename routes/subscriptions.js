const express = require('express');
const router = express.Router();
const Subscription = require('../models/Subscription');
const User = require('../models/User');
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');

// Get user's subscription
router.get('/user', auth, async (req, res) => {
  try {
    const subscription = await Subscription.findOne({ user: req.user.id })
      .sort({ createdAt: -1 });
    
    res.json(subscription);
  } catch (error) {
    res.status(500).json({ message: 'Abonelik bilgileri yüklenirken hata oluştu' });
  }
});

// Get subscription history
router.get('/user/history', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    
    const subscriptions = await Subscription.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Subscription.countDocuments({ user: req.user.id });
    
    res.json({
      subscriptions,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Abonelik geçmişi yüklenirken hata oluştu' });
  }
});

// Create subscription (for payment processing)
router.post('/user', auth, async (req, res) => {
  try {
    const {
      plan,
      planDetails,
      paymentMethod,
      amount,
      currency,
      discount,
      tax,
      totalAmount,
      billingAddress,
      isTrial,
      trialEndDate
    } = req.body;
    
    // Check if user already has an active subscription
    const existingSubscription = await Subscription.findOne({
      user: req.user.id,
      status: 'active'
    });
    
    if (existingSubscription) {
      return res.status(400).json({ message: 'Zaten aktif bir aboneliğiniz bulunmaktadır' });
    }
    
    const startDate = new Date();
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + planDetails.duration);
    
    const subscription = new Subscription({
      user: req.user.id,
      plan,
      planDetails,
      startDate,
      endDate,
      paymentMethod,
      amount,
      currency,
      discount,
      tax,
      totalAmount,
      billingAddress,
      isTrial,
      trialEndDate
    });
    
    await subscription.save();
    
    // Update user's subscription status
    await User.findByIdAndUpdate(req.user.id, {
      subscription: subscription._id,
      subscriptionStatus: 'active'
    });
    
    const populatedSubscription = await Subscription.findById(subscription._id)
      .populate('user', 'name email');
    
    res.status(201).json(populatedSubscription);
  } catch (error) {
    res.status(500).json({ message: 'Abonelik oluşturulurken hata oluştu' });
  }
});

// Cancel subscription
router.patch('/user/cancel', auth, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const subscription = await Subscription.findOne({
      user: req.user.id,
      status: 'active'
    });
    
    if (!subscription) {
      return res.status(404).json({ message: 'Aktif abonelik bulunamadı' });
    }
    
    subscription.status = 'cancelled';
    subscription.cancellationReason = reason;
    subscription.cancelledAt = new Date();
    subscription.autoRenew = false;
    
    await subscription.save();
    
    // Update user's subscription status
    await User.findByIdAndUpdate(req.user.id, {
      subscriptionStatus: 'cancelled'
    });
    
    res.json({ message: 'Abonelik başarıyla iptal edildi' });
  } catch (error) {
    res.status(500).json({ message: 'Abonelik iptal edilirken hata oluştu' });
  }
});

// Reactivate subscription
router.patch('/user/reactivate', auth, async (req, res) => {
  try {
    const subscription = await Subscription.findOne({
      user: req.user.id,
      status: 'cancelled'
    });
    
    if (!subscription) {
      return res.status(404).json({ message: 'İptal edilmiş abonelik bulunamadı' });
    }
    
    subscription.status = 'active';
    subscription.reactivatedAt = new Date();
    subscription.autoRenew = true;
    
    await subscription.save();
    
    // Update user's subscription status
    await User.findByIdAndUpdate(req.user.id, {
      subscriptionStatus: 'active'
    });
    
    res.json({ message: 'Abonelik başarıyla yeniden aktifleştirildi' });
  } catch (error) {
    res.status(500).json({ message: 'Abonelik yeniden aktifleştirilirken hata oluştu' });
  }
});

// Admin: Get all subscriptions
router.get('/', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, plan, dateFrom, dateTo } = req.query;
    
    const query = {};
    
    if (status) {
      query.status = status;
    }
    
    if (plan) {
      query.plan = plan;
    }
    
    if (dateFrom || dateTo) {
      query.createdAt = {};
      if (dateFrom) {
        query.createdAt.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        query.createdAt.$lte = new Date(dateTo);
      }
    }
    
    const subscriptions = await Subscription.find(query)
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Subscription.countDocuments(query);
    
    res.json({
      subscriptions,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Abonelikler yüklenirken hata oluştu' });
  }
});

// Admin: Get subscription details
router.get('/:id', adminAuth, async (req, res) => {
  try {
    const subscription = await Subscription.findById(req.params.id)
      .populate('user', 'name email');
    
    if (!subscription) {
      return res.status(404).json({ message: 'Abonelik bulunamadı' });
    }
    
    res.json(subscription);
  } catch (error) {
    res.status(500).json({ message: 'Abonelik detayları yüklenirken hata oluştu' });
  }
});

// Admin: Update subscription
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const {
      status,
      endDate,
      autoRenew,
      notes
    } = req.body;
    
    const subscription = await Subscription.findById(req.params.id);
    
    if (!subscription) {
      return res.status(404).json({ message: 'Abonelik bulunamadı' });
    }
    
    if (status) {
      subscription.status = status;
    }
    
    if (endDate) {
      subscription.endDate = new Date(endDate);
    }
    
    if (autoRenew !== undefined) {
      subscription.autoRenew = autoRenew;
    }
    
    if (notes) {
      subscription.notes = notes;
    }
    
    await subscription.save();
    
    // Update user's subscription status
    await User.findByIdAndUpdate(subscription.user, {
      subscriptionStatus: status
    });
    
    const updatedSubscription = await Subscription.findById(subscription._id)
      .populate('user', 'name email');
    
    res.json(updatedSubscription);
  } catch (error) {
    res.status(500).json({ message: 'Abonelik güncellenirken hata oluştu' });
  }
});

// Admin: Delete subscription
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const subscription = await Subscription.findById(req.params.id);
    
    if (!subscription) {
      return res.status(404).json({ message: 'Abonelik bulunamadı' });
    }
    
    await Subscription.findByIdAndDelete(req.params.id);
    
    // Update user's subscription status
    await User.findByIdAndUpdate(subscription.user, {
      subscription: null,
      subscriptionStatus: 'none'
    });
    
    res.json({ message: 'Abonelik başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Abonelik silinirken hata oluştu' });
  }
});

// Admin: Get subscription analytics
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const { dateFrom, dateTo } = req.query;
    
    const query = {};
    
    if (dateFrom || dateTo) {
      query.createdAt = {};
      if (dateFrom) {
        query.createdAt.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        query.createdAt.$lte = new Date(dateTo);
      }
    }
    
    const totalSubscriptions = await Subscription.countDocuments(query);
    const activeSubscriptions = await Subscription.countDocuments({ ...query, status: 'active' });
    const cancelledSubscriptions = await Subscription.countDocuments({ ...query, status: 'cancelled' });
    const expiredSubscriptions = await Subscription.countDocuments({ ...query, status: 'expired' });
    
    const planStats = await Subscription.aggregate([
      { $match: query },
      { $group: { _id: '$plan', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const revenueStats = await Subscription.aggregate([
      { $match: { ...query, paymentStatus: 'completed' } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$totalAmount' },
          avgRevenue: { $avg: '$totalAmount' },
          totalSubscriptions: { $sum: 1 }
        }
      }
    ]);
    
    const monthlyRevenue = await Subscription.aggregate([
      { $match: { ...query, paymentStatus: 'completed' } },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          revenue: { $sum: '$totalAmount' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': -1, '_id.month': -1 } },
      { $limit: 12 }
    ]);
    
    const recentSubscriptions = await Subscription.find(query)
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.json({
      totalSubscriptions,
      activeSubscriptions,
      cancelledSubscriptions,
      expiredSubscriptions,
      planStats,
      revenueStats: revenueStats[0] || { totalRevenue: 0, avgRevenue: 0, totalSubscriptions: 0 },
      monthlyRevenue,
      recentSubscriptions
    });
  } catch (error) {
    res.status(500).json({ message: 'Analitik veriler yüklenirken hata oluştu' });
  }
});

// Admin: Get subscription plans
router.get('/plans/available', adminAuth, async (req, res) => {
  try {
    const plans = [
      {
        id: 'free',
        name: 'Ücretsiz',
        price: 0,
        currency: 'TRY',
        duration: 30,
        features: [
          'Günlük 3 test',
          'Temel raporlar',
          'E-posta desteği'
        ],
        maxTests: 3,
        maxQuestions: 0,
        prioritySupport: false,
        customBranding: false,
        analytics: false
      },
      {
        id: 'basic',
        name: 'Temel',
        price: 29.99,
        currency: 'TRY',
        duration: 30,
        features: [
          'Sınırsız test',
          'Detaylı raporlar',
          'Öncelikli destek',
          'Temel analitikler'
        ],
        maxTests: -1,
        maxQuestions: 100,
        prioritySupport: true,
        customBranding: false,
        analytics: true
      },
      {
        id: 'premium',
        name: 'Premium',
        price: 59.99,
        currency: 'TRY',
        duration: 30,
        features: [
          'Sınırsız test ve soru',
          'Gelişmiş analitikler',
          'Özel markalama',
          'API erişimi',
          'Öncelikli destek'
        ],
        maxTests: -1,
        maxQuestions: -1,
        prioritySupport: true,
        customBranding: true,
        analytics: true
      },
      {
        id: 'enterprise',
        name: 'Kurumsal',
        price: 199.99,
        currency: 'TRY',
        duration: 30,
        features: [
          'Tüm özellikler',
          'Özel entegrasyonlar',
          'Dedicated destek',
          'Özel eğitim',
          'SLA garantisi'
        ],
        maxTests: -1,
        maxQuestions: -1,
        prioritySupport: true,
        customBranding: true,
        analytics: true
      }
    ];
    
    res.json(plans);
  } catch (error) {
    res.status(500).json({ message: 'Planlar yüklenirken hata oluştu' });
  }
});

module.exports = router; 