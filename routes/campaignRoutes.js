const express = require('express');
const router = express.Router();
const Campaign = require('../models/Campaign');
const adminAuth = require('../middleware/adminAuth');
const { v4: uuidv4 } = require('uuid');

// Get all campaigns with filtering and pagination
router.get('/', adminAuth, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      status = 'all',
      type = 'all',
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const query = {};

    // Search filter
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { trackingCode: { $regex: search, $options: 'i' } }
      ];
    }

    // Status filter
    if (status !== 'all') {
      query.status = status;
    }

    // Type filter
    if (type !== 'all') {
      query.type = type;
    }

    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const campaigns = await Campaign.find(query)
      .populate('createdBy', 'name email')
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();

    const total = await Campaign.countDocuments(query);

    res.json({
      campaigns,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching campaigns:', error);
    res.status(500).json({ message: 'Kampanyalar getirilirken hata oluştu' });
  }
});

// Get campaign by ID
router.get('/:id', adminAuth, async (req, res) => {
  try {
    const campaign = await Campaign.findById(req.params.id)
      .populate('createdBy', 'name email');
    
    if (!campaign) {
      return res.status(404).json({ message: 'Kampanya bulunamadı' });
    }

    res.json(campaign);
  } catch (error) {
    console.error('Error fetching campaign:', error);
    res.status(500).json({ message: 'Kampanya getirilirken hata oluştu' });
  }
});

// Create new campaign
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      name,
      description,
      type,
      status,
      startDate,
      endDate,
      budget,
      targetAudience,
      conversionGoals,
      customGoal,
      commission,
      commissionType,
      creativeAssets
    } = req.body;

    // Generate unique tracking code
    const trackingCode = `CAMP_${uuidv4().substring(0, 8).toUpperCase()}`;

    const campaign = new Campaign({
      name,
      description,
      type,
      status,
      startDate,
      endDate,
      budget,
      targetAudience,
      trackingCode,
      conversionGoals,
      customGoal,
      commission,
      commissionType,
      creativeAssets,
      createdBy: req.user.id
    });

    await campaign.save();
    res.status(201).json(campaign);
  } catch (error) {
    console.error('Error creating campaign:', error);
    res.status(500).json({ message: 'Kampanya oluşturulurken hata oluştu' });
  }
});

// Update campaign
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const campaign = await Campaign.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!campaign) {
      return res.status(404).json({ message: 'Kampanya bulunamadı' });
    }

    res.json(campaign);
  } catch (error) {
    console.error('Error updating campaign:', error);
    res.status(500).json({ message: 'Kampanya güncellenirken hata oluştu' });
  }
});

// Delete campaign
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const campaign = await Campaign.findByIdAndDelete(req.params.id);
    
    if (!campaign) {
      return res.status(404).json({ message: 'Kampanya bulunamadı' });
    }

    res.json({ message: 'Kampanya başarıyla silindi' });
  } catch (error) {
    console.error('Error deleting campaign:', error);
    res.status(500).json({ message: 'Kampanya silinirken hata oluştu' });
  }
});

// Get campaign analytics
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const totalCampaigns = await Campaign.countDocuments();
    const activeCampaigns = await Campaign.countDocuments({ status: 'active' });
    const totalBudget = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$budget.amount' } } }
    ]);
    const totalSpent = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$budget.spent' } } }
    ]);

    const totalImpressions = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$trackingMetrics.impressions' } } }
    ]);

    const totalClicks = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$trackingMetrics.clicks' } } }
    ]);

    const totalConversions = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$trackingMetrics.conversions' } } }
    ]);

    const totalRevenue = await Campaign.aggregate([
      { $group: { _id: null, total: { $sum: '$trackingMetrics.revenue' } } }
    ]);

    res.json({
      totalCampaigns,
      activeCampaigns,
      totalBudget: totalBudget[0]?.total || 0,
      totalSpent: totalSpent[0]?.total || 0,
      totalImpressions: totalImpressions[0]?.total || 0,
      totalClicks: totalClicks[0]?.total || 0,
      totalConversions: totalConversions[0]?.total || 0,
      totalRevenue: totalRevenue[0]?.total || 0
    });
  } catch (error) {
    console.error('Error fetching campaign analytics:', error);
    res.status(500).json({ message: 'Analitik veriler getirilirken hata oluştu' });
  }
});

// Track campaign event
router.post('/track/:trackingCode', async (req, res) => {
  try {
    const { trackingCode } = req.params;
    const { event, value = 0, userId } = req.body;

    const campaign = await Campaign.findOne({ trackingCode });
    
    if (!campaign) {
      return res.status(404).json({ message: 'Kampanya bulunamadı' });
    }

    // Update tracking metrics based on event
    switch (event) {
      case 'impression':
        campaign.trackingMetrics.impressions += 1;
        break;
      case 'click':
        campaign.trackingMetrics.clicks += 1;
        break;
      case 'conversion':
        campaign.trackingMetrics.conversions += 1;
        campaign.trackingMetrics.revenue += value;
        break;
    }

    await campaign.save();
    res.json({ message: 'Event tracked successfully' });
  } catch (error) {
    console.error('Error tracking campaign event:', error);
    res.status(500).json({ message: 'Event takip edilirken hata oluştu' });
  }
});

module.exports = router; 