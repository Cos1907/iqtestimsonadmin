const express = require('express');
const router = express.Router();
const Notification = require('../models/Notification');
const User = require('../models/User');
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');

// Get user notifications for mobile app
router.get('/user', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, unreadOnly = false } = req.query;
    
    const query = {
      $or: [
        { recipients: 'all' },
        { userIds: req.user.id },
        { recipients: 'category', category: req.user.preferences?.category }
      ],
      // Exclude notifications deleted by this user
      deletedBy: { $ne: req.user.id }
    };
    
    if (unreadOnly === 'true') {
      query.isRead = false;
    }
    
    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Notification.countDocuments(query);
    
    res.json({
      notifications,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching user notifications:', error);
    res.status(500).json({ message: 'Bildirimler yüklenirken hata oluştu' });
  }
});

// Mark notification as read
router.put('/:id/read', auth, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Bildirim bulunamadı' });
    }
    
    // Check if user has access to this notification
    const hasAccess = notification.recipients === 'all' || 
                     notification.userIds.includes(req.user.id) ||
                     (notification.recipients === 'category' && notification.category === req.user.preferences?.category);
    
    if (!hasAccess) {
      return res.status(403).json({ message: 'Bu bildirime erişim izniniz yok' });
    }
    
    // Add user to readBy if not already there
    const alreadyRead = notification.readBy.some(read => read.user.toString() === req.user.id);
    
    if (!alreadyRead) {
      notification.readBy.push({
        user: req.user.id,
        readAt: new Date()
      });
      await notification.save();
    }
    
    res.json({ message: 'Bildirim okundu olarak işaretlendi' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ message: 'İşlem sırasında hata oluştu' });
  }
});

// Mark all notifications as read
router.put('/mark-all-read', auth, async (req, res) => {
  try {
    const query = {
      $or: [
        { recipients: 'all' },
        { userIds: req.user.id },
        { recipients: 'category', category: req.user.preferences?.category }
      ],
      'readBy.user': { $ne: req.user.id }
    };
    
    const notifications = await Notification.find(query);
    
    for (const notification of notifications) {
      notification.readBy.push({
        user: req.user.id,
        readAt: new Date()
      });
      await notification.save();
    }
    
    res.json({ message: 'Tüm bildirimler okundu olarak işaretlendi' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ message: 'İşlem sırasında hata oluştu' });
  }
});

// Get user notification stats
router.get('/user/stats', auth, async (req, res) => {
  try {
    const query = {
      $or: [
        { recipients: 'all' },
        { userIds: req.user.id },
        { recipients: 'category', category: req.user.preferences?.category }
      ],
      // Exclude notifications deleted by this user
      deletedBy: { $ne: req.user.id }
    };
    
    const totalNotifications = await Notification.countDocuments(query);
    const unreadNotifications = await Notification.countDocuments({
      ...query,
      'readBy.user': { $ne: req.user.id }
    });
    
    const readNotifications = totalNotifications - unreadNotifications;
    
    // Get recent notifications
    const recentNotifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .limit(5)
      .exec();
    
    res.json({
      totalNotifications,
      unreadCount: unreadNotifications,
      readCount: readNotifications,
      recentNotifications
    });
  } catch (error) {
    console.error('Error fetching user notification stats:', error);
    res.status(500).json({ message: 'İstatistikler yüklenirken hata oluştu' });
  }
});

// Delete user notification
router.delete('/:id', auth, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Bildirim bulunamadı' });
    }
    
    // Check if user has access to this notification
    const hasAccess = notification.recipients === 'all' || 
                     notification.userIds.includes(req.user.id) ||
                     (notification.recipients === 'category' && notification.category === req.user.preferences?.category);
    
    if (!hasAccess) {
      return res.status(403).json({ message: 'Bu bildirime erişim izniniz yok' });
    }
    
    // For user deletion, we'll mark it as deleted for this user instead of actually deleting
    // Add user to deletedBy array
    if (!notification.deletedBy) {
      notification.deletedBy = [];
    }
    
    if (!notification.deletedBy.includes(req.user.id)) {
      notification.deletedBy.push(req.user.id);
      await notification.save();
    }
    
    res.json({ message: 'Bildirim başarıyla silindi' });
  } catch (error) {
    console.error('Error deleting user notification:', error);
    res.status(500).json({ message: 'Bildirim silinirken hata oluştu' });
  }
});

// Admin: Get all notifications
router.get('/', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status } = req.query;
    
    const query = {};
    
    if (type) {
      query.type = type;
    }
    
    if (status) {
      query.isSent = status === 'sent';
    }
    
    const notifications = await Notification.find(query)
      .populate('userIds', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await Notification.countDocuments(query);
    
    res.json({
      notifications,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Bildirimler yüklenirken hata oluştu' });
  }
});

// Admin: Create notification
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      title,
      message,
      type,
      recipients,
      userIds,
      category,
      scheduledFor,
      actionUrl,
      actionText,
      priority,
      expiresAt
    } = req.body;
    
    const notification = new Notification({
      title,
      message,
      type,
      recipients,
      userIds,
      category,
      scheduledFor,
      actionUrl,
      actionText,
      priority,
      expiresAt
    });
    
    await notification.save();
    
    // If scheduledFor is not set, send immediately
    if (!scheduledFor) {
      await sendNotification(notification);
    }
    
    const populatedNotification = await Notification.findById(notification._id)
      .populate('userIds', 'name email');
    
    res.status(201).json(populatedNotification);
  } catch (error) {
    res.status(500).json({ message: 'Bildirim oluşturulurken hata oluştu' });
  }
});

// Admin: Update notification
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const {
      title,
      message,
      type,
      recipients,
      userIds,
      category,
      scheduledFor,
      actionUrl,
      actionText,
      priority,
      expiresAt
    } = req.body;
    
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Bildirim bulunamadı' });
    }
    
    notification.title = title || notification.title;
    notification.message = message || notification.message;
    notification.type = type || notification.type;
    notification.recipients = recipients || notification.recipients;
    notification.userIds = userIds || notification.userIds;
    notification.category = category || notification.category;
    notification.scheduledFor = scheduledFor || notification.scheduledFor;
    notification.actionUrl = actionUrl || notification.actionUrl;
    notification.actionText = actionText || notification.actionText;
    notification.priority = priority || notification.priority;
    notification.expiresAt = expiresAt || notification.expiresAt;
    
    await notification.save();
    
    const updatedNotification = await Notification.findById(notification._id)
      .populate('userIds', 'name email');
    
    res.json(updatedNotification);
  } catch (error) {
    res.status(500).json({ message: 'Bildirim güncellenirken hata oluştu' });
  }
});

// Admin: Delete notification
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Bildirim bulunamadı' });
    }
    
    await Notification.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Bildirim başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Bildirim silinirken hata oluştu' });
  }
});

// Admin: Send notification immediately
router.post('/:id/send', adminAuth, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    
    if (!notification) {
      return res.status(404).json({ message: 'Bildirim bulunamadı' });
    }
    
    if (notification.isSent) {
      return res.status(400).json({ message: 'Bildirim zaten gönderilmiş' });
    }
    
    await sendNotification(notification);
    
    res.json({ message: 'Bildirim başarıyla gönderildi' });
  } catch (error) {
    res.status(500).json({ message: 'Bildirim gönderilirken hata oluştu' });
  }
});

// Admin: Get notification statistics
router.get('/stats/overview', adminAuth, async (req, res) => {
  try {
    const totalNotifications = await Notification.countDocuments();
    const sentNotifications = await Notification.countDocuments({ isSent: true });
    const pendingNotifications = await Notification.countDocuments({ isSent: false });
    const scheduledNotifications = await Notification.countDocuments({ 
      scheduledFor: { $exists: true, $ne: null },
      isSent: false 
    });
    
    const typeStats = await Notification.aggregate([
      { $group: { _id: '$type', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const priorityStats = await Notification.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const recentActivity = await Notification.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userIds', 'name email');
    
    res.json({
      totalNotifications,
      sentNotifications,
      pendingNotifications,
      scheduledNotifications,
      typeStats,
      priorityStats,
      recentActivity
    });
  } catch (error) {
    res.status(500).json({ message: 'İstatistikler yüklenirken hata oluştu' });
  }
});

// Register push token for mobile app
router.post('/register-token', auth, async (req, res) => {
  try {
    const { expoPushToken, platform } = req.body;
    
    if (!expoPushToken) {
      return res.status(400).json({ message: 'Expo push token gerekli' });
    }
    
    // Update user with push token
    await User.findByIdAndUpdate(req.user.id, {
      expoPushToken,
      platform,
      lastTokenUpdate: new Date()
    });
    
    res.json({ message: 'Push token başarıyla kaydedildi' });
  } catch (error) {
    console.error('Error registering push token:', error);
    res.status(500).json({ message: 'Token kaydedilirken hata oluştu' });
  }
});

// Helper function to send notification
async function sendNotification(notification) {
  try {
    let targetUsers = [];
    
    if (notification.recipients === 'all') {
      targetUsers = await User.find({ role: 'user' });
    } else if (notification.recipients === 'specific') {
      targetUsers = await User.find({ _id: { $in: notification.userIds } });
    } else if (notification.recipients === 'category') {
      targetUsers = await User.find({ 
        role: 'user',
        'preferences.category': notification.category 
      });
    }
    
    // Filter users with valid push tokens
    const usersWithTokens = targetUsers.filter(user => 
      user.expoPushToken && 
      user.notificationPreferences?.enabled !== false
    );
    
    if (usersWithTokens.length > 0) {
      // Send push notifications via Expo
      await sendExpoPushNotifications(notification, usersWithTokens);
    }
    
    // Mark notification as sent
    notification.isSent = true;
    notification.sentAt = new Date();
    await notification.save();
    
    // Log the notification sending
    console.log(`Notification "${notification.title}" sent to ${usersWithTokens.length} users`);
    
  } catch (error) {
    console.error('Error sending notification:', error);
    throw error;
  }
}

// Send push notifications via Expo
async function sendExpoPushNotifications(notification, users) {
  try {
    const messages = users.map(user => ({
      to: user.expoPushToken,
      sound: 'default',
      title: notification.title,
      body: notification.message,
      data: {
        notificationId: notification._id,
        type: notification.type,
        actionUrl: notification.actionUrl,
        actionText: notification.actionText,
      },
      priority: notification.priority === 'urgent' ? 'high' : 'default',
    }));

    // Send in batches of 100 (Expo limit)
    const batchSize = 100;
    for (let i = 0; i < messages.length; i += batchSize) {
      const batch = messages.slice(i, i + batchSize);
      
      const response = await fetch('https://exp.host/--/api/v2/push/send', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Accept-encoding': 'gzip, deflate',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(batch),
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error('Expo push notification error:', errorData);
        throw new Error(`Expo API error: ${response.status}`);
      }

      const result = await response.json();
      console.log(`Batch ${Math.floor(i / batchSize) + 1} sent:`, result);
    }
  } catch (error) {
    console.error('Error sending Expo push notifications:', error);
    throw error;
  }
}

module.exports = router; 