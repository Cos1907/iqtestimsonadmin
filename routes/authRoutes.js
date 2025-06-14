const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe, sendVerificationEmail, verifyEmail, updateProfile, createAdminUser } = require('../controllers/authController');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');
const { trackAdminActivity } = require('../utils/adminActivityTracker');

// Public routes
router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/verify-email/:token', verifyEmail);
router.post('/create-admin', createAdminUser);
router.get('/create-admin', createAdminUser);

// Protected routes
router.get('/me', protect, getMe);
router.put('/update-profile', protect, updateProfile);
router.post('/send-verification-email', protect, sendVerificationEmail);

// Admin routes
router.get('/users', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const User = require('../models/User');
    const users = await User.find({}).select('-password');
    
    // Track activity
    await trackAdminActivity(req, {
      action: 'analytics_view',
      module: 'users',
      description: 'Kullanıcı listesi görüntülendi',
      affectedRecords: users.length
    });
    
    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

router.put('/users/:id', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const User = require('../models/User');
    const { name, email, role, age, gender } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (name) user.name = name;
    if (email) user.email = email;
    if (role) user.role = role;
    if (age !== undefined) user.age = age;
    if (gender !== undefined) user.gender = gender;

    await user.save();
    
    // Track activity
    await trackAdminActivity(req, {
      action: 'update',
      module: 'users',
      description: `Kullanıcı güncellendi: ${user.email}`,
      details: { userId: user._id, changes: req.body }
    });
    
    res.json({ message: 'User updated successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

router.delete('/users/:id', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const User = require('../models/User');
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await User.findByIdAndDelete(req.params.id);
    
    // Track activity
    await trackAdminActivity(req, {
      action: 'delete',
      module: 'users',
      description: `Kullanıcı silindi: ${user.email}`,
      details: { userId: user._id, userEmail: user.email }
    });
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router; 