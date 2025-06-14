const User = require('../models/User');
const AdminActivity = require('../models/AdminActivity');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { setupLogger } = require('../utils/logger');

const logger = setupLogger();

// Generate JWT
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};

// Generate verification token
const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    res.status(400).json({ message: 'Please add all fields' });
    return;
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400).json({ message: 'User already exists' });
    return;
  }

  try {
    // Create user with email verification token
    const verificationToken = generateVerificationToken();
    const user = await User.create({
      name,
      email,
      password,
      emailVerified: false,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    });

    if (user) {
      logger.info(`User registered: ${user.email}`);
      
      // Email doğrulaması kaldırıldı - otomatik doğrulama
      user.emailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();
      
      res.status(201).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        token: generateToken(user._id, user.role),
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    logger.error(`Error during user registration for email ${email}:`, error);
    res.status(500).json({ message: 'Server error during registration' });
  }
};

// @desc    Authenticate a user
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: 'Please enter email and password' });
    return;
  }

  // Check for user email
  const user = await User.findOne({ email });

  if (!user) {
    logger.info(`Login attempt failed: User not found for email ${email}`);
    res.status(400).json({ message: 'Invalid credentials' });
    return;
  }

  try {
    // Debug logging
    logger.info(`Login attempt for user: ${user.email}, role: ${user.role}`);
    
    // Compare password
    const isPasswordMatch = await user.matchPassword(password);
    logger.info(`Password match result: ${isPasswordMatch}`);
    
    if (isPasswordMatch) {
      logger.info(`User logged in: ${user.email}`);
      
      // Track admin login activity
      if (user.role === 'admin' || user.role === 'super_admin') {
        try {
          const activity = new AdminActivity({
            adminId: user._id,
            adminName: user.name,
            adminEmail: user.email,
            action: 'login',
            module: 'auth',
            description: 'Admin giriş yaptı',
            status: 'success',
            affectedRecords: 1,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
          });
          await activity.save();
        } catch (activityError) {
          logger.error('Error tracking admin login activity:', activityError);
          // Don't fail the login if activity tracking fails
        }
      }
      
      res.json({
        _id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified,
        token: generateToken(user._id, user.role),
      });
    } else {
      logger.info(`Login failed: Invalid password for user ${user.email}`);
      res.status(400).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    logger.error(`Error during user login for email ${email}:`, error);
    res.status(500).json({ message: 'Server error during login' });
  }
};

// @desc    Request email verification
// @route   POST /api/auth/send-verification-email
// @access  Private
const sendVerificationEmail = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.emailVerified) {
      return res.status(400).json({ message: 'Email already verified' });
    }

    // Generate new verification token
    const verificationToken = generateVerificationToken();
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();

    // In a real app, send email here
    logger.info(`Verification email sent to: ${user.email} with token: ${verificationToken}`);
    
    res.status(200).json({ 
      message: 'Verification email sent successfully',
      token: verificationToken // For development only - remove in production
    });
  } catch (error) {
    logger.error('Error sending verification email:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Mark email as verified
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    logger.info(`Email verified for user: ${user.email}`);
    
    res.status(200).json({ 
      message: 'Email verified successfully',
      user: {
        _id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified
      }
    });
  } catch (error) {
    logger.error('Error verifying email:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Get user data (for current user)
// @route   GET /api/auth/me
// @access  Private
const getMe = async (req, res) => {
  res.status(200).json({
    _id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    role: req.user.role,
    emailVerified: req.user.emailVerified,
    age: req.user.age,
    gender: req.user.gender,
    selectedAvatar: req.user.selectedAvatar,
  });
};

// @desc    Update user profile
// @route   PUT /api/auth/update-profile
// @access  Private
const updateProfile = async (req, res) => {
  try {
    const { name, age, gender, selectedAvatar } = req.body;
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update user fields
    if (name) user.name = name;
    if (age !== undefined) user.age = age;
    if (gender !== undefined) user.gender = gender;
    if (selectedAvatar) user.selectedAvatar = selectedAvatar;
    
    user.updatedAt = Date.now();
    await user.save();

    logger.info(`Profile updated for user: ${user.email}`);

    res.status(200).json({
      _id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      emailVerified: user.emailVerified,
      age: user.age,
      gender: user.gender,
      selectedAvatar: user.selectedAvatar,
    });
  } catch (error) {
    logger.error('Error updating profile:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Create admin user
// @route   POST /api/auth/create-admin
// @access  Public
const createAdminUser = async (req, res) => {
  try {
    // Mevcut admin kullanıcısını kontrol et
    const existingAdmin = await User.findOne({ email: 'asil@nevo.com' });
    
    if (existingAdmin) {
      // Şifreyi güncelle - User modeli otomatik hash'ler
      existingAdmin.password = 'asil123';
      existingAdmin.role = 'admin';
      existingAdmin.emailVerified = true;
      await existingAdmin.save();
      
      logger.info(`Admin user updated: ${existingAdmin.email}`);
      res.json({ 
        message: 'Admin kullanıcısı güncellendi',
        user: {
          _id: existingAdmin.id,
          name: existingAdmin.name,
          email: existingAdmin.email,
          role: existingAdmin.role,
          emailVerified: existingAdmin.emailVerified
        }
      });
    } else {
      // Yeni admin kullanıcısı oluştur - User modeli otomatik hash'ler
      const adminUser = new User({
        name: 'Asil Nevo',
        email: 'asil@nevo.com',
        password: 'asil123',
        role: 'admin',
        emailVerified: true,
        age: '25-34',
        gender: 'Erkek',
        selectedAvatar: 'avatar1.png'
      });
      
      await adminUser.save();
      logger.info(`Admin user created: ${adminUser.email}`);
      
      res.status(201).json({ 
        message: 'Admin kullanıcısı oluşturuldu',
        user: {
          _id: adminUser.id,
          name: adminUser.name,
          email: adminUser.email,
          role: adminUser.role,
          emailVerified: adminUser.emailVerified
        }
      });
    }
  } catch (error) {
    logger.error('Error creating admin user:', error);
    res.status(500).json({ message: 'Admin kullanıcısı oluşturulurken hata oluştu' });
  }
};

module.exports = { registerUser, loginUser, getMe, sendVerificationEmail, verifyEmail, updateProfile, createAdminUser }; 