const mongoose = require('mongoose');
const AdminActivity = require('../models/AdminActivity');
const User = require('../models/User');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/quizaki', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const createSampleActivities = async () => {
  try {
    // Find an admin user
    const adminUser = await User.findOne({ role: 'admin' });
    
    if (!adminUser) {
      console.log('No admin user found. Please create an admin user first.');
      return;
    }

    console.log('Creating sample admin activities...');

    const sampleActivities = [
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'login',
        module: 'auth',
        description: 'Admin giriş yaptı',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 5) // 5 minutes ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'create',
        module: 'tests',
        description: 'Yeni test oluşturuldu: IQ Testi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 15) // 15 minutes ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'update',
        module: 'users',
        description: 'Kullanıcı bilgileri güncellendi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 30) // 30 minutes ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'publish',
        module: 'blog',
        description: 'Blog yazısı yayınlandı',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60) // 1 hour ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'create',
        module: 'subscription_plans',
        description: 'Yeni abonelik planı oluşturuldu',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 2) // 2 hours ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'delete',
        module: 'questions',
        description: 'Soru silindi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 3) // 3 hours ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'update',
        module: 'pages',
        description: 'Sayfa güncellendi: Hakkımızda',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 4) // 4 hours ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'create',
        module: 'campaigns',
        description: 'Yeni kampanya oluşturuldu',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 5) // 5 hours ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'analytics_view',
        module: 'analytics',
        description: 'Analitik sayfası görüntülendi',
        status: 'success',
        affectedRecords: 0,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 6) // 6 hours ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'settings_change',
        module: 'settings',
        description: 'Sistem ayarları güncellendi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 7) // 7 hours ago
      },
      // Yesterday's activities
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'login',
        module: 'auth',
        description: 'Admin giriş yaptı',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24) // 1 day ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'create',
        module: 'tests',
        description: 'Test oluşturuldu: Matematik Testi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 25) // 1 day + 1 hour ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'update',
        module: 'users',
        description: 'Kullanıcı rolü güncellendi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 26) // 1 day + 2 hours ago
      },
      // This week's activities
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'create',
        module: 'categories',
        description: 'Yeni kategori oluşturuldu',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3) // 3 days ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'publish',
        module: 'blog',
        description: 'Blog yazısı yayınlandı: Test Teknikleri',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 4) // 4 days ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'delete',
        module: 'notifications',
        description: 'Eski bildirimler silindi',
        status: 'success',
        affectedRecords: 5,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5) // 5 days ago
      },
      // This month's activities
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'create',
        module: 'pixels',
        description: 'Pixel kodu eklendi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10) // 10 days ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'update',
        module: 'subscription_plans',
        description: 'Abonelik planı fiyatı güncellendi',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15) // 15 days ago
      },
      {
        adminId: adminUser._id,
        adminName: adminUser.name,
        adminEmail: adminUser.email,
        action: 'feature',
        module: 'tests',
        description: 'Test öne çıkarıldı',
        status: 'success',
        affectedRecords: 1,
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 20) // 20 days ago
      }
    ];

    // Clear existing activities (optional)
    await AdminActivity.deleteMany({});
    console.log('Cleared existing activities');

    // Insert sample activities
    const result = await AdminActivity.insertMany(sampleActivities);
    console.log(`Created ${result.length} sample admin activities`);

    console.log('Sample activities created successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Error creating sample activities:', error);
    process.exit(1);
  }
};

createSampleActivities(); 