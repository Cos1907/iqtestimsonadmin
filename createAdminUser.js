const mongoose = require('mongoose');
const User = require('./models/User');
const bcrypt = require('bcryptjs');

const createAdminUser = async () => {
  try {
    // MongoDB'ye bağlan
    await mongoose.connect('mongodb://localhost:27017/quizaki');
    console.log('MongoDB\'ye bağlandı');

    // Mevcut admin kullanıcısını kontrol et
    const existingAdmin = await User.findOne({ email: 'asil@nevo.com' });
    
    if (existingAdmin) {
      console.log('Admin kullanıcısı zaten mevcut:', existingAdmin.email);
      
      // Şifreyi güncelle
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('asil123', salt);
      
      existingAdmin.password = hashedPassword;
      existingAdmin.role = 'admin';
      existingAdmin.emailVerified = true;
      await existingAdmin.save();
      
      console.log('Admin kullanıcısı güncellendi');
    } else {
      // Yeni admin kullanıcısı oluştur
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('asil123', salt);
      
      const adminUser = new User({
        name: 'Asil Nevo',
        email: 'asil@nevo.com',
        password: hashedPassword,
        role: 'admin',
        emailVerified: true,
        age: '25-34',
        gender: 'Erkek',
        selectedAvatar: 'avatar1.png'
      });
      
      await adminUser.save();
      console.log('Admin kullanıcısı oluşturuldu:', adminUser.email);
    }

    // Tüm kullanıcıları listele
    const users = await User.find({}, 'name email role emailVerified');
    console.log('\nMevcut kullanıcılar:');
    users.forEach(user => {
      console.log(`- ${user.name} (${user.email}) - Role: ${user.role} - Verified: ${user.emailVerified}`);
    });

    mongoose.connection.close();
    console.log('\nİşlem tamamlandı');
    
  } catch (error) {
    console.error('Hata:', error);
    mongoose.connection.close();
  }
};

createAdminUser(); 