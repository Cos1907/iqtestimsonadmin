const mongoose = require('mongoose');
const SubscriptionPlan = require('../models/SubscriptionPlan');

// MongoDB connection
const MONGODB_URI = 'mongodb://localhost:27017/quizaki';

async function addSubscriptionPlans() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGODB_URI);
    console.log('MongoDB connected successfully');

    // Define the 3 subscription plans
    const plans = [
      {
        name: 'Temel Paket',
        description: 'IQ testlerinizi çözün ve temel analizlerinizi görün',
        price: 29.99,
        currency: 'TRY',
        duration: 1,
        durationType: 'months',
        features: [
          { title: 'Sınırsız IQ Testi', description: 'İstediğiniz kadar test çözün', included: true },
          { title: 'Temel Analizler', description: 'Test sonuçlarınızın detaylı analizi', included: true },
          { title: 'İlerleme Takibi', description: 'IQ seviyenizin gelişimini takip edin', included: true },
          { title: 'Gelişmiş Raporlar', description: 'Detaylı performans raporları', included: false },
          { title: 'Kişisel Koçluk', description: 'Özel IQ geliştirme programları', included: false },
          { title: 'Premium Destek', description: '7/24 öncelikli destek', included: false }
        ],
        isActive: true,
        isPopular: false,
        sortOrder: 1,
        iosProductId: 'com.quizaki.basic.monthly',
        androidProductId: 'com.quizaki.basic.monthly',
        minScore: 0,
        maxScore: 100,
        color: '#4CAF50',
        icon: 'star'
      },
      {
        name: 'Premium Paket',
        description: 'Gelişmiş özelliklerle IQ seviyenizi maksimum seviyeye çıkarın',
        price: 59.99,
        currency: 'TRY',
        duration: 1,
        durationType: 'months',
        features: [
          { title: 'Sınırsız IQ Testi', description: 'İstediğiniz kadar test çözün', included: true },
          { title: 'Temel Analizler', description: 'Test sonuçlarınızın detaylı analizi', included: true },
          { title: 'İlerleme Takibi', description: 'IQ seviyenizin gelişimini takip edin', included: true },
          { title: 'Gelişmiş Raporlar', description: 'Detaylı performans raporları', included: true },
          { title: 'Kişisel Koçluk', description: 'Özel IQ geliştirme programları', included: true },
          { title: 'Premium Destek', description: '7/24 öncelikli destek', included: false }
        ],
        isActive: true,
        isPopular: true,
        sortOrder: 2,
        iosProductId: 'com.quizaki.premium.monthly',
        androidProductId: 'com.quizaki.premium.monthly',
        minScore: 80,
        maxScore: 130,
        color: '#2196F3',
        icon: 'diamond'
      },
      {
        name: 'Ultra Paket',
        description: 'En kapsamlı özelliklerle IQ seviyenizi zirveye taşıyın',
        price: 99.99,
        currency: 'TRY',
        duration: 1,
        durationType: 'months',
        features: [
          { title: 'Sınırsız IQ Testi', description: 'İstediğiniz kadar test çözün', included: true },
          { title: 'Temel Analizler', description: 'Test sonuçlarınızın detaylı analizi', included: true },
          { title: 'İlerleme Takibi', description: 'IQ seviyenizin gelişimini takip edin', included: true },
          { title: 'Gelişmiş Raporlar', description: 'Detaylı performans raporları', included: true },
          { title: 'Kişisel Koçluk', description: 'Özel IQ geliştirme programları', included: true },
          { title: 'Premium Destek', description: '7/24 öncelikli destek', included: true }
        ],
        isActive: true,
        isPopular: false,
        sortOrder: 3,
        iosProductId: 'com.quizaki.ultra.monthly',
        androidProductId: 'com.quizaki.ultra.monthly',
        minScore: 120,
        maxScore: 200,
        color: '#9C27B0',
        icon: 'crown'
      }
    ];

    // Check if plans already exist
    for (const planData of plans) {
      const existingPlan = await SubscriptionPlan.findOne({
        $or: [
          { iosProductId: planData.iosProductId },
          { androidProductId: planData.androidProductId }
        ]
      });

      if (existingPlan) {
        console.log(`Plan "${planData.name}" already exists, skipping...`);
        continue;
      }

      // Create new plan
      const plan = new SubscriptionPlan(planData);
      await plan.save();
      console.log(`Plan "${planData.name}" created successfully`);
    }

    console.log('All subscription plans have been added successfully!');
    
    // Display all plans
    const allPlans = await SubscriptionPlan.find().sort({ sortOrder: 1 });
    console.log('\nCurrent subscription plans:');
    allPlans.forEach(plan => {
      console.log(`- ${plan.name}: ${plan.price} ${plan.currency} (${plan.features.length} features)`);
    });

  } catch (error) {
    console.error('Error adding subscription plans:', error);
  } finally {
    // Close MongoDB connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  }
}

// Run the script
addSubscriptionPlans(); 