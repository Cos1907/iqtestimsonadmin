const mongoose = require('mongoose');
const Test = require('../models/Test');
const User = require('../models/User');
require('dotenv').config();

const sampleTests = [
  {
    title: 'Genel Kültür Ustası',
    description: 'Genel kültür bilginizi test edin',
    category: 'Genel Kültür',
    difficulty: 'Orta',
    timeLimit: 20,
    questions: [
      {
        questionText: "Türkiye Cumhuriyeti'nin kurucusu kimdir?",
        type: 'text',
        options: [
          { id: 'a', value: "İsmet İnönü" },
          { id: 'b', value: "Mustafa Kemal Atatürk" },
          { id: 'c', value: "Fevzi Çakmak" },
          { id: 'd', value: "Kazım Karabekir" },
        ],
        correctAnswer: 'b',
      },
      {
        questionText: "Hangi gezegen Güneş Sistemi'ndeki en büyük gezegendir?",
        type: 'text',
        options: [
          { id: 'a', value: "Mars" },
          { id: 'b', value: "Jüpiter" },
          { id: 'c', value: "Satürn" },
          { id: 'd', value: "Neptün" },
        ],
        correctAnswer: 'b',
      },
    ],
    image: 'https://via.placeholder.com/150x100/FF9900/ffffff?text=GK',
    isNew: true,
    participants: 1250,
    rating: 4.8,
    ratingCount: 89,
  },
  {
    title: 'Bilim Temelleri',
    description: 'Temel bilim bilgilerinizi ölçün',
    category: 'Bilim',
    difficulty: 'Zor',
    timeLimit: 25,
    questions: [
      {
        questionText: "Suyun kimyasal formülü nedir?",
        type: 'text',
        options: [
          { id: 'a', value: "H2O" },
          { id: 'b', value: "CO2" },
          { id: 'c', value: "NaCl" },
          { id: 'd', value: "O2" },
        ],
        correctAnswer: 'a',
      },
      {
        questionText: "İnsan vücudundaki en büyük organ hangisidir?",
        type: 'text',
        options: [
          { id: 'a', value: "Kalp" },
          { id: 'b', value: "Beyin" },
          { id: 'c', value: "Deri" },
          { id: 'd', value: "Karaciğer" },
        ],
        correctAnswer: 'c',
      },
    ],
    image: 'https://via.placeholder.com/150x100/FF8C00/ffffff?text=BT',
    isNew: false,
    participants: 890,
    rating: 4.6,
    ratingCount: 67,
  },
  {
    title: 'Dünya Tarihi Zaman Çizelgesi',
    description: 'Tarih bilginizi test edin',
    category: 'Tarih',
    difficulty: 'Kolay',
    timeLimit: 15,
    questions: [
      {
        questionText: "İstanbul'un fetih tarihi nedir?",
        type: 'text',
        options: [
          { id: 'a', value: "1453" },
          { id: 'b', value: "1454" },
          { id: 'c', value: "1452" },
          { id: 'd', value: "1455" },
        ],
        correctAnswer: 'a',
      },
    ],
    image: 'https://via.placeholder.com/150x100/FF7F50/ffffff?text=DT',
    isNew: true,
    participants: 1100,
    rating: 4.9,
    ratingCount: 95,
  },
  {
    title: 'Spor Efsaneleri',
    description: 'Spor dünyasındaki efsane isimleri tanıyor musunuz?',
    category: 'Spor',
    difficulty: 'Orta',
    timeLimit: 12,
    questions: [
      {
        questionText: "Hangi ülke en çok FIFA Dünya Kupası kazanmıştır?",
        type: 'text',
        options: [
          { id: 'a', value: "Almanya" },
          { id: 'b', value: "Brezilya" },
          { id: 'c', value: "Arjantin" },
          { id: 'd', value: "İtalya" },
        ],
        correctAnswer: 'b',
      },
    ],
    image: 'https://via.placeholder.com/150x100/FF6347/ffffff?text=SE',
    isNew: false,
    participants: 750,
    rating: 4.7,
    ratingCount: 54,
  },
  {
    title: 'Klasik Rock Müziği',
    description: 'Rock müzik tarihini test edin',
    category: 'Müzik',
    difficulty: 'Zor',
    timeLimit: 18,
    questions: [
      {
        questionText: "Queen grubunun solisti kimdir?",
        type: 'text',
        options: [
          { id: 'a', value: "Freddie Mercury" },
          { id: 'b', value: "John Lennon" },
          { id: 'c', value: "Mick Jagger" },
          { id: 'd', value: "David Bowie" },
        ],
        correctAnswer: 'a',
      },
    ],
    image: 'https://via.placeholder.com/150x100/FF4500/ffffff?text=KR',
    isNew: true,
    participants: 650,
    rating: 4.5,
    ratingCount: 42,
  },
  {
    title: 'Blockbuster Filmler',
    description: 'Popüler filmler hakkında ne biliyorsunuz?',
    category: 'Film',
    difficulty: 'Kolay',
    timeLimit: 10,
    questions: [
      {
        questionText: "Titanic filmi hangi yıl çıkmıştır?",
        type: 'text',
        options: [
          { id: 'a', value: "1997" },
          { id: 'b', value: "1998" },
          { id: 'c', value: "1996" },
          { id: 'd', value: "1999" },
        ],
        correctAnswer: 'a',
      },
    ],
    image: 'https://via.placeholder.com/150x100/FF6B35/ffffff?text=BF',
    isNew: false,
    participants: 920,
    rating: 4.4,
    ratingCount: 78,
  },
];

async function createSampleTests() {
  try {
    // MongoDB'ye bağlan
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected...');

    // Admin kullanıcısını bul veya oluştur
    let adminUser = await User.findOne({ role: 'admin' });
    if (!adminUser) {
      console.log('Admin user not found, creating one...');
      adminUser = new User({
        name: 'Admin User',
        username: 'admin',
        email: 'admin@example.com',
        password: 'admin123',
        role: 'admin',
        isEmailVerified: true,
      });
      await adminUser.save();
    }

    // Mevcut testleri temizle
    await Test.deleteMany({});
    console.log('Existing tests cleared...');

    // Örnek testleri oluştur
    for (const testData of sampleTests) {
      const test = new Test({
        ...testData,
        createdBy: adminUser._id,
      });
      await test.save();
      console.log(`Created test: ${test.title}`);
    }

    console.log('Sample tests created successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Error creating sample tests:', error);
    process.exit(1);
  }
}

createSampleTests(); 