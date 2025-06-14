const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  questionText: {
    type: String,
    required: [true, 'Soru metni gereklidir'],
    trim: true
  },
  options: {
    type: [String],
    required: [true, 'En az 2 seçenek gereklidir'],
    validate: {
      validator: function(v) {
        return v.length >= 2;
      },
      message: 'En az 2 seçenek olmalıdır'
    }
  },
  correctAnswer: {
    type: Number,
    required: [true, 'Doğru cevap gereklidir'],
    validate: {
      validator: function(v) {
        return v >= 0 && v < this.options.length;
      },
      message: 'Doğru cevap geçerli bir seçenek indeksi olmalıdır'
    }
  },
  explanation: {
    type: String,
    trim: true
  },
  difficulty: {
    type: String,
    enum: ['kolay', 'orta', 'zor'],
    default: 'orta'
  },
  category: {
    type: String,
    required: [true, 'Kategori gereklidir']
  },
  // Ana soru görseli
  image: {
    type: String,
    trim: true
  },
  // Seçenek görselleri (opsiyonel)
  optionImages: {
    type: [String],
    default: []
  },
  // Görsel açıklaması
  imageDescription: {
    type: String,
    trim: true
  },
  points: {
    type: Number,
    default: 1
  },
  timeLimit: {
    type: Number, // saniye cinsinden
    default: 60
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

// Doğru cevap indeksini kontrol eden middleware
questionSchema.pre('save', function(next) {
  if (this.correctAnswer >= this.options.length) {
    return next(new Error('Doğru cevap indeksi seçenek sayısından büyük olamaz'));
  }
  next();
});

module.exports = mongoose.model('Question', questionSchema); 