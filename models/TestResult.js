const mongoose = require('mongoose');

const testResultSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  test: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Test',
    required: true
  },
  score: {
    type: Number,
    required: true
  },
  totalQuestions: {
    type: Number,
    required: true
  },
  correctAnswers: {
    type: Number,
    required: true
  },
  wrongAnswers: {
    type: Number,
    required: true
  },
  unansweredQuestions: {
    type: Number,
    default: 0
  },
  timeSpent: {
    type: Number, // in seconds
    required: true
  },
  timeLimit: {
    type: Number, // in seconds
    required: true
  },
  answers: [{
    question: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Question'
    },
    selectedAnswer: {
      type: Number
    },
    correctAnswer: {
      type: Number
    },
    isCorrect: {
      type: Boolean
    },
    timeSpent: {
      type: Number // in seconds
    }
  }],
  categoryPerformance: [{
    category: {
      type: String
    },
    correctAnswers: {
      type: Number
    },
    totalQuestions: {
      type: Number
    },
    percentage: {
      type: Number
    }
  }],
  difficultyPerformance: [{
    difficulty: {
      type: String,
      enum: ['easy', 'medium', 'hard']
    },
    correctAnswers: {
      type: Number
    },
    totalQuestions: {
      type: Number
    },
    percentage: {
      type: Number
    }
  }],
  percentile: {
    type: Number
  },
  rank: {
    type: Number
  },
  totalParticipants: {
    type: Number
  },
  certificate: {
    issued: {
      type: Boolean,
      default: false
    },
    certificateId: {
      type: String
    },
    issuedAt: {
      type: Date
    }
  },
  feedback: {
    rating: {
      type: Number,
      min: 1,
      max: 5
    },
    comment: {
      type: String
    }
  },
  isCompleted: {
    type: Boolean,
    default: true
  },
  startedAt: {
    type: Date,
    required: true
  },
  completedAt: {
    type: Date,
    required: true
  },
  deviceInfo: {
    platform: {
      type: String
    },
    version: {
      type: String
    },
    userAgent: {
      type: String
    }
  },
  ipAddress: {
    type: String
  }
}, {
  timestamps: true
});

// Indexes for efficient queries
testResultSchema.index({ user: 1, test: 1 });
testResultSchema.index({ test: 1, score: -1 });
testResultSchema.index({ user: 1, createdAt: -1 });
testResultSchema.index({ score: -1 });

// Calculate percentage
testResultSchema.virtual('percentage').get(function() {
  return this.totalQuestions > 0 ? (this.correctAnswers / this.totalQuestions) * 100 : 0;
});

// Calculate time efficiency
testResultSchema.virtual('timeEfficiency').get(function() {
  return this.timeLimit > 0 ? (this.timeSpent / this.timeLimit) * 100 : 0;
});

module.exports = mongoose.model('TestResult', testResultSchema); 