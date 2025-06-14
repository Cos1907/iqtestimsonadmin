const mongoose = require('mongoose');

const AppConfigSchema = new mongoose.Schema({
  // App Settings
  appName: {
    type: String,
    default: 'QuizakiApp'
  },
  appVersion: {
    type: String,
    default: '1.0.0'
  },
  maintenanceMode: {
    type: Boolean,
    default: false
  },
  
  // Feature Toggles
  features: {
    emailVerification: {
      type: Boolean,
      default: true
    },
    passwordReset: {
      type: Boolean,
      default: true
    },
    socialLogin: {
      type: Boolean,
      default: false
    },
    pushNotifications: {
      type: Boolean,
      default: true
    }
  },
  
  // API Settings
  apiSettings: {
    rateLimit: {
      type: Number,
      default: 100
    },
    maxFileSize: {
      type: Number,
      default: 5242880 // 5MB
    }
  },
  
  // Notification Settings
  notifications: {
    email: {
      enabled: {
        type: Boolean,
        default: true
      },
      provider: {
        type: String,
        default: 'smtp'
      }
    },
    push: {
      enabled: {
        type: Boolean,
        default: true
      },
      provider: {
        type: String,
        default: 'firebase'
      }
    }
  },
  
  // Content Settings
  content: {
    defaultLanguage: {
      type: String,
      default: 'tr'
    },
    supportedLanguages: [{
      type: String,
      default: ['tr', 'en']
    }]
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('AppConfig', AppConfigSchema); 