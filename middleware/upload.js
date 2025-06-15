const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Upload klasörlerini oluştur
const createUploadDirs = () => {
  const uploadDirs = [
    '/var/www/iqtestim/uploads',
    '/var/www/iqtestim/uploads/blog',
    '/var/www/iqtestim/uploads/users',
    '/var/www/iqtestim/uploads/tests'
  ];
  
  uploadDirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};

createUploadDirs();

// Storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    let uploadPath = '/var/www/iqtestim/uploads';
    
    // Dosya tipine göre klasör seç
    if (file.fieldname === 'blogImage') {
      uploadPath = '/var/www/iqtestim/uploads/blog';
    } else if (file.fieldname === 'userImage') {
      uploadPath = '/var/www/iqtestim/uploads/users';
    } else if (file.fieldname === 'testImage') {
      uploadPath = '/var/www/iqtestim/uploads/tests';
    }
    
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Benzersiz dosya adı oluştur
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Sadece resim dosyaları yüklenebilir!'));
  }
};

// Multer configuration
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: fileFilter
});

module.exports = upload; 
module.exports.uploadMiddleware = upload.single('image');
module.exports.uploadMultipleMiddleware = upload.array('images', 10); // Allow up to 10 images 