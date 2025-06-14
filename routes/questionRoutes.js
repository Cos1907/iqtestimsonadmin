const express = require('express');
const router = express.Router();
const Question = require('../models/Question');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');
const { uploadMiddleware, uploadMultipleMiddleware } = require('../middleware/upload');

// Get all questions (admin only)
router.get('/', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const { category, difficulty, search, limit = 50, page = 1 } = req.query;
    
    let query = {};
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (difficulty && difficulty !== 'all') {
      query.difficulty = difficulty;
    }
    
    if (search) {
      query.$or = [
        { questionText: { $regex: search, $options: 'i' } },
        { explanation: { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    
    const questions = await Question.find(query)
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);
    
    const total = await Question.countDocuments(query);
    
    res.json({
      questions,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ message: 'Sorular yüklenirken hata oluştu' });
  }
});

// Get question by ID
router.get('/:id', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const question = await Question.findById(req.params.id)
      .populate('createdBy', 'name email');
    
    if (!question) {
      return res.status(404).json({ message: 'Soru bulunamadı' });
    }
    
    res.json(question);
  } catch (error) {
    console.error('Error fetching question:', error);
    res.status(500).json({ message: 'Soru yüklenirken hata oluştu' });
  }
});

// Create new question with file upload (admin only)
router.post('/', protect, authorizeRoles('admin', 'super_admin'), uploadMiddleware, async (req, res) => {
  try {
    const {
      questionText,
      options,
      correctAnswer,
      explanation,
      difficulty,
      category,
      imageDescription,
      points,
      timeLimit
    } = req.body;
    
    // Dosya yolu oluştur
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
    
    const question = new Question({
      questionText,
      options: JSON.parse(options),
      correctAnswer: parseInt(correctAnswer),
      explanation,
      difficulty,
      category,
      image: imagePath,
      optionImages: [],
      imageDescription,
      points: points || 1,
      timeLimit: timeLimit || 60,
      createdBy: req.user.id
    });
    
    await question.save();
    
    res.status(201).json(question);
  } catch (error) {
    console.error('Error creating question:', error);
    res.status(500).json({ message: 'Soru oluşturulurken hata oluştu', error: error.message });
  }
});

// Upload option images for a question
router.post('/:id/option-images', protect, authorizeRoles('admin', 'super_admin'), uploadMultipleMiddleware, async (req, res) => {
  try {
    const question = await Question.findById(req.params.id);
    if (!question) {
      return res.status(404).json({ message: 'Soru bulunamadı' });
    }
    
    const optionImages = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];
    
    question.optionImages = optionImages;
    await question.save();
    
    res.json({ message: 'Seçenek resimleri yüklendi', optionImages });
  } catch (error) {
    console.error('Error uploading option images:', error);
    res.status(500).json({ message: 'Seçenek resimleri yüklenirken hata oluştu' });
  }
});

// Update question with file upload (admin only)
router.put('/:id', protect, authorizeRoles('admin', 'super_admin'), uploadMiddleware, async (req, res) => {
  try {
    const {
      questionText,
      options,
      correctAnswer,
      explanation,
      difficulty,
      category,
      imageDescription,
      points,
      timeLimit
    } = req.body;
    
    const question = await Question.findById(req.params.id);
    if (!question) {
      return res.status(404).json({ message: 'Soru bulunamadı' });
    }
    
    // Yeni resim yüklendiyse güncelle
    if (req.file) {
      question.image = `/uploads/${req.file.filename}`;
    }
    
    if (questionText) question.questionText = questionText;
    if (options) question.options = JSON.parse(options);
    if (correctAnswer !== undefined) question.correctAnswer = parseInt(correctAnswer);
    if (explanation !== undefined) question.explanation = explanation;
    if (difficulty) question.difficulty = difficulty;
    if (category) question.category = category;
    if (imageDescription !== undefined) question.imageDescription = imageDescription;
    if (points !== undefined) question.points = points;
    if (timeLimit !== undefined) question.timeLimit = timeLimit;
    
    await question.save();
    
    res.json({ message: 'Soru güncellendi', question });
  } catch (error) {
    console.error('Error updating question:', error);
    res.status(500).json({ message: 'Soru güncellenirken hata oluştu', error: error.message });
  }
});

// Delete question (admin only)
router.delete('/:id', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const question = await Question.findById(req.params.id);
    if (!question) {
      return res.status(404).json({ message: 'Soru bulunamadı' });
    }
    
    await Question.findByIdAndDelete(req.params.id);
    res.json({ message: 'Soru silindi' });
  } catch (error) {
    console.error('Error deleting question:', error);
    res.status(500).json({ message: 'Soru silinirken hata oluştu' });
  }
});

// Get question categories
router.get('/categories/list', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const categories = await Question.distinct('category');
    res.json(categories);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Kategoriler yüklenirken hata oluştu' });
  }
});

// Bulk create questions (admin only)
router.post('/bulk', protect, authorizeRoles('admin', 'super_admin'), async (req, res) => {
  try {
    const { questions } = req.body;
    
    if (!Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({ message: 'Geçerli soru listesi gereklidir' });
    }
    
    const questionsWithCreator = questions.map(q => ({
      ...q,
      correctAnswer: parseInt(q.correctAnswer),
      createdBy: req.user.id
    }));
    
    const createdQuestions = await Question.insertMany(questionsWithCreator);
    
    res.status(201).json({
      message: `${createdQuestions.length} soru oluşturuldu`,
      questions: createdQuestions
    });
  } catch (error) {
    console.error('Error creating bulk questions:', error);
    res.status(500).json({ message: 'Toplu soru oluşturulurken hata oluştu', error: error.message });
  }
});

module.exports = router; 