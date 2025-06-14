const express = require('express');
const router = express.Router();
const Test = require('../models/Test');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');
const { uploadMiddleware } = require('../middleware/upload');

// Get test categories with counts
router.get('/categories/stats', async (req, res) => {
  try {
    const stats = await Test.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } }
    ]);
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching category stats:', error);
    res.status(500).json({ message: 'Kategori istatistikleri yüklenirken hata oluştu' });
  }
});

// Get all tests (public)
router.get('/', async (req, res) => {
  try {
    const { category, difficulty, search, limit = 50, page = 1, sort } = req.query;
    
    let query = { isActive: true };
    
    if (category && category !== 'Tümü') {
      query.category = category;
    }
    
    // Add difficulty filter
    if (difficulty) {
      query.difficulty = difficulty;
    }
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    
    let sortOption = { createdAt: -1 }; // Default sort by newest
    
    if (sort === 'participants') {
      sortOption = { participants: -1 };
    } else if (sort === 'rating') {
      sortOption = { rating: -1 };
    } else if (sort === 'createdAt') {
      sortOption = { createdAt: -1 };
    }
    
    const tests = await Test.find(query)
      .populate('createdBy', 'username')
      .populate('questions', 'questionText options correctAnswer difficulty category points timeLimit image optionImages')
      .sort(sortOption)
      .limit(parseInt(limit))
      .skip(skip);
    
    const total = await Test.countDocuments(query);
    
    res.json({
      tests,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Error fetching tests:', error);
    res.status(500).json({ message: 'Testler yüklenirken hata oluştu' });
  }
});

// Get test by ID (public)
router.get('/:id', async (req, res) => {
  try {
    const test = await Test.findById(req.params.id)
      .populate('createdBy', 'username')
      .populate('questions', 'questionText options correctAnswer explanation difficulty category image optionImages points timeLimit');
    
    if (!test) {
      return res.status(404).json({ message: 'Test bulunamadı' });
    }
    
    res.json(test);
  } catch (error) {
    console.error('Error fetching test:', error);
    res.status(500).json({ message: 'Test yüklenirken hata oluştu' });
  }
});

// Create test (admin only)
router.post('/', protect, authorizeRoles('admin'), uploadMiddleware, async (req, res) => {
  try {
    console.log('Test creation request received:', req.body);
    console.log('Files:', req.file);
    
    const { title, description, category, difficulty, timeLimit, questions } = req.body;
    
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Bu işlem için yetkiniz yok' });
    }
    
    // Validate required fields
    if (!title || !category || !difficulty) {
      return res.status(400).json({ message: 'Başlık, kategori ve zorluk alanları zorunludur' });
    }
    
    // Handle image upload
    let imagePath = '';
    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
    }
    
    // Parse questions array
    let questionsArray = [];
    if (questions) {
      try {
        questionsArray = JSON.parse(questions);
      } catch (parseError) {
        console.error('Error parsing questions:', parseError);
        return res.status(400).json({ message: 'Sorular formatı hatalı' });
      }
    }
    
    const test = new Test({
      title,
      description,
      category,
      difficulty,
      timeLimit: timeLimit ? parseInt(timeLimit) : 20,
      questions: questionsArray,
      image: imagePath,
      createdBy: req.user.id,
      isNew: true, // New tests are marked as new
    });
    
    console.log('Test object to save:', test);
    
    await test.save();
    
    // Populate questions for response
    await test.populate('questions', 'questionText options correctAnswer difficulty category points timeLimit');
    
    console.log('Test created successfully:', test._id);
    res.status(201).json(test);
  } catch (error) {
    console.error('Error creating test:', error);
    res.status(500).json({ 
      message: 'Test oluşturulurken hata oluştu',
      error: error.message,
      stack: error.stack
    });
  }
});

// Update test (admin only)
router.put('/:id', protect, authorizeRoles('admin'), uploadMiddleware, async (req, res) => {
  try {
    const { title, description, category, difficulty, timeLimit, questions, isActive } = req.body;
    
    const test = await Test.findById(req.params.id);
    if (!test) {
      return res.status(404).json({ message: 'Test not found' });
    }

    // Update test fields
    if (title) test.title = title;
    if (description !== undefined) test.description = description;
    if (category) test.category = category;
    if (difficulty) test.difficulty = difficulty;
    if (timeLimit) test.timeLimit = timeLimit;
    if (questions) test.questions = JSON.parse(questions); // Array of question IDs
    if (isActive !== undefined) test.isActive = isActive;
    
    // Handle image upload
    if (req.file) {
      test.image = `/uploads/${req.file.filename}`;
    }

    await test.save();
    
    // Populate questions for response
    await test.populate('questions', 'questionText options correctAnswer difficulty category points timeLimit');
    
    res.json({ message: 'Test updated successfully', test });
  } catch (error) {
    console.error('Error updating test:', error);
    res.status(500).json({ message: 'Test güncellenirken hata oluştu' });
  }
});

// Delete test (admin only)
router.delete('/:id', protect, authorizeRoles('admin'), async (req, res) => {
  try {
    const test = await Test.findById(req.params.id);
    if (!test) {
      return res.status(404).json({ message: 'Test not found' });
    }

    await Test.findByIdAndDelete(req.params.id);
    res.json({ message: 'Test deleted successfully' });
  } catch (error) {
    console.error('Error deleting test:', error);
    res.status(500).json({ message: 'Test silinirken hata oluştu' });
  }
});

// Start test (create test result record)
router.post('/:id/start', protect, async (req, res) => {
  try {
    const test = await Test.findById(req.params.id);
    if (!test) {
      return res.status(404).json({ message: 'Test bulunamadı' });
    }

    if (!test.isActive) {
      return res.status(400).json({ message: 'Bu test aktif değil' });
    }

    // Create a test result record for tracking
    const TestResult = require('../models/TestResult');
    
    const testResult = new TestResult({
      user: req.user.id, // User is now required
      test: test._id,
      score: 0,
      totalQuestions: test.questions.length,
      correctAnswers: 0,
      wrongAnswers: 0,
      unansweredQuestions: test.questions.length,
      timeSpent: 0,
      timeLimit: test.timeLimit * 60, // Convert minutes to seconds
      answers: [],
      isCompleted: false,
      startedAt: new Date(),
      completedAt: new Date(), // Will be updated when test is completed
    });

    await testResult.save();

    // Populate test data for response
    await testResult.populate('test', 'title category description image');

    res.status(201).json({
      message: 'Test başlatıldı',
      testResult: testResult._id,
      test: testResult.test
    });
  } catch (error) {
    console.error('Error starting test:', error);
    res.status(500).json({ message: 'Test başlatılırken hata oluştu' });
  }
});

// Get test questions for solving (public)
router.get('/:id/questions', async (req, res) => {
  try {
    const test = await Test.findById(req.params.id)
      .populate('questions', 'questionText options correctAnswer explanation difficulty category image optionImages points timeLimit');
    
    if (!test) {
      return res.status(404).json({ message: 'Test bulunamadı' });
    }
    
    if (!test.isActive) {
      return res.status(400).json({ message: 'Bu test aktif değil' });
    }
    
    // Return only the questions without correct answers for solving
    const questionsForSolving = test.questions.map(question => ({
      _id: question._id,
      questionText: question.questionText,
      options: question.options,
      explanation: question.explanation,
      difficulty: question.difficulty,
      category: question.category,
      image: question.image,
      optionImages: question.optionImages,
      points: question.points,
      timeLimit: question.timeLimit
    }));
    
    res.json({
      test: {
        _id: test._id,
        title: test.title,
        description: test.description,
        category: test.category,
        difficulty: test.difficulty,
        timeLimit: test.timeLimit,
        image: test.image
      },
      questions: questionsForSolving
    });
  } catch (error) {
    console.error('Error fetching test questions:', error);
    res.status(500).json({ message: 'Test soruları yüklenirken hata oluştu' });
  }
});

// Submit test results (public)
router.post('/:id/submit', async (req, res) => {
  try {
    const { answers, timeSpent } = req.body;
    
    const test = await Test.findById(req.params.id)
      .populate('questions', 'correctAnswer points');
    
    if (!test) {
      return res.status(404).json({ message: 'Test bulunamadı' });
    }
    
    if (!test.isActive) {
      return res.status(400).json({ message: 'Bu test aktif değil' });
    }
    
    // Calculate score
    let totalScore = 0;
    let correctAnswers = 0;
    const results = [];
    
    test.questions.forEach((question, index) => {
      const userAnswer = answers[index];
      const isCorrect = userAnswer === question.correctAnswer;
      
      if (isCorrect) {
        totalScore += question.points;
        correctAnswers++;
      }
      
      results.push({
        questionId: question._id,
        userAnswer,
        correctAnswer: question.correctAnswer,
        isCorrect,
        points: isCorrect ? question.points : 0
      });
    });
    
    const percentage = (correctAnswers / test.questions.length) * 100;
    
    // Update test statistics
    test.participants += 1;
    await test.save();
    
    res.json({
      totalScore,
      correctAnswers,
      totalQuestions: test.questions.length,
      percentage: Math.round(percentage * 100) / 100,
      timeSpent,
      results
    });
  } catch (error) {
    console.error('Error submitting test:', error);
    res.status(500).json({ message: 'Test sonucu gönderilirken hata oluştu' });
  }
});

module.exports = router; 