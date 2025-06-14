const express = require('express');
const router = express.Router();
const TestResult = require('../models/TestResult');
const Test = require('../models/Test');
const User = require('../models/User');
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');

// Get user's test results
router.get('/user', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, testId } = req.query;
    
    const query = { user: req.user.id };
    
    if (testId) {
      query.test = testId;
    }
    
    const results = await TestResult.find(query)
      .populate('test', 'title category image')
      .sort({ completedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await TestResult.countDocuments(query);
    
    res.json({
      results,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Test sonuçları yüklenirken hata oluştu' });
  }
});

// Get single test result
router.get('/user/:id', auth, async (req, res) => {
  try {
    const result = await TestResult.findById(req.params.id)
      .populate('test', 'title category description image')
      .populate('answers.question', 'questionText options correctAnswer');
    
    if (!result) {
      return res.status(404).json({ message: 'Test sonucu bulunamadı' });
    }
    
    if (result.user.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Bu sonuca erişim izniniz yok' });
    }
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: 'Test sonucu yüklenirken hata oluştu' });
  }
});

// Submit test result
router.post('/', auth, async (req, res) => {
  try {
    const {
      testId,
      answers,
      timeSpent,
      timeLimit,
      deviceInfo,
      ipAddress
    } = req.body;
    
    const test = await Test.findById(testId).populate('questions');
    
    if (!test) {
      return res.status(404).json({ message: 'Test bulunamadı' });
    }
    
    let correctAnswers = 0;
    let wrongAnswers = 0;
    let unansweredQuestions = 0;
    
    const processedAnswers = [];
    const categoryPerformance = {};
    const difficultyPerformance = {};
    
    // Process each answer
    for (const answer of answers) {
      const question = test.questions.find(q => q._id.toString() === answer.questionId);
      
      if (question) {
        const isCorrect = answer.selectedAnswer === question.correctAnswer;
        
        if (isCorrect) {
          correctAnswers++;
        } else if (answer.selectedAnswer !== null && answer.selectedAnswer !== undefined) {
          wrongAnswers++;
        } else {
          unansweredQuestions++;
        }
        
        // Track category performance
        if (question.category) {
          if (!categoryPerformance[question.category]) {
            categoryPerformance[question.category] = { correct: 0, total: 0 };
          }
          categoryPerformance[question.category].total++;
          if (isCorrect) {
            categoryPerformance[question.category].correct++;
          }
        }
        
        // Track difficulty performance
        if (question.difficulty) {
          if (!difficultyPerformance[question.difficulty]) {
            difficultyPerformance[question.difficulty] = { correct: 0, total: 0 };
          }
          difficultyPerformance[question.difficulty].total++;
          if (isCorrect) {
            difficultyPerformance[question.difficulty].correct++;
          }
        }
        
        processedAnswers.push({
          question: question._id,
          selectedAnswer: answer.selectedAnswer,
          correctAnswer: question.correctAnswer,
          isCorrect,
          timeSpent: answer.timeSpent || 0
        });
      }
    }
    
    // Calculate score
    const score = (correctAnswers / test.questions.length) * 100;
    
    // Convert category and difficulty performance to arrays
    const categoryPerformanceArray = Object.entries(categoryPerformance).map(([category, data]) => ({
      category,
      correctAnswers: data.correct,
      totalQuestions: data.total,
      percentage: (data.correct / data.total) * 100
    }));
    
    const difficultyPerformanceArray = Object.entries(difficultyPerformance).map(([difficulty, data]) => ({
      difficulty,
      correctAnswers: data.correct,
      totalQuestions: data.total,
      percentage: (data.correct / data.total) * 100
    }));
    
    // Calculate percentile and rank
    const allResults = await TestResult.find({ test: testId }).sort({ score: -1 });
    const rank = allResults.findIndex(r => r.score < score) + 1;
    const percentile = ((allResults.length - rank + 1) / allResults.length) * 100;
    
    const testResult = new TestResult({
      user: req.user.id,
      test: testId,
      score,
      totalQuestions: test.questions.length,
      correctAnswers,
      wrongAnswers,
      unansweredQuestions,
      timeSpent,
      timeLimit,
      answers: processedAnswers,
      categoryPerformance: categoryPerformanceArray,
      difficultyPerformance: difficultyPerformanceArray,
      percentile,
      rank,
      totalParticipants: allResults.length + 1,
      startedAt: new Date(Date.now() - timeSpent * 1000),
      completedAt: new Date(),
      deviceInfo,
      ipAddress
    });
    
    await testResult.save();
    
    // Populate the result for response
    const populatedResult = await TestResult.findById(testResult._id)
      .populate('test', 'title category image');
    
    res.status(201).json(populatedResult);
  } catch (error) {
    console.error('Error submitting test result:', error);
    res.status(500).json({ message: 'Test sonucu kaydedilirken hata oluştu' });
  }
});

// Admin: Get all test results
router.get('/', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 20, testId, userId, dateFrom, dateTo } = req.query;
    
    const query = {};
    
    if (testId) {
      query.test = testId;
    }
    
    if (userId) {
      query.user = userId;
    }
    
    if (dateFrom || dateTo) {
      query.completedAt = {};
      if (dateFrom) {
        query.completedAt.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        query.completedAt.$lte = new Date(dateTo);
      }
    }
    
    const results = await TestResult.find(query)
      .populate('user', 'name email')
      .populate('test', 'title category image')
      .sort({ completedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();
    
    const total = await TestResult.countDocuments(query);
    
    res.json({
      results,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Test sonuçları yüklenirken hata oluştu' });
  }
});

// Admin: Get test result details
router.get('/:id', adminAuth, async (req, res) => {
  try {
    const result = await TestResult.findById(req.params.id)
      .populate('user', 'name email')
      .populate('test', 'title category image description')
      .populate('answers.question', 'questionText options correctAnswer category difficulty');
    
    if (!result) {
      return res.status(404).json({ message: 'Test sonucu bulunamadı' });
    }
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: 'Test sonucu yüklenirken hata oluştu' });
  }
});

// Admin: Delete test result
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const result = await TestResult.findById(req.params.id);
    
    if (!result) {
      return res.status(404).json({ message: 'Test sonucu bulunamadı' });
    }
    
    await TestResult.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Test sonucu başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Test sonucu silinirken hata oluştu' });
  }
});

// Admin: Get test results analytics
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const { testId, dateFrom, dateTo } = req.query;
    
    const query = {};
    
    if (testId) {
      query.test = testId;
    }
    
    if (dateFrom || dateTo) {
      query.completedAt = {};
      if (dateFrom) {
        query.completedAt.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        query.completedAt.$lte = new Date(dateTo);
      }
    }
    
    const totalResults = await TestResult.countDocuments(query);
    const completedResults = await TestResult.countDocuments({ ...query, isCompleted: true });
    
    const avgScore = await TestResult.aggregate([
      { $match: query },
      { $group: { _id: null, avgScore: { $avg: '$score' } } }
    ]);
    
    const scoreDistribution = await TestResult.aggregate([
      { $match: query },
      {
        $bucket: {
          groupBy: '$score',
          boundaries: [0, 20, 40, 60, 80, 100],
          default: 'Other',
          output: {
            count: { $sum: 1 }
          }
        }
      }
    ]);
    
    const topPerformers = await TestResult.find(query)
      .populate('user', 'name email')
      .populate('test', 'title')
      .sort({ score: -1 })
      .limit(10);
    
    const recentActivity = await TestResult.find(query)
      .populate('user', 'name email')
      .populate('test', 'title')
      .sort({ completedAt: -1 })
      .limit(10);
    
    const categoryPerformance = await TestResult.aggregate([
      { $match: query },
      { $unwind: '$categoryPerformance' },
      {
        $group: {
          _id: '$categoryPerformance.category',
          avgPercentage: { $avg: '$categoryPerformance.percentage' },
          totalQuestions: { $sum: '$categoryPerformance.totalQuestions' },
          correctAnswers: { $sum: '$categoryPerformance.correctAnswers' }
        }
      },
      { $sort: { avgPercentage: -1 } }
    ]);
    
    res.json({
      totalResults,
      completedResults,
      avgScore: avgScore[0]?.avgScore || 0,
      scoreDistribution,
      topPerformers,
      recentActivity,
      categoryPerformance
    });
  } catch (error) {
    res.status(500).json({ message: 'Analitik veriler yüklenirken hata oluştu' });
  }
});

// Admin: Get user performance analytics
router.get('/analytics/user/:userId', adminAuth, async (req, res) => {
  try {
    const { dateFrom, dateTo } = req.query;
    
    const query = { user: req.params.userId };
    
    if (dateFrom || dateTo) {
      query.completedAt = {};
      if (dateFrom) {
        query.completedAt.$gte = new Date(dateFrom);
      }
      if (dateTo) {
        query.completedAt.$lte = new Date(dateTo);
      }
    }
    
    const userResults = await TestResult.find(query)
      .populate('test', 'title category')
      .sort({ completedAt: -1 });
    
    const totalTests = userResults.length;
    const avgScore = userResults.reduce((sum, result) => sum + result.score, 0) / totalTests;
    
    const categoryPerformance = {};
    const testPerformance = {};
    
    userResults.forEach(result => {
      // Category performance
      result.categoryPerformance.forEach(cat => {
        if (!categoryPerformance[cat.category]) {
          categoryPerformance[cat.category] = { total: 0, correct: 0 };
        }
        categoryPerformance[cat.category].total += cat.totalQuestions;
        categoryPerformance[cat.category].correct += cat.correctAnswers;
      });
      
      // Test performance
      testPerformance[result.test.title] = {
        score: result.score,
        completedAt: result.completedAt,
        timeSpent: result.timeSpent
      };
    });
    
    const categoryStats = Object.entries(categoryPerformance).map(([category, data]) => ({
      category,
      totalQuestions: data.total,
      correctAnswers: data.correct,
      percentage: (data.correct / data.total) * 100
    }));
    
    res.json({
      totalTests,
      avgScore,
      categoryStats,
      testPerformance,
      recentResults: userResults.slice(0, 10)
    });
  } catch (error) {
    res.status(500).json({ message: 'Kullanıcı analitikleri yüklenirken hata oluştu' });
  }
});

module.exports = router; 