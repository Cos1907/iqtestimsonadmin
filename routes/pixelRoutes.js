const express = require('express');
const router = express.Router();
const Pixel = require('../models/Pixel');
const adminAuth = require('../middleware/adminAuth');

// Get all pixels with filtering and pagination
router.get('/', adminAuth, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      status = 'all',
      type = 'all',
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    const query = {};

    // Search filter
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { pixelId: { $regex: search, $options: 'i' } }
      ];
    }

    // Status filter
    if (status !== 'all') {
      query.status = status;
    }

    // Type filter
    if (type !== 'all') {
      query.type = type;
    }

    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const pixels = await Pixel.find(query)
      .populate('createdBy', 'name email')
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();

    const total = await Pixel.countDocuments(query);

    res.json({
      pixels,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching pixels:', error);
    res.status(500).json({ message: 'Pikseller getirilirken hata oluştu' });
  }
});

// Get pixel by ID
router.get('/:id', adminAuth, async (req, res) => {
  try {
    const pixel = await Pixel.findById(req.params.id)
      .populate('createdBy', 'name email');
    
    if (!pixel) {
      return res.status(404).json({ message: 'Pixel bulunamadı' });
    }

    res.json(pixel);
  } catch (error) {
    console.error('Error fetching pixel:', error);
    res.status(500).json({ message: 'Pixel getirilirken hata oluştu' });
  }
});

// Create new pixel
router.post('/', adminAuth, async (req, res) => {
  try {
    const {
      name,
      description,
      type,
      status,
      pixelId,
      events,
      trackingEvents,
      conversionValue
    } = req.body;

    const pixel = new Pixel({
      name,
      description,
      type,
      status,
      pixelId,
      events,
      trackingEvents,
      conversionValue,
      createdBy: req.user.id
    });

    await pixel.save();
    res.status(201).json(pixel);
  } catch (error) {
    console.error('Error creating pixel:', error);
    res.status(500).json({ message: 'Pixel oluşturulurken hata oluştu' });
  }
});

// Update pixel
router.put('/:id', adminAuth, async (req, res) => {
  try {
    const pixel = await Pixel.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!pixel) {
      return res.status(404).json({ message: 'Pixel bulunamadı' });
    }

    res.json(pixel);
  } catch (error) {
    console.error('Error updating pixel:', error);
    res.status(500).json({ message: 'Pixel güncellenirken hata oluştu' });
  }
});

// Delete pixel
router.delete('/:id', adminAuth, async (req, res) => {
  try {
    const pixel = await Pixel.findByIdAndDelete(req.params.id);
    
    if (!pixel) {
      return res.status(404).json({ message: 'Pixel bulunamadı' });
    }

    res.json({ message: 'Pixel başarıyla silindi' });
  } catch (error) {
    console.error('Error deleting pixel:', error);
    res.status(500).json({ message: 'Pixel silinirken hata oluştu' });
  }
});

// Get pixel analytics
router.get('/analytics/overview', adminAuth, async (req, res) => {
  try {
    const totalPixels = await Pixel.countDocuments();
    const activePixels = await Pixel.countDocuments({ status: 'active' });
    const testingPixels = await Pixel.countDocuments({ status: 'testing' });
    const inactivePixels = await Pixel.countDocuments({ status: 'inactive' });

    // Count pixels by type
    const pixelTypes = await Pixel.aggregate([
      { $group: { _id: '$type', count: { $sum: 1 } } }
    ]);

    res.json({
      totalPixels,
      activePixels,
      testingPixels,
      inactivePixels,
      pixelTypes
    });
  } catch (error) {
    console.error('Error fetching pixel analytics:', error);
    res.status(500).json({ message: 'Analitik veriler getirilirken hata oluştu' });
  }
});

// Get pixel tracking code
router.get('/:id/tracking-code', adminAuth, async (req, res) => {
  try {
    const pixel = await Pixel.findById(req.params.id);
    
    if (!pixel) {
      return res.status(404).json({ message: 'Pixel bulunamadı' });
    }

    let trackingCode = '';

    switch (pixel.type) {
      case 'facebook':
        trackingCode = `
<!-- Facebook Pixel Code -->
<script>
!function(f,b,e,v,n,t,s)
{if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];
s.parentNode.insertBefore(t,s)}(window, document,'script',
'https://connect.facebook.net/en_US/fbevents.js');
fbq('init', '${pixel.pixelId}');
fbq('track', 'PageView');
</script>
<noscript><img height="1" width="1" style="display:none"
src="https://www.facebook.com/tr?id=${pixel.pixelId}&ev=PageView&noscript=1"
/></noscript>
<!-- End Facebook Pixel Code -->`;
        break;

      case 'google':
        trackingCode = `
<!-- Google Analytics Code -->
<script async src="https://www.googletagmanager.com/gtag/js?id=${pixel.pixelId}"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', '${pixel.pixelId}');
</script>
<!-- End Google Analytics Code -->`;
        break;

      case 'tiktok':
        trackingCode = `
<!-- TikTok Pixel Code -->
<script>
!function (w, d, t) {
  if (w[t]) return;
  w[t] = function () {
    w[t].callMethod ? w[t].callMethod.apply(w[t], arguments) : w[t].queue.push(arguments);
  };
  w[t].queue = w[t].queue || [];
  w[t].t = +new Date();
  var s = d.createElement(t);
  s.async = !0;
  s.src = 'https://analytics.tiktok.com/i18n/pixel/sdk.js?sdkid=${pixel.pixelId}';
  var a = d.getElementsByTagName(t)[0];
  a.parentNode.insertBefore(s, a);
}(window, document, 'ttq');
ttq.track('PageView');
</script>
<!-- End TikTok Pixel Code -->`;
        break;

      default:
        trackingCode = `<!-- Custom Pixel Code for ${pixel.name} -->`;
    }

    res.json({ trackingCode, pixel });
  } catch (error) {
    console.error('Error generating tracking code:', error);
    res.status(500).json({ message: 'Tracking kodu oluşturulurken hata oluştu' });
  }
});

// Track pixel event
router.post('/track/:pixelId', async (req, res) => {
  try {
    const { pixelId } = req.params;
    const { event, value = 0, userId } = req.body;

    const pixel = await Pixel.findOne({ pixelId });
    
    if (!pixel) {
      return res.status(404).json({ message: 'Pixel bulunamadı' });
    }

    // Here you would implement the actual tracking logic
    // For now, we'll just return success
    res.json({ 
      message: 'Event tracked successfully',
      pixel: pixel.name,
      event,
      value
    });
  } catch (error) {
    console.error('Error tracking pixel event:', error);
    res.status(500).json({ message: 'Event takip edilirken hata oluştu' });
  }
});

module.exports = router; 