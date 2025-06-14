const express = require('express');
const router = express.Router();

// Get IQ rankings by country
router.get('/', async (req, res) => {
  try {
    const { limit = 10, sort = 'rank' } = req.query;
    
    // Mock data for IQ rankings (in a real app, this would come from a database)
    const rankings = [
      { rank: 1, country: 'Japonya', flag: '🇯🇵', averageIQ: 106, population: 125700000, region: 'Asya' },
      { rank: 2, country: 'Güney Kore', flag: '🇰🇷', averageIQ: 105, population: 51270000, region: 'Asya' },
      { rank: 3, country: 'Tayvan', flag: '🇹🇼', averageIQ: 104, population: 23820000, region: 'Asya' },
      { rank: 4, country: 'Singapur', flag: '🇸🇬', averageIQ: 103, population: 5700000, region: 'Asya' },
      { rank: 5, country: 'Hong Kong', flag: '🇭🇰', averageIQ: 103, population: 7500000, region: 'Asya' },
      { rank: 6, country: 'Çin', flag: '🇨🇳', averageIQ: 101, population: 1402000000, region: 'Asya' },
      { rank: 7, country: 'İsviçre', flag: '🇨🇭', averageIQ: 101, population: 8700000, region: 'Avrupa' },
      { rank: 8, country: 'Hollanda', flag: '🇳🇱', averageIQ: 100, population: 17400000, region: 'Avrupa' },
      { rank: 9, country: 'İtalya', flag: '🇮🇹', averageIQ: 99, population: 60360000, region: 'Avrupa' },
      { rank: 10, country: 'Almanya', flag: '🇩🇪', averageIQ: 99, population: 83190000, region: 'Avrupa' },
      { rank: 11, country: 'Avusturya', flag: '🇦🇹', averageIQ: 98, population: 9000000, region: 'Avrupa' },
      { rank: 12, country: 'İsveç', flag: '🇸🇪', averageIQ: 98, population: 10350000, region: 'Avrupa' },
      { rank: 13, country: 'Belçika', flag: '🇧🇪', averageIQ: 97, population: 11590000, region: 'Avrupa' },
      { rank: 14, country: 'Finlandiya', flag: '🇫🇮', averageIQ: 97, population: 5500000, region: 'Avrupa' },
      { rank: 15, country: 'Norveç', flag: '🇳🇴', averageIQ: 96, population: 5400000, region: 'Avrupa' },
      { rank: 16, country: 'Danimarka', flag: '🇩🇰', averageIQ: 96, population: 5800000, region: 'Avrupa' },
      { rank: 17, country: 'Fransa', flag: '🇫🇷', averageIQ: 95, population: 67390000, region: 'Avrupa' },
      { rank: 18, country: 'İspanya', flag: '🇪🇸', averageIQ: 94, population: 46750000, region: 'Avrupa' },
      { rank: 19, country: 'Polonya', flag: '🇵🇱', averageIQ: 94, population: 37850000, region: 'Avrupa' },
      { rank: 20, country: 'Macaristan', flag: '🇭🇺', averageIQ: 93, population: 9660000, region: 'Avrupa' },
      { rank: 21, country: 'Türkiye', flag: '🇹🇷', averageIQ: 90, population: 84340000, region: 'Avrupa/Asya' },
      { rank: 22, country: 'Rusya', flag: '🇷🇺', averageIQ: 89, population: 144100000, region: 'Avrupa/Asya' },
      { rank: 23, country: 'Brezilya', flag: '🇧🇷', averageIQ: 87, population: 212600000, region: 'Güney Amerika' },
      { rank: 24, country: 'Meksika', flag: '🇲🇽', averageIQ: 86, population: 128900000, region: 'Kuzey Amerika' },
      { rank: 25, country: 'Arjantin', flag: '🇦🇷', averageIQ: 85, population: 45160000, region: 'Güney Amerika' },
      { rank: 26, country: 'Hindistan', flag: '🇮🇳', averageIQ: 82, population: 1380000000, region: 'Asya' },
      { rank: 27, country: 'Endonezya', flag: '🇮🇩', averageIQ: 78, population: 273500000, region: 'Asya' },
      { rank: 28, country: 'Mısır', flag: '🇪🇬', averageIQ: 76, population: 102300000, region: 'Afrika' },
      { rank: 29, country: 'Nijerya', flag: '🇳🇬', averageIQ: 67, population: 206100000, region: 'Afrika' },
      { rank: 30, country: 'Etiyopya', flag: '🇪🇹', averageIQ: 64, population: 114900000, region: 'Afrika' }
    ];

    // Sort rankings based on parameter
    let sortedRankings = [...rankings];
    if (sort === 'population') {
      sortedRankings.sort((a, b) => b.population - a.population);
    } else if (sort === 'iq') {
      sortedRankings.sort((a, b) => b.averageIQ - a.averageIQ);
    } else {
      // Default sort by rank
      sortedRankings.sort((a, b) => a.rank - b.rank);
    }

    // Apply limit
    const limitedRankings = sortedRankings.slice(0, parseInt(limit));

    res.json({
      rankings: limitedRankings,
      total: rankings.length,
      limit: parseInt(limit),
      sort
    });
  } catch (error) {
    console.error('Error fetching IQ rankings:', error);
    res.status(500).json({ message: 'IQ sıralaması yüklenirken hata oluştu' });
  }
});

// Get ranking by country
router.get('/country/:countryCode', async (req, res) => {
  try {
    const { countryCode } = req.params;
    
    // Mock data - in real app, this would query by country code
    const rankings = [
      { rank: 1, country: 'Japonya', flag: '🇯🇵', averageIQ: 106, population: 125700000, region: 'Asya', countryCode: 'JP' },
      { rank: 2, country: 'Güney Kore', flag: '🇰🇷', averageIQ: 105, population: 51270000, region: 'Asya', countryCode: 'KR' },
      { rank: 21, country: 'Türkiye', flag: '🇹🇷', averageIQ: 90, population: 84340000, region: 'Avrupa/Asya', countryCode: 'TR' }
    ];

    const country = rankings.find(r => r.countryCode === countryCode.toUpperCase());
    
    if (!country) {
      return res.status(404).json({ message: 'Ülke bulunamadı' });
    }

    res.json(country);
  } catch (error) {
    console.error('Error fetching country ranking:', error);
    res.status(500).json({ message: 'Ülke sıralaması yüklenirken hata oluştu' });
  }
});

module.exports = router; 