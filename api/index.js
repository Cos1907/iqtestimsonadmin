// Vercel serverless function handler
// Updated for proper Vercel deployment
// Triggering new deployment for testing
module.exports = (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Parse JSON body
  let body = {};
  if (req.method === 'POST' || req.method === 'PUT') {
    try {
      body = JSON.parse(req.body || '{}');
    } catch (e) {
      body = {};
    }
  }

  // Route handling
  const { pathname } = new URL(req.url, `https://${req.headers.host}`);

  if (pathname === '/' && req.method === 'GET') {
    res.status(200).json({
      message: 'API is running...',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      method: req.method,
      path: pathname
    });
    return;
  }

  if (pathname === '/health' && req.method === 'GET') {
    res.status(200).json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      method: req.method,
      path: pathname
    });
    return;
  }

  if (pathname === '/test' && req.method === 'GET') {
    res.status(200).json({
      message: 'Test endpoint working',
      timestamp: new Date().toISOString(),
      method: req.method,
      path: pathname,
      headers: req.headers
    });
    return;
  }

  // 404 for all other routes
  res.status(404).json({
    error: 'Route not found',
    path: pathname,
    method: req.method,
    timestamp: new Date().toISOString()
  });
};
