import express from 'express';
import fetch from 'node-fetch';

const router = express.Router();

// Consulta NVD por query (ej: cpeName, keyword, etc)
router.get('/', async (req, res) => {
  const { query } = req.query;
  const apiKey = process.env.NVD_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'NVD API key not set' });
  if (!query) return res.status(400).json({ error: 'Missing query parameter' });

  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}`, {
      headers: { 'apiKey': apiKey }
    });
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Error from NVD API' });
    }
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch from NVD', details: err.message });
  }
});

export default router; 