import express from 'express';
import fetch from 'node-fetch';

const router = express.Router();

router.get('/:ip', async (req, res) => {
  const { ip } = req.params;
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'Shodan API key not set' });

  try {
    const response = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Error from Shodan API' });
    }
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch from Shodan', details: err.message });
  }
});

export default router; 