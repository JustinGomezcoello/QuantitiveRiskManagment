import express from 'express';
import { exec } from 'child_process';

const router = express.Router();

router.post('/', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Missing IP' });

  exec(`nmap -sV ${ip}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Nmap execution failed', details: stderr });
    }
    res.json({ result: stdout });
  });
});

export default router; 