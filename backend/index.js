import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
dotenv.config();

import shodanRouter from './services/shodanService.js';
import nvdRouter from './services/nvdService.js';
import nmapRouter from './services/nmapService.js';
import scanRouter from './services/scanService.js';

const app = express();
app.use(cors());
app.use(express.json());

app.use('/api/shodan', shodanRouter);
app.use('/api/nvd', nvdRouter);
app.use('/api/nmap', nmapRouter);
app.use('/api/scan', scanRouter);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
}); 