import express from 'express';
import { exec } from 'child_process';
import fs from 'fs';
import { parseStringPromise } from 'xml2js';
import fetch from 'node-fetch';
import path from 'path';
import PDFDocument from 'pdfkit';

const router = express.Router();

const OBS_DB_PATH = path.join(process.cwd(), 'report_observations.json');

function loadObservations() {
  if (!fs.existsSync(OBS_DB_PATH)) return {};
  return JSON.parse(fs.readFileSync(OBS_DB_PATH, 'utf8'));
}
function saveObservations(data) {
  fs.writeFileSync(OBS_DB_PATH, JSON.stringify(data, null, 2));
}

// Utilidad para clasificar servicios
function classifyService(service) {
  const name = service.name.toLowerCase();
  if (name.includes('mysql') || name.includes('postgres') || name.includes('mongo') || name.includes('db')) return 'database';
  if (name.includes('http') || name.includes('apache') || name.includes('nginx') || name.includes('iis')) return 'infrastructure';
  if (name.includes('app') || name.includes('web') || name.includes('api')) return 'application';
  return 'infrastructure';
}

// Utilidad para calcular CIA (dummy, puedes mejorarla)
function calculateCIA(service) {
  // Por ahora, asigna valores fijos. Puedes mejorar con lógica real.
  return {
    confidencialidad: 4,
    integridad: 4,
    disponibilidad: 3
  };
}

// Utilidad para calcular criticidad (dummy)
function calculateCriticidad(tipo) {
  if (tipo === 'Base de datos') return 2.0;
  if (tipo === 'Aplicación') return 1.5;
  return 1.0;
}

// Utilidad para escalar CVSS a 1-5
function scaleCVSS(cvss) {
  if (cvss >= 9) return 5;
  if (cvss >= 7) return 4;
  if (cvss >= 5) return 3;
  if (cvss >= 3) return 2;
  return 1;
}

router.post('/', async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Missing IP' });

  const xmlPath = path.join(process.cwd(), 'scan_result.xml');

  // Escaneo profundo: detecta servicios, versiones y vulnerabilidades (puede tardar varios minutos)
  exec(`nmap -sV --script vuln ${ip} -oX scan_result.xml`, async (error, stdout, stderr) => {
    if (error) {
      console.error('Nmap execution failed:', error, stderr);
      return res.status(500).json({ error: 'Nmap execution failed', details: stderr });
    }
    try {
      // 2. Procesar XML
      const xml = fs.readFileSync(xmlPath, 'utf8');
      const result = await parseStringPromise(xml);
      const host = result.nmaprun.host[0];
      const ports = host.ports[0].port || [];
      const os = host.os ? host.os[0].osmatch?.[0]?.$?.name : 'Desconocido';
      const detectedServices = ports.map(p => {
        const service = p.service?.[0]?.$ || {};
        return {
          port: p.$.portid,
          protocol: p.$.protocol,
          name: service.name || 'unknown',
          product: service.product || '',
          version: service.version || '',
        };
      });

      // 3. Clasificar activos y calcular CIA
      const activos = detectedServices.map(s => {
        const tipo = classifyService(s);
        const cia = calculateCIA(s);
        const criticidad = calculateCriticidad(tipo);
        return {
          ...s,
          tipo,
          cia,
          criticidad,
        };
      });

      // 4. Consultar Shodan
      const shodanKey = process.env.SHODAN_API_KEY;
      let shodanData = {};
      if (shodanKey) {
        const shodanRes = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${shodanKey}`);
        if (shodanRes.ok) shodanData = await shodanRes.json();
      }

      // 5. Consultar NVD para cada servicio
      const nvdKey = process.env.NVD_API_KEY;
      for (let activo of activos) {
        let cves = [];
        if (nvdKey && activo.product) {
          const query = encodeURIComponent(`${activo.product} ${activo.version}`);
          const nvdRes = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}`, {
            headers: { 'apiKey': nvdKey }
          });
          if (nvdRes.ok) {
            const nvdData = await nvdRes.json();
            cves = (nvdData.vulnerabilities || []).map(v => {
              const cve = v.cve;
              // Mejorar el mapeo de score/severity
              let score = null;
              let severity = null;
              if (cve.metrics?.cvssMetricV31?.[0]?.cvssData) {
                score = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
                severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
              } else if (cve.metrics?.cvssMetricV30?.[0]?.cvssData) {
                score = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
                severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity;
              } else if (cve.metrics?.cvssMetricV2?.[0]?.cvssData) {
                score = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
                severity = cve.metrics.cvssMetricV2[0].baseSeverity || null;
              }
              return {
                id: cve.id,
                score: score,
                severity: severity,
                published: cve.published,
                summary: cve.descriptions?.[0]?.value || '',
                url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
              };
            });
          }
        }
        activo.cves = cves;
      }

      // 6. Calcular riesgo
      const activosConRiesgo = activos.map(a => {
        const maxCVSS = a.cves.length > 0 ? Math.max(...a.cves.map(c => c.score || 0)) : 0;
        const probabilidad = maxCVSS;
        const ciaProm = (a.cia.confidencialidad + a.cia.integridad + a.cia.disponibilidad) / 3;
        const impacto = ciaProm + a.criticidad;
        const riesgo = probabilidad * impacto;
        return {
          ...a,
          probabilidad,
          impacto,
          riesgo,
        };
      });

      // 7. Matriz de calor (estructura base)
      const heatmap = activosConRiesgo.map(a => ({
        x: scaleCVSS(a.probabilidad),
        y: Math.round(a.impacto),
        riesgo: a.riesgo,
        activo: a.name + ' ' + a.product + ' ' + a.version
      }));

      // 8. Priorización y tratamiento
      const priorizados = activosConRiesgo.sort((a, b) => b.riesgo - a.riesgo).map(a => {
        let tratamiento = 'ACCEPT';
        if (a.riesgo >= 40) tratamiento = 'AVOID';
        else if (a.riesgo >= 20) tratamiento = 'MITIGATE';
        else if (a.riesgo >= 10) tratamiento = 'TRANSFER';
        return { ...a, tratamiento };
      });

      // 9. Respuesta final
      const response = {
        ip,
        os,
        shodan: shodanData,
        activos: priorizados,
        heatmap,
        timestamp: new Date().toISOString()
      };
      // Guardar el resultado del escaneo para reportes PDF
      fs.writeFileSync(path.join(process.cwd(), `last_scan_${ip}.json`), JSON.stringify(response, null, 2));
      res.json(response);
    } catch (err) {
      console.error('Processing failed:', err);
      res.status(500).json({ error: 'Processing failed', details: err.message });
    }
  });
});

// Endpoint para guardar observación
router.post('/report/observation', (req, res) => {
  const { ip, cve, observation } = req.body;
  if (!ip || !cve) return res.status(400).json({ error: 'Missing ip or cve' });
  const db = loadObservations();
  if (!db[ip]) db[ip] = {};
  db[ip][cve] = observation;
  saveObservations(db);
  res.json({ success: true });
});

// Endpoint para obtener observaciones por IP
router.get('/report/observations', (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip' });
  const db = loadObservations();
  res.json(db[ip] || {});
});

// Endpoint para exportar PDF
router.get('/report/pdf', async (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip' });
  try {
    const scanPath = path.join(process.cwd(), `last_scan_${ip}.json`);
    if (!fs.existsSync(scanPath)) {
      // Devuelve un PDF con mensaje de error
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=report_${ip}.pdf`);
      const doc = new PDFDocument();
      doc.pipe(res);
      doc.fontSize(18).text('QRMS - Vulnerability Report', { align: 'center' });
      doc.moveDown();
      doc.fontSize(14).fillColor('red').text('No scan data found for this IP.', { align: 'center' });
      doc.end();
      return;
    }
    const scanData = JSON.parse(fs.readFileSync(scanPath, 'utf8'));
    const observations = loadObservations()[ip] || {};
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=report_${ip}.pdf`);
    const doc = new PDFDocument();
    doc.pipe(res);
    doc.fontSize(20).text('QRMS - Vulnerability Report', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`IP: ${ip}`);
    doc.text(`Date: ${new Date().toLocaleString()}`);
    doc.moveDown();
    doc.fontSize(16).text('Vulnerabilities:', { underline: true });
    doc.moveDown(0.5);
    let vulnCount = 0;
    (scanData.activos || []).forEach(a => {
      (a.cves || []).forEach(cve => {
        vulnCount++;
        doc.fontSize(12).fillColor('black').text(`CVE: ${cve.id} | Score: ${cve.score || '-'} | Severity: ${cve.severity || '-'} | Service: ${a.name} ${a.product} ${a.version}`);
        doc.fontSize(10).fillColor('gray').text(`Observation: ${observations[cve.id] || ''}`);
        doc.moveDown(0.5);
      });
    });
    if (vulnCount === 0) {
      doc.fontSize(14).fillColor('green').text('No vulnerabilities detected for this IP.', { align: 'center' });
    }
    doc.end();
  } catch (err) {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=report_${ip}.pdf`);
    const doc = new PDFDocument();
    doc.pipe(res);
    doc.fontSize(18).text('QRMS - Vulnerability Report', { align: 'center' });
    doc.moveDown();
    doc.fontSize(14).fillColor('red').text('An error occurred while generating the PDF report.', { align: 'center' });
    doc.fontSize(10).fillColor('black').text(String(err));
    doc.end();
  }
});

export default router; 