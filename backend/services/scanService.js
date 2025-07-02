import express from 'express';
import { exec } from 'child_process';
import fs from 'fs';
import { parseStringPromise } from 'xml2js';
import fetch from 'node-fetch';
import path from 'path';

const router = express.Router();

// Utilidad para clasificar servicios
function classifyService(service) {
  const name = service.name.toLowerCase();
  if (name.includes('mysql') || name.includes('postgres') || name.includes('mongo') || name.includes('db')) return 'Base de datos';
  if (name.includes('http') || name.includes('apache') || name.includes('nginx') || name.includes('iis')) return 'Infraestructura';
  if (name.includes('app') || name.includes('web') || name.includes('api')) return 'Aplicación';
  return 'Infraestructura';
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
              const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData || {};
              return {
                id: cve.id,
                score: cvss.baseScore || null,
                severity: cvss.baseSeverity || null,
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
        let tratamiento = 'Aceptar';
        if (a.riesgo >= 40) tratamiento = 'Evitar';
        else if (a.riesgo >= 20) tratamiento = 'Mitigar';
        else if (a.riesgo >= 10) tratamiento = 'Transferir';
        return { ...a, tratamiento };
      });

      // 9. Respuesta final
      res.json({
        ip,
        os,
        shodan: shodanData,
        activos: priorizados,
        heatmap,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Processing failed:', err);
      res.status(500).json({ error: 'Processing failed', details: err.message });
    }
  });
});

export default router; 