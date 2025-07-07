import emailjs from '@emailjs/browser';

// Configuración de EmailJS
const EMAILJS_CONFIG = {
  serviceId: 'service_in2p88o',
  templateId: 'template_6ahr0wn',
  publicKey: 'Gw2dpHl_e79A9ePqm',
  toEmail: 'jhoelsuarez02@gmail.com'
};

// Inicializar EmailJS
emailjs.init(EMAILJS_CONFIG.publicKey);

export interface ScanResult {
  ip: string;
  os: string;
  activos: Array<{
    name: string;
    product: string;
    version: string;
    port: string;
    tipo: string;
    riesgo: number;
    probabilidad: number;
    impacto: number;
    tratamiento: string;
    cves: Array<{
      id: string;
      score: number;
      severity: string;
      summary: string;
      url: string;
    }>;
    cia: {
      confidencialidad: number;
      integridad: number;
      disponibilidad: number;
    };
  }>;
  heatmap: Array<{
    x: number;
    y: number;
    riesgo: number;
    activo: string;
  }>;
  timestamp: string;
}

export const sendScanReport = async (scanData: ScanResult): Promise<boolean> => {
  try {
    // Generar resumen del reporte
    const totalVulnerabilities = scanData.activos.reduce((total, activo) => total + activo.cves.length, 0);
    const criticalVulns = scanData.activos.reduce((total, activo) => 
      total + activo.cves.filter(cve => cve.score >= 9).length, 0);
    const highVulns = scanData.activos.reduce((total, activo) => 
      total + activo.cves.filter(cve => cve.score >= 7 && cve.score < 9).length, 0);
    const mediumVulns = scanData.activos.reduce((total, activo) => 
      total + activo.cves.filter(cve => cve.score >= 4 && cve.score < 7).length, 0);
    const lowVulns = scanData.activos.reduce((total, activo) => 
      total + activo.cves.filter(cve => cve.score < 4).length, 0);

    const maxRisk = Math.max(...scanData.activos.map(a => a.riesgo));
    const riskLevel = maxRisk >= 40 ? 'CRÍTICO' : maxRisk >= 20 ? 'ALTO' : maxRisk >= 10 ? 'MEDIO' : 'BAJO';

    // Generar lista de vulnerabilidades críticas
    const criticalCVEs = scanData.activos
      .flatMap(activo => 
        activo.cves
          .filter(cve => cve.score >= 7)
          .map(cve => `• ${cve.id} (${cve.score}/10) - ${activo.name} ${activo.product} ${activo.version}`)
      )
      .slice(0, 10); // Limitar a 10 vulnerabilidades más críticas

    // Generar tabla de activos de mayor riesgo
    const topRiskAssets = scanData.activos
      .sort((a, b) => b.riesgo - a.riesgo)
      .slice(0, 5)
      .map(activo => 
        `• ${activo.name} ${activo.product} - Puerto ${activo.port} (Riesgo: ${activo.riesgo.toFixed(1)}) - Tratamiento: ${activo.tratamiento}`
      );

    // Crear el mensaje del reporte
    const reportMessage = `
=== REPORTE DE ANÁLISIS DE RIESGOS CUANTITATIVO ===

IP Analizada: ${scanData.ip}
Sistema Operativo: ${scanData.os}
Fecha y Hora: ${new Date(scanData.timestamp).toLocaleString('es-ES')}

📊 RESUMEN EJECUTIVO:
- Nivel de Riesgo General: ${riskLevel}
- Total de Vulnerabilidades: ${totalVulnerabilities}
- Servicios Analizados: ${scanData.activos.length}

🚨 DISTRIBUCIÓN DE VULNERABILIDADES:
- Críticas (9.0-10.0): ${criticalVulns}
- Altas (7.0-8.9): ${highVulns}
- Medias (4.0-6.9): ${mediumVulns}
- Bajas (0.0-3.9): ${lowVulns}

🎯 ACTIVOS DE MAYOR RIESGO:
${topRiskAssets.join('\n')}

⚠️ VULNERABILIDADES CRÍTICAS Y ALTAS:
${criticalCVEs.length > 0 ? criticalCVEs.join('\n') : 'No se encontraron vulnerabilidades críticas.'}

📈 MATRIZ DE CALOR:
${scanData.heatmap.map(h => `- ${h.activo}: Probabilidad ${h.x}/5, Impacto ${h.y}/5 (Riesgo: ${h.riesgo.toFixed(1)})`).join('\n')}

🔧 RECOMENDACIONES DE TRATAMIENTO:
${scanData.activos.filter(a => a.tratamiento === 'AVOID').length > 0 ? `- EVITAR: ${scanData.activos.filter(a => a.tratamiento === 'AVOID').length} activos requieren acción inmediata` : ''}
${scanData.activos.filter(a => a.tratamiento === 'MITIGATE').length > 0 ? `- MITIGAR: ${scanData.activos.filter(a => a.tratamiento === 'MITIGATE').length} activos requieren medidas de control` : ''}
${scanData.activos.filter(a => a.tratamiento === 'TRANSFER').length > 0 ? `- TRANSFERIR: ${scanData.activos.filter(a => a.tratamiento === 'TRANSFER').length} activos pueden ser transferidos` : ''}
${scanData.activos.filter(a => a.tratamiento === 'ACCEPT').length > 0 ? `- ACEPTAR: ${scanData.activos.filter(a => a.tratamiento === 'ACCEPT').length} activos con riesgo aceptable` : ''}

📋 DETALLE TÉCNICO:
Para obtener el reporte completo en PDF, acceda al sistema QRMS y utilice la función de exportación.

---
Este reporte fue generado automáticamente por el Sistema de Gestión de Riesgos Cuantitativo (QRMS).
`;

    // Parámetros para EmailJS
    const templateParams = {
      name: 'Sistema QRMS',
      email: 'sistema@qrms.local',
      time: new Date().toLocaleString('es-ES'),
      subject: `Reporte de Riesgos - IP ${scanData.ip} - Nivel ${riskLevel}`,
      message: reportMessage
    };

    // Enviar email
    const response = await emailjs.send(
      EMAILJS_CONFIG.serviceId,
      EMAILJS_CONFIG.templateId,
      templateParams
    );

    console.log('Email enviado exitosamente:', response);
    return true;
  } catch (error) {
    console.error('Error enviando email:', error);
    return false;
  }
};
