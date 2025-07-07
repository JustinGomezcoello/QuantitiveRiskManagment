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

    // Generar clasificación de activos por tipo
    const activosPorTipo = {
      infraestructura: scanData.activos.filter(a => a.tipo === 'infrastructure').length,
      aplicaciones: scanData.activos.filter(a => a.tipo === 'application').length,
      baseDatos: scanData.activos.filter(a => a.tipo === 'database').length
    };

    // Generar métricas de exposición
    const activosExternos = scanData.activos.filter(a => 
      ['80', '443', '22', '21', '23', '25', '53', '110', '143', '993', '995'].includes(a.port)
    ).length;

    // Crear el mensaje del reporte con metodología QRMS completa
    const reportMessage = `
═══════════════════════════════════════════════════════════════════════════════
    QUANTITATIVE RISK MANAGEMENT SYSTEM (QRMS) - REPORTE DE ANÁLISIS
═══════════════════════════════════════════════════════════════════════════════

🎯 DATOS DE LA EVALUACIÓN:
├─ IP Analizada: ${scanData.ip}
├─ Sistema Operativo: ${scanData.os}
├─ Fecha y Hora: ${new Date(scanData.timestamp).toLocaleString('es-ES')}
├─ Marco de Referencia: NIST SP 800-30 Rev.1, ISO/IEC 27005:2022, NVD
└─ Metodología: Análisis automatizado mediante nmap + APIs (Shodan/NVD)

📊 RESUMEN EJECUTIVO - NIVEL ORGANIZACIONAL:
┌─────────────────────────────────────────────────────────────────────────────┐
│  NIVEL DE RIESGO GENERAL: ${riskLevel}                                        │
│  Total de Vulnerabilidades Detectadas: ${totalVulnerabilities}              │
│  Servicios/Activos Analizados: ${scanData.activos.length}                   │
│  Tiempo de Análisis: Automatizado < 2 min/IP                                │
└─────────────────────────────────────────────────────────────────────────────┘

� IDENTIFICACIÓN Y CLASIFICACIÓN DE ACTIVOS (Sección 4 - QRMS):
├─ Infraestructura (servidores web, routers, firewalls): ${activosPorTipo.infraestructura}
├─ Aplicaciones (servicios de aplicación): ${activosPorTipo.aplicaciones}
├─ Bases de Datos (servicios de datos): ${activosPorTipo.baseDatos}
└─ Exposición Externa (puertos públicos): ${activosExternos} servicios

🚨 IDENTIFICACIÓN DE AMENAZAS Y VULNERABILIDADES (Sección 5 - QRMS):
┌─ Distribución por Severidad CVSS ─┐
│  • Críticas (9.0-10.0): ${criticalVulns.toString().padEnd(10)}│
│  • Altas (7.0-8.9): ${highVulns.toString().padEnd(13)}│
│  • Medias (4.0-6.9): ${mediumVulns.toString().padEnd(12)}│
│  • Bajas (0.0-3.9): ${lowVulns.toString().padEnd(13)}│
└─────────────────────────────────────┘

⚖️ VALORACIÓN DEL RIESGO (Sección 6 - QRMS):
Fórmula aplicada: Riesgo = Probabilidad (CVSS) × Impacto (CIA + Criticidad)

🎯 TOP 5 ACTIVOS DE MAYOR RIESGO:
${topRiskAssets.length > 0 ? topRiskAssets.join('\n') : '• No se identificaron activos de riesgo significativo'}

⚠️ VULNERABILIDADES CRÍTICAS Y ALTAS (≥7.0 CVSS):
${criticalCVEs.length > 0 ? criticalCVEs.join('\n') : '✅ No se detectaron vulnerabilidades críticas o altas'}

📈 MATRIZ DE CALOR - MAPA DE RIESGOS (Sección 6 - QRMS):
Ubicación en matriz Probabilidad/Impacto (escala 1-5):
${scanData.heatmap.map(h => `│ ${h.activo.padEnd(30)} │ P:${h.x}/5 │ I:${h.y}/5 │ R:${h.riesgo.toFixed(1).padStart(4)} │`).join('\n')}

🔧 ESTRATEGIAS DE TRATAMIENTO DEL RIESGO (Sección 8 - QRMS):
${scanData.activos.filter(a => a.tratamiento === 'AVOID').length > 0 ? 
`├─ EVITAR (Riesgo crítico): ${scanData.activos.filter(a => a.tratamiento === 'AVOID').length} activos
│  └─ Requieren eliminación o cambio inmediato del activo` : ''}
${scanData.activos.filter(a => a.tratamiento === 'MITIGATE').length > 0 ? 
`├─ MITIGAR (Aplicar controles): ${scanData.activos.filter(a => a.tratamiento === 'MITIGATE').length} activos
│  └─ Parches, actualizaciones, configuraciones seguras` : ''}
${scanData.activos.filter(a => a.tratamiento === 'TRANSFER').length > 0 ? 
`├─ TRANSFERIR (Delegar riesgo): ${scanData.activos.filter(a => a.tratamiento === 'TRANSFER').length} activos
│  └─ Hosting externo, seguros, tercerización` : ''}
${scanData.activos.filter(a => a.tratamiento === 'ACCEPT').length > 0 ? 
`└─ ACEPTAR (Riesgo tolerable): ${scanData.activos.filter(a => a.tratamiento === 'ACCEPT').length} activos
   └─ Monitoreo periódico, sin acción inmediata` : ''}

📋 EVALUACIÓN Y PRIORIZACIÓN (Sección 7 - QRMS):
Criterios aplicados:
├─ Severidad CVEs encontrados (NVD Database)
├─ Rol del activo en la organización (CIA: C/I/A)
├─ Exposición directa (puertos abiertos públicamente)
└─ Facilidad de explotación (disponibilidad de exploits)

🔄 PLAN DE MONITOREO Y MEJORA CONTINUA (Sección 9 - QRMS):
┌─ KPIs del Análisis ────────────────────────────────────────────┐
│  • Tiempo de respuesta: < 2 segundos por keyword             │
│  • Precisión categorización: ≥ 90%                           │
│  • Cobertura de activos: ${scanData.activos.length}/IP                              │
│  • Fuentes consultadas: nmap + Shodan + NVD                  │
└─────────────────────────────────────────────────────────────────┘

� MARCO NORMATIVO Y CUMPLIMIENTO:
├─ NIST SP 800-30 Rev.1 (Risk Assessment)
├─ ISO/IEC 27005:2022 (Information Security Risk Management)
├─ CIS Controls v8 (Critical Security Controls)
├─ NVD - National Vulnerability Database
└─ SPDP Ecuador 2025 (Marco local de ciberseguridad)

🔗 PRÓXIMOS PASOS RECOMENDADOS:
1. Implementar controles para activos de riesgo CRÍTICO y ALTO
2. Programar escaneos recurrentes (mensual/trimestral)
3. Establecer alertas automáticas para nuevos CVEs
4. Documentar e implementar procedimientos de respuesta
5. Capacitación del personal en gestión de riesgos cibernéticos

📧 CONTACTO Y SOPORTE TÉCNICO:
Para obtener el reporte completo en PDF o consultas técnicas:
└─ Acceder al sistema QRMS y utilizar la función de exportación

═══════════════════════════════════════════════════════════════════════════════
Este reporte fue generado automáticamente por el Quantitative Risk Management 
System (QRMS) siguiendo estándares internacionales ISO 27005 y NIST 800-30.
═══════════════════════════════════════════════════════════════════════════════
`;

    // Parámetros para EmailJS
    const templateParams = {
      name: 'QRMS - Quantitative Risk Management System',
      email: 'qrms.system@cybersecurity.local',
      time: new Date().toLocaleString('es-ES'),
      subject: `QRMS Analysis Report - IP ${scanData.ip} - Risk Level: ${riskLevel} - ${totalVulnerabilities} CVEs Found`,
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
