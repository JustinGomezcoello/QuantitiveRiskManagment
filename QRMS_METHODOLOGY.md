# Metodología QRMS - Quantitative Risk Management System

## Implementación en el Sistema de Email Reporting

### 🎯 Objetivo de la Metodología

Metodología técnica y automatizada que, a partir del ingreso de una dirección IP, identifica y evalúa activos digitales, detecta vulnerabilidades usando herramientas como nmap, y permite aplicar estrategias de tratamiento de riesgos cibernéticos bajo estándares internacionales.

### 📋 Marco de Referencia Implementado

- **NIST SP 800-30 Rev.1** - Risk Assessment
- **ISO/IEC 27005:2022** - Information Security Risk Management  
- **NVD** - National Vulnerability Database
- **CIS Controls v8** - Critical Security Controls
- **SPDP Ecuador 2025** - Marco local de ciberseguridad

### 🔍 Proceso de Análisis Automatizado

#### 1. **Identificación y Clasificación de Activos** (Sección 4 - QRMS)
```
- Servicios activos detectados por nmap
- Sistemas operativos identificados
- Frameworks detectados por headers/puertos
- Clasificación automática por tipo:
  • Infraestructura (servidores web, routers, firewalls)
  • Aplicaciones (servicios de aplicación) 
  • Bases de Datos (servicios de datos)
```

#### 2. **Identificación de Amenazas y Vulnerabilidades** (Sección 5 - QRMS)
```
- Herramientas: nmap -sV --script vuln
- Integración con APIs: Shodan + NVD
- Extracción automática de CVEs
- Enriquecimiento con base de datos NVD
```

#### 3. **Valoración del Riesgo** (Sección 6 - QRMS)
```
Fórmula implementada:
Riesgo = Probabilidad (basado en CVSS) × Impacto (CIA + Criticidad empresarial)

Matriz de Calor (1-5):
┌─────────────────────────────────────────────────────┐
│ Impacto/Prob │  1  │  2  │  3  │  4  │  5  │ Acción │
├─────────────────────────────────────────────────────┤
│      5       │  5  │ 10  │ 15  │ 20  │ 25  │ EVITAR │
│      4       │  4  │  8  │ 12  │ 16  │ 20  │ MITIGAR│
│      3       │  3  │  6  │  9  │ 12  │ 15  │ MITIGAR│
│      2       │  2  │  4  │  6  │  8  │ 10  │TRANSFER│
│      1       │  1  │  2  │  3  │  4  │  5  │ ACEPTAR│
└─────────────────────────────────────────────────────┘
```

#### 4. **Estrategias de Tratamiento** (Sección 8 - QRMS)

| Estrategia | Cuándo se Aplica | Implementación |
|------------|------------------|----------------|
| **EVITAR** | Riesgo ≥ 20 | Eliminar/cambiar activo crítico |
| **MITIGAR** | Riesgo 10-19 | Parches, configuraciones seguras |
| **TRANSFERIR** | Riesgo 5-9 | Hosting externo, seguros |
| **ACEPTAR** | Riesgo < 5 | Monitoreo periódico |

### 📊 Formato del Reporte Implementado

El reporte generado incluye:

#### **Sección 1: Datos de la Evaluación**
- IP analizada y sistema operativo
- Timestamp del análisis
- Marco normativo aplicado
- Metodología utilizada

#### **Sección 2: Resumen Ejecutivo**
- Nivel de riesgo general
- Total de vulnerabilidades
- Servicios analizados
- Tiempo de análisis

#### **Sección 3: Clasificación de Activos**
- Distribución por tipo (Infraestructura/Aplicaciones/BD)
- Métricas de exposición externa
- Inventario automatizado

#### **Sección 4: Amenazas y Vulnerabilidades**
- Distribución por severidad CVSS
- Identificación automática de CVEs
- Consulta en tiempo real a NVD

#### **Sección 5: Valoración del Riesgo**
- Aplicación de fórmula cuantitativa
- Top 5 activos de mayor riesgo
- Matriz de calor por activo

#### **Sección 6: Estrategias de Tratamiento**
- Distribución por estrategia (EVITAR/MITIGAR/TRANSFERIR/ACEPTAR)
- Recomendaciones específicas por activo
- Priorización basada en riesgo

#### **Sección 7: KPIs y Cumplimiento**
- Métricas de análisis
- Tiempo de respuesta
- Precisión de categorización
- Cobertura de activos

#### **Sección 8: Marco Normativo**
- Referencias a estándares implementados
- Cumplimiento regulatorio
- Trazabilidad del proceso

### 🔄 KPIs Implementados

| Indicador | Meta QRMS | Implementación |
|-----------|-----------|----------------|
| Tiempo de respuesta | < 2 segundos/keyword | ✅ Automatizado |
| Precisión categorización | ≥ 90% | ✅ Algoritmo clasificación |
| Cobertura activos | 100% IP analizada | ✅ Escaneo completo |
| Fuentes consultadas | Múltiples APIs | ✅ nmap + Shodan + NVD |

### 📧 Integración EmailJS

#### **Configuración Automática:**
- Envío automático al completar escaneo
- Formato profesional con metodología QRMS
- Subject line informativo con nivel de riesgo
- Reporte completo según estándares

#### **Parámetros del Email:**
```typescript
{
  name: 'QRMS - Quantitative Risk Management System',
  email: 'qrms.system@cybersecurity.local',
  subject: 'QRMS Analysis Report - IP {ip} - Risk Level: {level} - {count} CVEs Found',
  message: {reporte_completo_con_metodologia}
}
```

### 🎯 Ventajas de la Implementación

1. **✅ Cumplimiento Normativo**: ISO 27005, NIST 800-30
2. **✅ Automatización Completa**: Sin intervención manual
3. **✅ Trazabilidad**: Metodología documentada y reproducible
4. **✅ Objetividad**: Basado en CVSS y bases de datos oficiales
5. **✅ Escalabilidad**: Aplicable a cualquier organización
6. **✅ Tiempo Real**: Análisis en menos de 2 minutos
7. **✅ Formato Profesional**: Reporte técnico estructurado

### 🔮 Próximos Pasos

1. **Riesgo Residual**: Implementar recálculo post-mitigación
2. **Alertas Automáticas**: Notificaciones de nuevos CVEs
3. **Dashboard Histórico**: Panel de control con tendencias
4. **Reportes Programados**: Escaneos recurrentes automáticos
5. **Integración SIEM**: Exportación a herramientas de monitoreo

### 📝 Conclusión

La implementación de la metodología QRMS en el sistema de email reporting garantiza:

- **Evaluación automatizada** de seguridad desde una IP
- **Integración técnica** con herramientas ofensivas y defensivas  
- **Valoración cuantitativa** del riesgo según estándares internacionales
- **Toma de decisiones** basada en evidencia objetiva
- **Acción proactiva** con estrategias de tratamiento definidas

El sistema cumple con los objetivos de la metodología QRMS proporcionando un análisis técnico, automatizado y basado en estándares internacionales para la gestión de riesgos cibernéticos.
