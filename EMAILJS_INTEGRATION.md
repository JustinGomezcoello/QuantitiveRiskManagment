# Integración EmailJS - QRMS

## Funcionalidad Implementada

Se ha integrado EmailJS para enviar automáticamente un reporte completo de análisis de riesgos al finalizar cada escaneo.

### Configuración EmailJS

- **Service ID**: `service_in2p88o`
- **Template ID**: `template_6ahr0wn`
- **Public Key**: `Gw2dpHl_e79A9ePqm`
- **Email Destino**: `jhoelsuarez02@gmail.com`

### Características del Reporte

El reporte incluye:

1. **Resumen Ejecutivo**
   - IP analizada y sistema operativo
   - Nivel de riesgo general
   - Total de vulnerabilidades encontradas
   - Número de servicios analizados

2. **Distribución de Vulnerabilidades**
   - Críticas (9.0-10.0)
   - Altas (7.0-8.9)
   - Medias (4.0-6.9)
   - Bajas (0.0-3.9)

3. **Activos de Mayor Riesgo**
   - Top 5 servicios con mayor puntuación de riesgo
   - Tratamiento recomendado para cada uno

4. **Vulnerabilidades Críticas y Altas**
   - Lista de CVEs con puntuación >= 7.0
   - Servicio afectado para cada vulnerabilidad

5. **Matriz de Calor**
   - Probabilidad e impacto de cada activo
   - Puntuación de riesgo calculada

6. **Recomendaciones de Tratamiento**
   - Distribución por estrategia: EVITAR, MITIGAR, TRANSFERIR, ACEPTAR

### Flujo de Funcionamiento

1. **Inicio del Escaneo**: Se inicia el proceso normal de escaneo con Nmap
2. **Procesamiento**: Se analizan los resultados y se consultan las APIs (Shodan, NVD)
3. **Cálculo de Riesgos**: Se calculan los riesgos cuantitativos según ISO 27005
4. **Generación del Reporte**: Se crea un reporte estructurado con todos los hallazgos
5. **Envío Automático**: Se envía por email automáticamente al completar el escaneo
6. **Confirmación**: Se muestra confirmación visual del envío exitoso

### Interfaz de Usuario

- **Indicador de Progreso**: Muestra cuando se está enviando el email
- **Confirmación Visual**: Alert verde cuando el email se envía exitosamente
- **Botón de Reenvío**: Permite reenviar manualmente el reporte
- **Estado del Email**: Indica la dirección de destino y último envío

### Archivos Modificados

1. **`frontend/src/services/emailService.ts`** (NUEVO)
   - Servicio para integración con EmailJS
   - Formateo del reporte de riesgos
   - Configuración de parámetros del email

2. **`frontend/src/pages/Index.tsx`** (MODIFICADO)
   - Integración del envío automático al finalizar escaneo
   - Estados para controlar el envío del email
   - Interfaz para reenvío manual
   - Indicadores visuales de estado

3. **`frontend/package.json`** (MODIFICADO)
   - Agregada dependencia `@emailjs/browser`

### Formato del Email

El email utiliza el template configurado en EmailJS con las siguientes variables:

- `{{name}}`: "Sistema QRMS"
- `{{email}}`: "sistema@qrms.local"
- `{{time}}`: Fecha y hora del escaneo
- `{{subject}}`: "Reporte de Riesgos - IP {ip} - Nivel {nivel}"
- `{{message}}`: Reporte completo formateado

### Uso

1. **Automático**: Al completar cualquier escaneo, se envía automáticamente
2. **Manual**: Usar el botón "Enviar por Email" o "Reenviar Email" en la sección Dashboard
3. **Verificación**: Revisar el email en jhoelsuarez02@gmail.com

### Ventajas

- ✅ Notificación inmediata de resultados críticos
- ✅ Reporte estructurado y profesional
- ✅ Historial de análisis por email
- ✅ Integración transparente con el flujo existente
- ✅ Capacidad de reenvío manual cuando sea necesario

### Próximos Pasos Sugeridos

1. Configurar plantilla HTML más avanzada en EmailJS
2. Agregar archivos adjuntos (PDF del reporte)
3. Configurar múltiples destinatarios
4. Implementar notificaciones condicionales (solo para riesgos críticos)
5. Agregar programación de reportes periódicos
