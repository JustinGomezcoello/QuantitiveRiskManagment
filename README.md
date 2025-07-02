# Quantitative Risk Management System (QRMS)

## Overview

**QRMS** (Quantitative Risk Management System) is an automated, end-to-end platform for cyber risk assessment, asset discovery, vulnerability detection, and risk reporting. Designed for real-world environments, QRMS leverages industry standards (ISO/IEC 27005, NIST 800-30, SPDP Ecuador, CIS Controls v8) to provide actionable, quantitative risk analysis and treatment recommendations for any IP address.

---

## Key Features

- **Automated Asset Discovery:**
  - Enter any IP (public or private) and QRMS will scan using Nmap (`nmap -sV --script vuln <IP> -oX scan_result.xml`).
  - Extracts active services, versions, open ports, detected OS, and frameworks.

- **Asset Classification:**
  - Classifies each detected service as Infrastructure, Application, or Database.
  - Assigns CIA (Confidentiality, Integrity, Availability) ratings (1–5 scale) and business criticality.

- **Threat Intelligence Integration:**
  - Queries the real Shodan API for public exposure, scan history, geolocation, ISP, and technical details.
  - Combines Shodan data with Nmap results for a comprehensive asset profile.

- **Vulnerability Detection:**
  - For each detected service, queries the real NVD API for CVEs, CVSS scores, severity, and technical summaries.
  - Uses your real NVD API key for up-to-date vulnerability data.

- **Quantitative Risk Calculation:**
  - Calculates risk using: `RISK = PROBABILITY (CVSS) × IMPACT (CIA + Business Criticality)`.
  - Impact is computed as the average CIA plus a business criticality factor.
  - All risk calculations are based on international standards.

- **Risk Visualization:**
  - Generates a 5x5 heatmap (Impact vs. Probability) with color-coded risk levels.
  - Each asset is plotted on the matrix for clear prioritization.

- **Risk Prioritization & Treatment:**
  - Prioritizes risks by CVE severity, asset role, and public exposure.
  - Suggests real treatment strategies: ACCEPT, MITIGATE, TRANSFER, AVOID, with professional guidance for each.

- **Residual Risk Calculation:**
  - After mitigation, re-scan and compare new risk scores to show risk evolution over time.

- **Automated Technical Reporting:**
  - Generates PDF and CSV reports per IP, including detected assets, vulnerabilities, heatmap, suggested treatments, and residual risk.
  - Dashboard with KPIs: scan time, CVEs detected, % of vulnerable services, and more.

- **Continuous Monitoring & Alerts:**
  - Schedules automatic scans every 7 days.
  - Monitors NVD for new CVEs affecting previously scanned assets.
  - Sends alerts via email (and optionally Telegram/Slack).

- **Quality Indicators:**
  - ≥3 keywords analyzed per scan
  - ≥90% correct asset categorization
  - <2s response per keyword
  - 100% scan history retention

- **Standards Compliance:**
  - ISO/IEC 27005:2022, NIST SP 800-30 Rev.1, SPDP Ecuador 2025, CIS Controls v8

---

## Technology Stack
- **Frontend:** React, Vite, TypeScript, Tailwind CSS, shadcn-ui
- **Backend:** Node.js, Express, Nmap, Shodan API, NVD API, PDFKit
- **Containerization:** Docker, Nginx (for SPA routing and API proxy)

---

## How to Run

### Option 1: Docker Compose (Recommended)

Build and start the entire system (frontend + backend) with a single command:

```sh
docker-compose up -d
```
- The frontend will be available at: http://localhost
- The backend API will be available at: http://localhost:4000 (and proxied as /api from the frontend)

To stop the system:
```sh
docker-compose down
```

### Option 2: Docker (Manual)

```sh
docker build -t qrms .
docker run -p 80:80 -p 4000:4000 qrms
```

---

## Usage
1. Open http://localhost in your browser.
2. Enter an IP address to scan.
3. View detected assets, vulnerabilities, risk heatmap, prioritization, and threat intelligence.
4. Add recommendations, export reports (PDF/CSV), and monitor risk evolution.
5. The system will schedule periodic scans and alert you to new threats automatically.

---

## API Keys
- **Shodan API Key:** `PPv207fG0kjk1xNr818CnECsWfkNWOMF`
- **NVD API Key:** `3bafed90-e81d-43e4-b9c7-1bf44e845ce4`

These are already integrated in the backend for real-time data.

---

## References
- ISO/IEC 27005:2022
- NIST SP 800-30 Rev.1
- SPDP Ecuador 2025
- CIS Controls v8

---

## License
This project is for educational and professional demonstration purposes. Use responsibly and in accordance with applicable laws and standards.
