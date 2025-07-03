import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, AlertTriangle, Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useState } from "react";

interface CVE {
  id: string;
  score?: number;
  severity?: string;
  published?: string;
  summary?: string;
}

interface Asset {
  service: string;
  version: string;
  cia: string;
  probabilidad: number;
  impacto: number;
  riesgo: number;
  tratamiento: string;
  cves: CVE[];
  shodanExposed?: boolean;
}

interface RiskPrioritizationTableProps {
  assets: Asset[];
}

function getRiskLevelColor(risk: number) {
  if (risk >= 20) return "bg-red-600 text-white"; // Critical
  if (risk >= 15) return "bg-orange-500 text-white"; // High
  if (risk >= 10) return "bg-yellow-500 text-black"; // Medium
  if (risk >= 5) return "bg-green-500 text-white"; // Low
  return "bg-blue-500 text-white"; // Very Low
}

function getTreatmentDescription(treatment: string) {
  switch (treatment) {
    case "AVOID":
      return (
        <div>
          <div className="font-bold text-red-400 mb-1">AVOID</div>
          <div className="mb-1">Reason: Critical risk detected. The asset poses an unacceptable threat to the organization.</div>
          <div className="mb-1">When: No feasible mitigation exists, or the asset is not essential for business operations.</div>
          <div className="mb-1">Solution: Remove or isolate the asset from the network immediately. Decommission or replace with a secure alternative.</div>
        </div>
      );
    case "MITIGATE":
      return (
        <div>
          <div className="font-bold text-orange-400 mb-1">MITIGATE</div>
          <div className="mb-1">Reason: Vulnerabilities detected, but patches or mitigations are available.</div>
          <div className="mb-1">When: The asset is critical for business, but risk can be reduced.</div>
          <div className="mb-1">Solution: Apply security patches, update software, close unnecessary ports, harden configurations, and monitor for threats.</div>
        </div>
      );
    case "TRANSFER":
      return (
        <div>
          <div className="font-bold text-yellow-400 mb-1">TRANSFER</div>
          <div className="mb-1">Reason: Risk cannot be fully mitigated internally.</div>
          <div className="mb-1">When: The organization lacks resources or expertise to address the risk.</div>
          <div className="mb-1">Solution: Outsource the service to a trusted third party, use cloud solutions, or obtain cyber insurance.</div>
        </div>
      );
    case "ACCEPT":
    default:
      return (
        <div>
          <div className="font-bold text-green-400 mb-1">ACCEPT</div>
          <div className="mb-1">Reason: Low risk, no known exploit, or the asset is not exposed externally.</div>
          <div className="mb-1">When: The cost of mitigation exceeds the potential impact.</div>
          <div className="mb-1">Solution: Document the risk, monitor periodically, and review if the threat landscape changes.</div>
        </div>
      );
  }
}

export const RiskPrioritizationTable = ({ assets }: RiskPrioritizationTableProps) => {
  const [observations, setObservations] = useState<{ [key: number]: string }>({});
  const [recommendations, setRecommendations] = useState("");
  const [resolved, setResolved] = useState<{ [key: number]: boolean }>({});
  const [resolveMsg, setResolveMsg] = useState<{ [key: number]: string }>({});

  // CSV Export
  const handleExportCSV = () => {
    let csv = 'Asset/Service,Version,Detected CVEs,Probability (CVSS),CIA,Impact (CIA + Criticality),Total Risk,Suggested Treatment,External Accessibility,Observations,Recommendations\n';
    assets.filter(asset => (asset.riesgo && asset.riesgo > 0) || (asset.cves && asset.cves.length > 0)).forEach((asset, idx) => {
      // Asset/Service
      const service = asset.service || '-';
      // Version
      const version = asset.version || '-';
      // Detected CVEs
      const detectedCVEs = asset.cves && asset.cves.length > 0 ? asset.cves.map(cve => cve.id).join(', ') : '-';
      // Probability (CVSS)
      const probability = (asset.probabilidad !== undefined && asset.probabilidad !== null) ? asset.probabilidad : '-';
      // CIA
      let ciaString = '-';
      if (typeof asset.cia === 'string') {
        ciaString = asset.cia;
      } else if (
        asset.cia &&
        typeof asset.cia === 'object' &&
        ('confidentiality' in asset.cia || 'confidencialidad' in asset.cia || 'integrity' in asset.cia || 'integridad' in asset.cia || 'availability' in asset.cia || 'disponibilidad' in asset.cia)
      ) {
        const c = (asset.cia as any).confidentiality ?? (asset.cia as any).confidencialidad ?? '-';
        const i = (asset.cia as any).integrity ?? (asset.cia as any).integridad ?? '-';
        const a = (asset.cia as any).availability ?? (asset.cia as any).disponibilidad ?? '-';
        ciaString = `${c}/${i}/${a}`;
      }
      // Impact
      const impact = (asset.impacto !== undefined && asset.impacto !== null) ? asset.impacto : '-';
      // Total Risk
      const totalRisk = (asset.riesgo !== undefined && asset.riesgo !== null) ? asset.riesgo : '-';
      // Suggested Treatment
      const treatment = asset.tratamiento || '-';
      // External Accessibility
      const external = asset.shodanExposed ? 'Public' : 'Internal';
      // Observations
      const observation = observations[idx] || '';
      // Recommendations (same for all rows)
      const recs = recommendations || '';
      csv += `"${service}","${version}","${detectedCVEs}","${probability}","${ciaString}","${impact}","${totalRisk}","${treatment}","${external}","${observation}","${recs}"
`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'risk_identification.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  // Risk action explanations and links
  const riskActionInfo: Record<string, { desc: string; link: string; linkLabel: string }> = {
    AVOID: {
      desc: 'Avoiding risk means eliminating the activity or asset that exposes the organization to the risk. This is appropriate when the risk is unacceptable and cannot be mitigated or transferred. Example: Discontinue a vulnerable service.',
      link: 'https://www.techtarget.com/searchsecurity/definition/risk-avoidance',
      linkLabel: 'NIST Glossary: Risk Avoidance',
    },
    MITIGATE: {
      desc: 'Mitigating risk involves taking actions to reduce the likelihood or impact of the risk. This can include applying patches, improving configurations, or implementing additional controls.',
      link: 'https://www.indeed.com/career-advice/career-development/risk-mitigation-strategies',
      linkLabel: 'CISA: Mitigating Cybersecurity Risks',
    },
    TRANSFER: {
      desc: 'Transferring risk means shifting the risk to a third party, such as through insurance or outsourcing. This is suitable when the organization cannot fully mitigate the risk internally.',
      link: 'https://corporatefinanceinstitute.com/resources/career-map/sell-side/risk-management/risk-transfer/',
      linkLabel: 'NIST: Risk Management (Transfer)',
    },
    ACCEPT: {
      desc: 'Accepting risk means acknowledging the risk and choosing not to take any action, typically because the cost of mitigation exceeds the potential impact or the risk is within tolerance.',
      link: 'https://www.investopedia.com/terms/a/accepting-risk.asp',
      linkLabel: 'NIST Glossary: Risk Acceptance',
    },
  };

  function handleResolve(idx: number, action: string) {
    setResolved(prev => ({ ...prev, [idx]: true }));
    let msg = '';
    switch (action) {
      case 'AVOID':
        msg = 'Risk marked as avoided. Please ensure the asset is discontinued or isolated.';
        break;
      case 'MITIGATE':
        msg = 'Risk marked as mitigated. Please apply the recommended patches and controls.';
        break;
      case 'TRANSFER':
        msg = 'Risk marked as transferred. Please coordinate with your third-party provider or insurer.';
        break;
      case 'ACCEPT':
        msg = 'Risk marked as accepted. Please document and monitor this risk periodically.';
        break;
      default:
        msg = 'Risk marked as resolved.';
    }
    setResolveMsg(prev => ({ ...prev, [idx]: msg }));
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end mb-2">
        <button
          className="bg-blue-700 hover:bg-blue-800 text-white font-bold py-2 px-4 rounded"
          onClick={handleExportCSV}
        >
          Export to CSV
        </button>
      </div>
      <div>
        <h3 className="text-2xl font-bold text-white mb-1 flex items-center">
          <AlertTriangle className="h-5 w-5 text-blue-400 mr-2" />
          Risk Prioritization Table
        </h3>
        <p className="text-blue-200 text-base mb-4 max-w-2xl">
          This table lists all detected assets and their associated risks, vulnerabilities (CVEs), and recommended risk treatment strategies. Use this view to prioritize mitigation actions based on quantitative risk analysis.
        </p>
        <div className="mb-4 p-4 rounded-lg bg-slate-800/80 border border-slate-700 text-white">
          <h4 className="font-bold mb-2 text-lg">Risk Treatment Strategies</h4>
          <ul className="space-y-2 text-base">
            <li><span className="font-bold text-red-400">AVOID:</span> <span className="font-semibold">Reason:</span> Critical risk detected. <span className="font-semibold">When:</span> No feasible mitigation exists, or the asset is not essential. <span className="font-semibold">Action:</span> Remove or isolate the asset from the network immediately.</li>
            <li><span className="font-bold text-orange-400">MITIGATE:</span> <span className="font-semibold">Reason:</span> Vulnerabilities detected, but patches or mitigations are available. <span className="font-semibold">When:</span> The asset is critical, but risk can be reduced. <span className="font-semibold">Action:</span> Apply patches, update, close unnecessary ports, harden configurations, monitor for threats.</li>
            <li><span className="font-bold text-yellow-400">TRANSFER:</span> <span className="font-semibold">Reason:</span> Risk cannot be fully mitigated internally. <span className="font-semibold">When:</span> Lack of resources or expertise. <span className="font-semibold">Action:</span> Outsource to a trusted third party, use cloud, or obtain cyber insurance.</li>
            <li><span className="font-bold text-green-400">ACCEPT:</span> <span className="font-semibold">Reason:</span> Low risk, no known exploit, or not exposed externally. <span className="font-semibold">When:</span> Cost of mitigation exceeds potential impact. <span className="font-semibold">Action:</span> Document the risk, monitor periodically, review if threat landscape changes.</li>
          </ul>
        </div>
      </div>
      <div className="rounded-lg shadow-lg overflow-x-auto border border-slate-200 bg-white">
        <Table className="min-w-full text-base">
          <TableHeader>
            <TableRow className="bg-blue-900/90">
              <TableHead className="text-white font-bold px-6 py-4">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>Asset/Service</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">The detected digital asset or service (name and version).</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>Detected CVEs</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">List of vulnerabilities (CVEs) found for this asset, from NVD API.</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4 text-center">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>Probability (CVSS)</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">Highest CVSS score among detected CVEs for the asset.</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4 text-center">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>Impact (CIA + Criticality)</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">Average of Confidentiality, Integrity, Availability (CIA) plus business criticality (scale 1-5).</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4 text-center">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>Total Risk</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">Calculated as Probability × Impact.</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4 text-center">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>Suggested Treatment</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">Recommended risk treatment strategy based on risk level and mitigation options.</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4 text-center">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>External Accessibility</span>
                    </TooltipTrigger>
                    <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">Whether the asset is exposed to the internet (from Shodan data).</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableHead>
              <TableHead className="text-white font-bold px-6 py-4 text-center">Observations</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assets.filter(asset => (asset.riesgo && asset.riesgo > 0) || (asset.cves && asset.cves.length > 0)).map((asset, idx) => (
              <TableRow key={idx} className={idx % 2 === 0 ? "bg-slate-100" : "bg-white"}>
                <TableCell className="font-semibold text-slate-900 align-top px-6 py-4">
                  {asset.service}
                  <span className="text-slate-500 text-xs ml-1">({asset.version || "-"})</span>
                </TableCell>
                <TableCell className="align-top px-6 py-4">
                  {asset.cves && asset.cves.length > 0 ? (
                    <ul className="list-disc pl-4 space-y-1">
                      {asset.cves.map((cve, cidx) => (
                        <li key={cidx}>
                          {cve.id && typeof cve.id === 'string' && cve.id.startsWith('CVE-') ? (
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <a
                                    href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-700 hover:underline flex items-center font-semibold"
                                  >
                                    {cve.id}
                                    <ExternalLink className="h-3 w-3 ml-1 inline" />
                                  </a>
                                </TooltipTrigger>
                                <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">
                                  <div className="font-bold mb-1">{cve.id}</div>
                                  <div className="text-xs">{cve.summary || "No summary available."}</div>
                                  <div className="text-xs mt-1">CVSS: {cve.score ?? "N/A"} | Severity: {cve.severity ?? "N/A"}</div>
                                  <div className="text-xs">Published: {cve.published ?? "N/A"}</div>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          ) : (
                            <span className="text-slate-400 text-xs">N/A</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="text-slate-400 text-xs">No CVEs</span>
                  )}
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  {asset.probabilidad && asset.probabilidad > 0 ? asset.probabilidad.toFixed(1) : "N/A"}
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  {asset.impacto && asset.impacto > 0 ? asset.impacto.toFixed(1) : "N/A"}
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  <Badge className={`font-bold px-3 py-1 text-base ${getRiskLevelColor(asset.riesgo)}`}
                    >
                    {asset.riesgo && asset.riesgo > 0 ? asset.riesgo.toFixed(1) : "N/A"}
                  </Badge>
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span>
                          <Badge className={`capitalize px-3 py-1 text-base ${asset.tratamiento === "AVOID" ? "bg-red-700 text-white" : asset.tratamiento === "MITIGATE" ? "bg-orange-600 text-white" : asset.tratamiento === "TRANSFER" ? "bg-yellow-600 text-black" : "bg-green-700 text-white"}`}>{asset.tratamiento}</Badge>
                        </span>
                      </TooltipTrigger>
                      <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">
                        <div className="mb-2">{riskActionInfo[asset.tratamiento]?.desc}</div>
                        <a
                          href={riskActionInfo[asset.tratamiento]?.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 underline text-xs"
                        >
                          {riskActionInfo[asset.tratamiento]?.linkLabel}
                        </a>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                  <button
                    className={`ml-2 mt-2 px-3 py-1 rounded font-bold ${resolved[idx] ? 'bg-green-400 text-white cursor-not-allowed' : 'bg-blue-700 hover:bg-blue-800 text-white'}`}
                    onClick={() => handleResolve(idx, asset.tratamiento)}
                    disabled={resolved[idx]}
                  >
                    {resolved[idx] ? 'Resolved' : 'Apply'}
                  </button>
                  {resolved[idx] && (
                    <div className="mt-2 text-green-700 text-xs font-semibold">{resolveMsg[idx]}</div>
                  )}
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  {asset.shodanExposed ? (
                    <Badge className="bg-green-600 text-white px-3 py-1 text-base">Public</Badge>
                  ) : (
                    <Badge className="bg-slate-600 text-white px-3 py-1 text-base">Internal</Badge>
                  )}
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  <textarea
                    className="w-full bg-slate-100 border border-slate-300 rounded p-1 text-sm"
                    value={observations[idx] || ''}
                    onChange={e => setObservations({ ...observations, [idx]: e.target.value })}
                    placeholder="Add your observation..."
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="mt-6">
        <h4 className="text-lg font-bold text-white mb-2">Recommendations</h4>
        <textarea
          className="w-full bg-slate-100 border border-slate-300 rounded p-2 text-base"
          rows={3}
          value={recommendations}
          onChange={e => setRecommendations(e.target.value)}
          placeholder="Enter general suggestions or insights here..."
        />
      </div>
    </div>
  );
}; 