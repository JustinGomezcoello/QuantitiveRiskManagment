import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, AlertTriangle, Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

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
  return (
    <div className="space-y-4">
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
                          <Info className="inline h-4 w-4 ml-1 text-blue-400 cursor-pointer align-middle" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent className="bg-slate-800 border-slate-600 text-white max-w-xs">
                        {getTreatmentDescription(asset.tratamiento)}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </TableCell>
                <TableCell className="align-top text-center px-6 py-4">
                  {asset.shodanExposed ? (
                    <Badge className="bg-green-600 text-white px-3 py-1 text-base">Public</Badge>
                  ) : (
                    <Badge className="bg-slate-600 text-white px-3 py-1 text-base">Internal</Badge>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}; 