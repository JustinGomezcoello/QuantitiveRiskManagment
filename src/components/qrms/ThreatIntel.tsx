import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Eye, Globe, MapPin, Server, Calendar, Activity } from "lucide-react";

interface ThreatIntelProps {
  ip: string;
  shodanData?: any;
}

export const ThreatIntel = ({ ip, shodanData }: ThreatIntelProps) => {
  // Si no hay datos, mostrar mensaje
  if (!shodanData) {
    return <div className="text-slate-400">No Shodan data available for {ip}</div>;
  }

  // Adaptar los campos a los posibles nombres reales de la API
  const country = shodanData.country_name || shodanData.country || "-";
  const city = shodanData.city || "-";
  const isp = shodanData.isp || shodanData.org || "-";
  const org = shodanData.org || "-";
  const ports = shodanData.ports || [];
  const lastSeen = shodanData.last_update || shodanData.lastSeen || "-";
  const services = (shodanData.data || []).map((s: any) => ({
    port: s.port,
    service: s.transport || s.product || "-",
    product: s.product || "-",
    version: s.version || "-"
  }));
  const riskScore = shodanData.risk || shodanData.riskScore || "-";
  const tags = shodanData.tags || [];
  // Extraer CVEs si existen en shodanData
  const cves = shodanData.cves || shodanData.vulnerabilities || [];

  return (
    <div className="space-y-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center text-white">
            <Eye className="h-5 w-5 mr-2 text-green-400" />
            Threat Intelligence - Shodan
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Geographic Information */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center space-x-2">
              <MapPin className="h-4 w-4 text-blue-400" />
              <div>
                <p className="text-slate-400 text-sm">Location</p>
                <p className="text-white">{city}, {country}</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Server className="h-4 w-4 text-purple-400" />
              <div>
                <p className="text-slate-400 text-sm">Provider</p>
                <p className="text-white">{isp}</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Calendar className="h-4 w-4 text-orange-400" />
              <div>
                <p className="text-slate-400 text-sm">Last scan</p>
                <p className="text-white">{lastSeen}</p>
              </div>
            </div>
          </div>

          {/* Exposed Services */}
          <div>
            <h4 className="text-sm font-medium text-slate-300 mb-2">Publicly Exposed Services:</h4>
            <div className="grid grid-cols-1 gap-2">
              {services.map((service, index) => (
                <div key={index} className="flex items-center justify-between p-2 bg-slate-700/50 rounded">
                  <div className="flex items-center space-x-3">
                    <Globe className="h-4 w-4 text-green-400" />
                    <span className="text-white">Port {service.port}/{service.service}</span>
                    <span className="text-slate-400">{service.product} {service.version}</span>
                  </div>
                  <Badge className="text-green-400 border-green-400 border" variant="outline">Public</Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Risk Assessment */}
          <Alert className="bg-orange-900/20 border-orange-700">
            <Activity className="h-4 w-4 text-orange-400" />
            <AlertDescription className="text-orange-300">
              <strong>Public Exposure Detected:</strong> This IP has {ports.length} ports 
              publicly exposed. Shodan Risk: {riskScore}/10
            </AlertDescription>
          </Alert>

          {/* Tags */}
          {tags.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-2">Classification Tags:</h4>
              <div className="flex flex-wrap gap-2">
                {tags.map((tag: string, index: number) => (
                  <Badge key={index} className="text-blue-400 border-blue-400 border" variant="outline">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* CVEs y Vulnerabilidades */}
          {cves.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-2">Vulnerabilidades detectadas (NVD):</h4>
              <div className="space-y-2">
                {cves.map((cve: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-slate-700/50 rounded">
                    <div className="flex flex-col">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.id || cve.CVE || cve.cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 font-semibold hover:underline"
                        title="Ver detalle en NVD"
                      >
                        {cve.id || cve.CVE || cve.cve}
                      </a>
                      <span className="text-slate-400 text-xs">{cve.summary || cve.description || "Sin resumen"}</span>
                    </div>
                    <div className="flex flex-col items-end">
                      <span className="text-xs text-slate-300">CVSS: {cve.score || cve.cvss || "-"}</span>
                      <span className="text-xs text-slate-300">Severidad: {cve.severity || "-"}</span>
                      <span className="text-xs text-slate-300">Fecha: {cve.published || cve.date || "-"}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Historical Data (placeholder) */}
          <Card className="bg-slate-700/50 border-slate-600">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm text-slate-300">Detection History</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">First detection:</span>
                  <span className="text-white">-</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Changes detected:</span>
                  <span className="text-white">-</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Historical ports:</span>
                  <span className="text-white">{ports.join(", ")}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
};
