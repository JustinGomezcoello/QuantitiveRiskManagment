import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  TrendingUp, 
  Network, 
  Eye,
  Database,
  Server,
  Globe,
  Activity,
  Target,
  Clock
} from "lucide-react";
import { DashboardStats } from "@/components/qrms/DashboardStats";
import { RiskMatrix } from "@/components/qrms/RiskMatrix";
import { AssetInventory } from "@/components/qrms/AssetInventory";
import { ScanProgress } from "@/components/qrms/ScanProgress";
import { ThreatIntel } from "@/components/qrms/ThreatIntel";
import { RiskPrioritizationTable } from "@/components/qrms/RiskPrioritizationTable";

const Index = () => {
  const [ip, setIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState("");
  const [scanData, setScanData] = useState(null);
  const [error, setError] = useState("");
  const [observations, setObservations] = useState({});
  const [reportLoading, setReportLoading] = useState(false);

  const API_URL = import.meta.env.VITE_API_URL;

  const handleScan = async () => {
    setLoading(true);
    setProgress(10);
    setCurrentStep("Ejecutando Nmap...");
    setError("");
    setScanData(null);
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
      });
      setProgress(60);
      setCurrentStep("Procesando resultados y consultando APIs...");
      if (!res.ok) throw new Error("Error en el escaneo");
      const data = await res.json();
      setProgress(100);
      setCurrentStep("¡Escaneo completo!");
      setScanData(data);
    } catch (err) {
      setError("Error en el escaneo: " + err.message);
    } finally {
      setLoading(false);
      setTimeout(() => setProgress(0), 2000);
    }
  };

  // Recuperar observaciones al cargar scanData
  useEffect(() => {
    if (scanData?.ip) {
      fetch(`${API_URL}/report/observations?ip=${encodeURIComponent(scanData.ip)}`)
        .then(res => res.json())
        .then(setObservations)
        .catch(() => setObservations({}));
    }
  }, [scanData?.ip]);

  // Guardar observación en backend
  const handleObservationChange = async (cve, value) => {
    setObservations(prev => ({ ...prev, [cve]: value }));
    if (scanData?.ip) {
      await fetch(`${API_URL}/report/observation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: scanData.ip, cve, observation: value })
      });
    }
  };

  // Exportar PDF
  const handleExportPDF = async () => {
    if (!scanData?.ip) return;
    setReportLoading(true);
    const res = await fetch(`${API_URL}/report/pdf?ip=${encodeURIComponent(scanData.ip)}`);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report_${scanData.ip}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setReportLoading(false);
  };

  // Exportar CSV
  const handleExportCSV = () => {
    if (!scanData?.activos) return;
    let csv = 'CVE,Score,Severity,Service,Observation\n';
    scanData.activos.forEach(a => {
      (a.cves || []).forEach(cve => {
        csv += `${cve.id},${cve.score || ''},${cve.severity || ''},"${a.name} ${a.product} ${a.version}","${observations[cve.id] || ''}"\n`;
      });
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report_${scanData.ip}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  // Adaptar datos para los componentes
  const vulnerabilities = scanData?.activos?.flatMap(a =>
    (a.cves || []).map(cve => ({
      cve: cve.id,
      cvss: cve.score,
      severity: cve.severity,
      service: `${a.name} ${a.product} ${a.version}`
    }))
  ) || [];

  const assets = scanData?.activos?.map(a => ({
    service: `${a.name} ${a.product}`,
    version: a.version,
    port: a.port,
    type: a.tipo?.toLowerCase() || "infrastructure",
    cia: `${a.cia.confidencialidad}/${a.cia.integridad}/${a.cia.disponibilidad}`,
    riskScore: a.riesgo,
    probability: a.probabilidad,
    impact: a.impacto
  })) || [];

  const dashboardStats = scanData ? {
    riskScore: Math.round(Math.max(...assets.map(a => a.riskScore || 0)) / 10),
    riskLevel: vulnerabilities.some(v => v.cvss >= 9) ? 'CRITICAL' : vulnerabilities.some(v => v.cvss >= 7) ? 'HIGH' : vulnerabilities.some(v => v.cvss >= 4) ? 'MEDIUM' : 'LOW',
    vulnerabilities,
    assets,
  } : null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-800">
      {/* Header */}
      <div className="border-b border-slate-700 bg-slate-800/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-400" />
              <div>
                <h1 className="text-2xl font-bold text-white">QRMS</h1>
                <p className="text-sm text-slate-300">Quantitative Risk Management System</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant="outline" className="text-green-400 border-green-400">
                <Activity className="h-3 w-3 mr-1" />
                System Active
              </Badge>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 py-8">
        {/* Scan Input Section */}
        <Card className="mb-8 bg-slate-800/50 border-slate-700 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center text-white">
              <Search className="h-5 w-5 mr-2 text-blue-400" />
              Quantitative Risk Assessment
            </CardTitle>
            <CardDescription className="text-slate-400">
              Enter an IP address to start automated vulnerability analysis and risk calculation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-4">
              <div className="flex-1">
                <Input
                  placeholder="e.g: 192.168.1.1 or 8.8.8.8"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-slate-400"
                  disabled={loading}
                />
              </div>
              <Button 
                onClick={handleScan}
                disabled={loading || !ip}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {loading ? (
                  <>
                    <Clock className="h-4 w-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Target className="h-4 w-4 mr-2" />
                    Start QRMS
                  </>
                )}
              </Button>
            </div>
            
            {loading && (
              <div className="mt-4 space-y-2">
                <ScanProgress progress={progress} currentStep={currentStep} />
                <div className="text-yellow-400 font-bold text-center mt-2">
                Deep scan in progress. This may take several minutes depending on the network and the services detected.
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results Section */}
        {scanData && (
          <Tabs defaultValue="dashboard" className="space-y-6">
            <TabsList className="bg-slate-800 border-slate-700">
              <TabsTrigger value="dashboard" className="data-[state=active]:bg-blue-600">
                <TrendingUp className="h-4 w-4 mr-2" />
                Dashboard
              </TabsTrigger>
              <TabsTrigger value="assets" className="data-[state=active]:bg-blue-600">
                <Database className="h-4 w-4 mr-2" />
                Asset Valuation
              </TabsTrigger>
              <TabsTrigger value="risk-identification" className="data-[state=active]:bg-blue-600">
                <TrendingUp className="h-4 w-4 mr-2" />
                Risk Identification
              </TabsTrigger>
              <TabsTrigger value="risk-matrix" className="data-[state=active]:bg-blue-600">
                <Network className="h-4 w-4 mr-2" />
                Risk Matrix
              </TabsTrigger>
              <TabsTrigger value="intel" className="data-[state=active]:bg-blue-600">
                <Eye className="h-4 w-4 mr-2" />
                Threat Intel
              </TabsTrigger>
            </TabsList>

            <TabsContent value="dashboard" className="space-y-6">
              <DashboardStats scanResults={dashboardStats} />
              
              <Alert className="bg-red-900/20 border-red-700">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <AlertDescription className="text-red-300">
                  <strong>{dashboardStats.riskLevel} Risk</strong> detected on {ip}. 
                  Found {dashboardStats.vulnerabilities.length} critical vulnerabilities requiring immediate attention.
                </AlertDescription>
              </Alert>
            </TabsContent>

            <TabsContent value="assets">
              {assets.length === 0 ? (
                <div className="text-center text-slate-400 py-8">No assets detected for this IP.</div>
              ) : (
                <AssetInventory assets={assets} />
              )}
            </TabsContent>

            <TabsContent value="risk-identification">
              <RiskPrioritizationTable assets={scanData?.activos || []} />
            </TabsContent>

            <TabsContent value="risk-matrix">
              <RiskMatrix assets={assets} vulnerabilities={vulnerabilities} />
            </TabsContent>

            <TabsContent value="intel">
              <ThreatIntel ip={ip} shodanData={scanData.shodan} />
            </TabsContent>
          </Tabs>
        )}

        {/* Info Cards for Initial State */}
        {!scanData && !loading && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader className="pb-4">
                <div className="flex items-center space-x-2">
                  <Network className="h-5 w-5 text-blue-400" />
                  <CardTitle className="text-lg text-white">Automated Scanning</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-sm">
                  Nmap + Shodan API + NVD for complete asset and vulnerability detection
                </p>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader className="pb-4">
                <div className="flex items-center space-x-2">
                  <TrendingUp className="h-5 w-5 text-green-400" />
                  <CardTitle className="text-lg text-white">Quantitative Analysis</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-sm">
                  Risk calculation based on CVSS, CIA and business criticality according to ISO 27005
                </p>
              </CardContent>
            </Card>

            <Card className="bg-slate-800/50 border-slate-700">
              <CardHeader className="pb-4">
                <div className="flex items-center space-x-2">
                  <Globe className="h-5 w-5 text-purple-400" />
                  <CardTitle className="text-lg text-white">Real-Time Data</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-sm">
                  Official Shodan and NVD APIs for up-to-date threat information
                </p>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default Index;
