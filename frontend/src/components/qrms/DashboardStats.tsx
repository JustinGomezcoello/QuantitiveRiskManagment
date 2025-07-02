
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Clock,
  Target,
  Activity
} from "lucide-react";

interface DashboardStatsProps {
  scanResults: any;
}

export const DashboardStats = ({ scanResults }: DashboardStatsProps) => {
  const getRiskColor = (level: string) => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-600';
      case 'HIGH': return 'bg-orange-600';
      case 'MEDIUM': return 'bg-yellow-600';
      case 'LOW': return 'bg-green-600';
      default: return 'bg-gray-600';
    }
  };

  const criticalVulns = scanResults.vulnerabilities.filter((v: any) => v.severity === 'CRITICAL').length;
  const highVulns = scanResults.vulnerabilities.filter((v: any) => v.severity === 'HIGH').length;
  
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">Risk Score</CardTitle>
          <TrendingUp className="h-4 w-4 text-red-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-white mb-2">{scanResults.riskScore}/10</div>
          <div className="flex items-center space-x-2">
            <Badge className={`${getRiskColor(scanResults.riskLevel)} text-white`}>
              {scanResults.riskLevel}
            </Badge>
          </div>
          <Progress value={scanResults.riskScore * 10} className="mt-2" />
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">Vulnerabilities</CardTitle>
          <AlertTriangle className="h-4 w-4 text-orange-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-white mb-2">{scanResults.vulnerabilities.length}</div>
          <div className="text-xs text-slate-400">
            {criticalVulns} critical, {highVulns} high
          </div>
          <div className="flex space-x-1 mt-2">
            {Array(criticalVulns).fill(0).map((_, i) => (
              <div key={i} className="w-2 h-2 bg-red-500 rounded-full"></div>
            ))}
            {Array(highVulns).fill(0).map((_, i) => (
              <div key={i} className="w-2 h-2 bg-orange-500 rounded-full"></div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">Scanned Assets</CardTitle>
          <Target className="h-4 w-4 text-blue-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-white mb-2">{scanResults.assets.length}</div>
          <div className="text-xs text-slate-400">
            Services detected
          </div>
          <div className="flex items-center mt-2">
            <Shield className="h-3 w-3 text-green-400 mr-1" />
            <span className="text-xs text-green-400">100% Inventoried</span>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">Scan Time</CardTitle>
          <Clock className="h-4 w-4 text-purple-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-white mb-2">2.4m</div>
          <div className="text-xs text-slate-400">
            Last updated
          </div>
          <div className="flex items-center mt-2">
            <Activity className="h-3 w-3 text-green-400 mr-1" />
            <span className="text-xs text-green-400">Active monitoring</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
