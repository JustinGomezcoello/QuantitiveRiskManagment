
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Network, TrendingUp } from "lucide-react";

interface RiskMatrixProps {
  assets: any[];
  vulnerabilities: any[];
}

export const RiskMatrix = ({ assets, vulnerabilities }: RiskMatrixProps) => {
  // Risk matrix 5x5 grid
  const getRiskLevel = (probability: number, impact: number) => {
    const risk = probability * impact;
    if (risk >= 20) return { level: 'CRITICAL', color: 'bg-red-600', textColor: 'text-red-100' };
    if (risk >= 15) return { level: 'HIGH', color: 'bg-orange-600', textColor: 'text-orange-100' };
    if (risk >= 10) return { level: 'MEDIUM', color: 'bg-yellow-600', textColor: 'text-yellow-100' };
    if (risk >= 5) return { level: 'LOW', color: 'bg-green-600', textColor: 'text-green-100' };
    return { level: 'VERY LOW', color: 'bg-blue-600', textColor: 'text-blue-100' };
  };

  // Position assets on matrix based on their risk profile
  const positionedAssets = assets.map((asset, index) => {
    const vuln = vulnerabilities.find(v => v.service === asset.service);
    const probability = vuln ? Math.ceil(vuln.cvss / 2) : 1; // Scale CVSS to 1-5
    const [c, i, a] = asset.cia.split('/').map(Number);
    const impact = Math.ceil((c + i + a) / 3); // Average CIA to 1-5
    
    return {
      ...asset,
      probability,
      impact,
      riskScore: probability * impact,
      x: probability,
      y: impact
    };
  });

  return (
    <div className="space-y-6">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="flex items-center text-white">
            <Network className="h-5 w-5 mr-2 text-purple-400" />
            Risk Heat Matrix 5x5
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Risk Matrix Grid */}
          <div className="grid grid-cols-6 gap-1 mb-6">
            {/* Header row */}
            <div className="text-center text-slate-400 text-sm font-medium p-2"></div>
            {[1, 2, 3, 4, 5].map(prob => (
              <div key={prob} className="text-center text-slate-400 text-sm font-medium p-2">
                Prob {prob}
              </div>
            ))}
            
            {/* Matrix rows */}
            {[5, 4, 3, 2, 1].map(impact => (
              <div key={impact} className="contents">
                <div className="text-center text-slate-400 text-sm font-medium p-2 flex items-center justify-center">
                  Impact {impact}
                </div>
                {[1, 2, 3, 4, 5].map(prob => {
                  const riskInfo = getRiskLevel(prob, impact);
                  const assetsInCell = positionedAssets.filter(a => a.x === prob && a.y === impact);
                  
                  return (
                    <div
                      key={`${prob}-${impact}`}
                      className={`${riskInfo.color} p-3 min-h-[60px] flex flex-col items-center justify-center relative`}
                    >
                      <span className={`text-xs font-bold ${riskInfo.textColor}`}>
                        {prob * impact}
                      </span>
                      {assetsInCell.map((asset, idx) => (
                        <div
                          key={idx}
                          className="absolute top-0 right-0 w-2 h-2 bg-white rounded-full transform translate-x-1 -translate-y-1"
                          title={asset.service}
                        />
                      ))}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Legend */}
          <div className="flex flex-wrap gap-2 mb-4">
            <Badge className="bg-red-600 text-white">CRITICAL (20-25)</Badge>
            <Badge className="bg-orange-600 text-white">HIGH (15-19)</Badge>
            <Badge className="bg-yellow-600 text-white">MEDIUM (10-14)</Badge>
            <Badge className="bg-green-600 text-white">LOW (5-9)</Badge>
            <Badge className="bg-blue-600 text-white">VERY LOW (1-4)</Badge>
          </div>

          {/* Asset Risk Summary */}
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-slate-300 mb-3">Asset Risk Summary:</h4>
            {positionedAssets
              .sort((a, b) => b.riskScore - a.riskScore)
              .map((asset, index) => {
                const riskInfo = getRiskLevel(asset.probability, asset.impact);
                return (
                  <div key={index} className="flex items-center justify-between p-2 bg-slate-700/50 rounded">
                    <div className="flex items-center space-x-3">
                      <TrendingUp className="h-4 w-4 text-blue-400" />
                      <span className="text-white font-medium">{asset.service}</span>
                      <span className="text-slate-400 text-sm">({asset.version})</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-300 text-sm">Risk: {asset.riskScore}</span>
                      <Badge className={`${riskInfo.color} text-white`}>
                        {riskInfo.level}
                      </Badge>
                    </div>
                  </div>
                );
              })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
