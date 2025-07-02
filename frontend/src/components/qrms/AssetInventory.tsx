
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Server, Database, Globe, Shield } from "lucide-react";

interface Asset {
  service: string;
  version: string;
  port: number;
  type: string;
  cia: string;
}

interface AssetInventoryProps {
  assets: Asset[];
}

export const AssetInventory = ({ assets }: AssetInventoryProps) => {
  const getAssetIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'infrastructure': return <Server className="h-4 w-4" />;
      case 'database': return <Database className="h-4 w-4" />;
      case 'application': return <Globe className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'infrastructure': return 'bg-blue-600';
      case 'database': return 'bg-purple-600';
      case 'application': return 'bg-green-600';
      default: return 'bg-gray-600';
    }
  };

  const getCIALevel = (cia: string) => {
    const [c, i, a] = cia.split('/').map(Number);
    const avg = (c + i + a) / 3;
    if (avg >= 4) return { label: 'HIGH', color: 'bg-red-600' };
    if (avg >= 3) return { label: 'MEDIUM', color: 'bg-yellow-600' };
    return { label: 'LOW', color: 'bg-green-600' };
  };

  return (
    <Card className="bg-slate-800/50 border-slate-700">
      <CardHeader>
        <CardTitle className="flex items-center text-white">
          <Server className="h-5 w-5 mr-2 text-blue-400" />
          Digital Asset Inventory
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow className="border-slate-700">
              <TableHead className="text-slate-300">Service</TableHead>
              <TableHead className="text-slate-300">Version</TableHead>
              <TableHead className="text-slate-300">Port</TableHead>
              <TableHead className="text-slate-300">Type</TableHead>
              <TableHead className="text-slate-300">CIA</TableHead>
              <TableHead className="text-slate-300">Classification</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assets.map((asset, index) => {
              const ciaLevel = getCIALevel(asset.cia);
              return (
                <TableRow key={index} className="border-slate-700">
                  <TableCell className="text-white font-medium">
                    <div className="flex items-center space-x-2">
                      {getAssetIcon(asset.type)}
                      <span>{asset.service}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-slate-300">{asset.version}</TableCell>
                  <TableCell className="text-slate-300">{asset.port}/tcp</TableCell>
                  <TableCell>
                    <Badge className={`${getTypeColor(asset.type)} text-white`}>
                      {asset.type}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-slate-300 font-mono">{asset.cia}</TableCell>
                  <TableCell>
                    <Badge className={`${ciaLevel.color} text-white`}>
                      {ciaLevel.label}
                    </Badge>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};
