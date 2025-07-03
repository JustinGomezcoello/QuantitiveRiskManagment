// ----------------------------------------------------------------------------------
// AssetInventory.tsx - Developer Documentation
// ----------------------------------------------------------------------------------
/**
 * ORIGIN OF LISTED SERVICES:
 * All services displayed in the table are discovered automatically during a network scan.
 * The backend uses tools like Nmap and threat intelligence APIs (e.g., Shodan, NVD) to detect
 * open ports, running services, and their versions for the target IP address. The results are
 * sent to the frontend as an array of asset objects, each representing a detected service.
 *
 * CLASSIFICATION COLUMN CALCULATION:
 * The 'classification' column is determined by calculating the average of the CIA (Confidentiality,
 * Integrity, Availability) values for each asset. The logic is as follows:
 *   - HIGH: Average CIA ≥ 4
 *   - MEDIUM: Average CIA ≥ 3 and < 4
 *   - LOW: Average CIA < 3
 * This provides a quick visual indicator of the asset's overall criticality based on security principles.
 *
 * COLUMN MEANINGS:
 * - port: The network port number where the service was detected (e.g., 80/tcp, 443/tcp).
 * - type: The type of protocol or technology identified (e.g., HTTP, SSH, FTP, database, etc.).
 * - cia: The criticality level of the asset, based on the principles of Confidentiality, Integrity, and Availability (CIA).
 *        This is shown as a numeric triplet (e.g., 5/5/4) and is assigned according to a criteria table based on asset type.
 * - classification: The assigned category (HIGH, MEDIUM, LOW) reflecting the asset's overall criticality, calculated from the CIA average.
 *
 * NOTE: This documentation is for developer reference only and does not affect runtime logic.
 */
// ----------------------------------------------------------------------------------

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
          Asset Valuation
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-6 p-4 rounded-lg bg-slate-800/80 border border-slate-700 text-white text-base space-y-3">
          <div className="font-bold mb-2">How is each column value obtained?</div>
          <div>
            <span className="font-bold">1. Port:</span>
            <ul className="list-disc pl-6 mt-1">
              <li><span className="font-semibold">Origin:</span> The port number is obtained from the network scan results performed by the backend.</li>
              <li><span className="font-semibold">Detection:</span> The backend uses tools like Nmap to scan the target IP and detect open ports. Each detected service includes the port where it was found.</li>
              <li><span className="font-semibold">How it reaches the frontend:</span> The backend sends an object for each asset with the <code>port</code> property (e.g., 80, 443, 135).</li>
            </ul>
          </div>
          <div>
            <span className="font-bold">2. Type:</span>
            <ul className="list-disc pl-6 mt-1">
              <li><span className="font-semibold">Origin:</span> The type of service or technology is determined by the backend.</li>
              <li><span className="font-semibold">Detection:</span> The backend analyzes the detected service name (e.g., "nginx", "mysql", "http") and classifies it as infrastructure, database, application, etc., using the <code>classifyService</code> function.</li>
              <li><span className="font-semibold">How it reaches the frontend:</span> The backend sends the <code>type</code> property for each asset, which is displayed in the corresponding column.</li>
            </ul>
          </div>
          <div>
            <span className="font-bold">3. CIA:</span>
            <ul className="list-disc pl-6 mt-1">
              <li><span className="font-semibold">Origin:</span> CIA values (Confidentiality, Integrity, Availability) are calculated by the backend.</li>
              <li><span className="font-semibold">Calculation:</span> The backend uses the <code>calculateCIA</code> function, which assigns numeric values to each principle (e.g., 5/5/4) based on asset type, using a criteria table.</li>
              <li><span className="font-semibold">How it reaches the frontend:</span> The backend sends a <code>cia</code> object with <code>confidentiality</code>, <code>integrity</code>, and <code>availability</code> properties. The frontend concatenates and displays them as a triplet (e.g., 5/5/4).</li>
            </ul>
          </div>
          <div>
            <span className="font-bold">4. Classification:</span>
            <ul className="list-disc pl-6 mt-1">
              <li><span className="font-semibold">Origin:</span> Calculated in the frontend.</li>
              <li><span className="font-semibold">Calculation:</span> The frontend takes the CIA values, calculates their average, and assigns a category:
                <ul className="list-disc pl-6 mt-1">
                  <li><span className="font-bold">HIGH:</span> Average CIA ≥ 4</li>
                  <li><span className="font-bold">MEDIUM:</span> Average CIA ≥ 3 and &lt; 4</li>
                  <li><span className="font-bold">LOW:</span> Average CIA &lt; 3</li>
                </ul>
              </li>
              <li><span className="font-semibold">How it is displayed:</span> The frontend shows the resulting classification in the "Classification" column.</li>
            </ul>
          </div>
        </div>
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
