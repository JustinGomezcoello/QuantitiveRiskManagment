
import { Progress } from "@/components/ui/progress";
import { Card, CardContent } from "@/components/ui/card";
import { Loader2 } from "lucide-react";

interface ScanProgressProps {
  progress: number;
  currentStep: string;
}

export const ScanProgress = ({ progress, currentStep }: ScanProgressProps) => {
  return (
    <Card className="bg-slate-700/50 border-slate-600">
      <CardContent className="pt-6">
        <div className="flex items-center space-x-3 mb-3">
          <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
          <span className="text-sm text-slate-300">{currentStep}</span>
        </div>
        <Progress value={progress} className="h-2" />
        <div className="flex justify-between text-xs text-slate-400 mt-2">
          <span>Scan progress</span>
          <span>{progress}%</span>
        </div>
      </CardContent>
    </Card>
  );
};
