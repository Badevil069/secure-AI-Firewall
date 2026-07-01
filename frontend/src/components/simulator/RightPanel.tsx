"use client";

import { useSecurityStore } from "@/store/useSecurityStore";
import { cn, severityColor, decisionColor, categoryIcon } from "@/lib/utils";
import { AlertTriangle, CheckCircle2, XCircle, Eye, Fingerprint, ShieldAlert } from "lucide-react";

export default function RightPanel() {
  const { currentAnalysis, isAnalyzing } = useSecurityStore();

  if (!currentAnalysis && !isAnalyzing) {
    return (
      <div className="flex flex-col h-full">
        <div className="px-4 py-3 border-b border-[#151d2e] flex items-center gap-2">
          <Eye className="w-4 h-4 text-violet-400" />
          <span className="text-sm font-semibold text-white">Threat Analysis</span>
        </div>
        <div className="flex-1 flex items-center justify-center px-4">
          <div className="text-center">
            <ShieldAlert className="w-10 h-10 text-slate-700 mx-auto mb-3" />
            <p className="text-xs text-slate-500">Submit a prompt to see the<br />real-time threat analysis.</p>
          </div>
        </div>
      </div>
    );
  }

  if (isAnalyzing) {
    return (
      <div className="flex flex-col h-full">
        <div className="px-4 py-3 border-b border-[#151d2e] flex items-center gap-2">
          <Eye className="w-4 h-4 text-violet-400" />
          <span className="text-sm font-semibold text-white">Threat Analysis</span>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-10 h-10 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin mx-auto mb-3" />
            <p className="text-xs text-blue-400 font-medium">Analyzing threat...</p>
          </div>
        </div>
      </div>
    );
  }

  const a = currentAnalysis!;
  const isBlocked = a.decision === "BLOCK";
  const isWarn = a.decision === "WARN";

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#151d2e] flex items-center gap-2">
        <Eye className="w-4 h-4 text-violet-400" />
        <span className="text-sm font-semibold text-white">Threat Analysis</span>
        {a.attack_id && (
          <span className="ml-auto text-[10px] font-mono text-slate-500 bg-slate-800/50 px-1.5 py-0.5 rounded">
            {a.attack_id}
          </span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {/* Decision Banner */}
        <div className={cn(
          "rounded-lg p-3 border text-center animate-fade-in-up",
          isBlocked ? "bg-red-500/10 border-red-500/30 glow-red" :
          isWarn ? "bg-yellow-500/10 border-yellow-500/30 glow-yellow" :
          "bg-emerald-500/10 border-emerald-500/30 glow-green"
        )}>
          <div className="text-2xl mb-1">
            {isBlocked ? "🚨" : isWarn ? "⚠️" : "✅"}
          </div>
          <div className={cn(
            "text-sm font-bold uppercase tracking-wider",
            isBlocked ? "text-red-400" : isWarn ? "text-yellow-400" : "text-emerald-400"
          )}>
            {isBlocked ? "THREAT BLOCKED" : isWarn ? "WARNING" : "SAFE REQUEST"}
          </div>
          <div className="text-xs text-slate-400 mt-1">{a.category}</div>
        </div>

        {/* Risk & Trust Scores */}
        <div className="grid grid-cols-2 gap-2">
          <div className="card p-3 text-center">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-1">Risk</div>
            <div className={cn("text-2xl font-bold", a.risk_score >= 70 ? "text-red-400" : a.risk_score >= 40 ? "text-yellow-400" : "text-emerald-400")}>
              {a.risk_score}<span className="text-sm text-slate-500">%</span>
            </div>
          </div>
          <div className="card p-3 text-center">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-1">Trust</div>
            <div className={cn("text-2xl font-bold", a.trust_score >= 60 ? "text-emerald-400" : a.trust_score >= 30 ? "text-yellow-400" : "text-red-400")}>
              {a.trust_score}<span className="text-sm text-slate-500">%</span>
            </div>
          </div>
        </div>

        {/* Details */}
        <div className="space-y-2.5">
          {a.technique && a.technique !== "None" && (
            <DetailRow label="Technique" value={a.technique} />
          )}
          <DetailRow label="Severity" value={a.severity} valueClass={severityColor(a.severity)} />
          <DetailRow label="Confidence" value={`${Math.round(a.confidence * 100)}%`} />
          {a.matched_pattern && (
            <DetailRow label="Matched Pattern" value={`"${a.matched_pattern}"`} mono />
          )}
          {a.policy_triggered && a.policy_triggered !== "None" && (
            <DetailRow label="Policy" value={a.policy_triggered} />
          )}
        </div>

        {/* Explanation */}
        {a.explanation && (
          <div className="card p-3">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-1.5">Explanation</div>
            <p className="text-xs text-slate-300 leading-relaxed">{a.explanation}</p>
          </div>
        )}

        {/* Detection Pipeline */}
        {a.pipeline && a.pipeline.length > 0 && (
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-2 flex items-center gap-1.5">
              <Fingerprint className="w-3 h-3" />
              Detection Pipeline
            </div>
            <div className="space-y-1">
              {a.pipeline.map((step, i) => (
                <div
                  key={i}
                  className={cn(
                    "flex items-center gap-2 px-2.5 py-1.5 rounded-md text-[11px] border animate-fade-in-up",
                    step.status === "detected" ? "bg-red-500/5 border-red-500/20" :
                    step.status === "BLOCK" ? "bg-red-500/10 border-red-500/30" :
                    step.status === "WARN" ? "bg-yellow-500/5 border-yellow-500/20" :
                    "bg-emerald-500/5 border-emerald-500/20"
                  )}
                  style={{ animationDelay: `${i * 60}ms` }}
                >
                  {step.status === "detected" || step.status === "BLOCK" ? (
                    <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  ) : step.status === "WARN" ? (
                    <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  )}
                  <span className="font-medium text-white flex-1">{step.name}</span>
                  <span className={cn(
                    "text-[10px]",
                    step.status === "detected" || step.status === "BLOCK" ? "text-red-400" :
                    step.status === "WARN" ? "text-yellow-400" : "text-emerald-400"
                  )}>
                    {step.status === "passed" ? "✓" : step.status.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value, valueClass = "text-white", mono = false }: {
  label: string; value: string; valueClass?: string; mono?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="text-[11px] text-slate-500 shrink-0">{label}</span>
      <span className={cn("text-[11px] font-medium text-right", valueClass, mono && "font-mono")}>{value}</span>
    </div>
  );
}
