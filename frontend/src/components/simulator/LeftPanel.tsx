"use client";

import { useSecurityStore } from "@/store/useSecurityStore";
import { cn, formatTimestamp, categoryIcon, decisionColor } from "@/lib/utils";
import { Activity, ShieldBan, ShieldCheck, Zap, TrendingUp } from "lucide-react";

export default function LeftPanel() {
  const { securityEvents, totalRequests, safeRequests, blockedThreats, firewallMode, setFirewallMode } = useSecurityStore();

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#151d2e] flex items-center gap-2">
        <Activity className="w-4 h-4 text-blue-400" />
        <span className="text-sm font-semibold text-white">Security Monitor</span>
      </div>

      {/* Firewall Mode Selector */}
      <div className="px-4 py-3 border-b border-[#151d2e]">
        <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-2">Firewall Mode</div>
        <div className="flex gap-1">
          {(["strict", "balanced", "learning"] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setFirewallMode(mode)}
              className={cn(
                "flex-1 px-2 py-1.5 rounded-md text-[11px] font-medium transition-all capitalize",
                firewallMode === mode
                  ? mode === "strict" ? "bg-red-500/15 text-red-400 border border-red-500/30"
                    : mode === "balanced" ? "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                    : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                  : "text-slate-500 hover:text-slate-300 border border-transparent hover:bg-white/5"
              )}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Counters */}
      <div className="px-4 py-3 border-b border-[#151d2e] grid grid-cols-3 gap-2">
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 mb-1">
            <Zap className="w-3 h-3 text-blue-400" />
          </div>
          <div className="text-lg font-bold text-white">{totalRequests}</div>
          <div className="text-[10px] text-slate-500">Total</div>
        </div>
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 mb-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
          </div>
          <div className="text-lg font-bold text-emerald-400">{safeRequests}</div>
          <div className="text-[10px] text-slate-500">Safe</div>
        </div>
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 mb-1">
            <ShieldBan className="w-3 h-3 text-red-400" />
          </div>
          <div className="text-lg font-bold text-red-400">{blockedThreats}</div>
          <div className="text-[10px] text-slate-500">Blocked</div>
        </div>
      </div>

      {/* Security Score */}
      <div className="px-4 py-3 border-b border-[#151d2e]">
        <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mb-2">Security Score</div>
        <div className="flex items-end gap-2">
          <span className="text-2xl font-bold text-white">
            {totalRequests === 0 ? "100" : Math.round((safeRequests / Math.max(totalRequests, 1)) * 100)}
          </span>
          <span className="text-sm text-slate-500 mb-0.5">%</span>
        </div>
        <div className="w-full bg-[#1e293b] rounded-full h-1.5 mt-2">
          <div
            className="bg-gradient-to-r from-emerald-500 to-cyan-500 h-1.5 rounded-full transition-all duration-500"
            style={{ width: `${totalRequests === 0 ? 100 : Math.round((safeRequests / Math.max(totalRequests, 1)) * 100)}%` }}
          />
        </div>
      </div>

      {/* Live AI Security Events */}
      <div className="flex-1 overflow-y-auto">
        <div className="px-4 py-2 sticky top-0 bg-[#080b12] z-10">
          <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold flex items-center gap-1.5">
            <TrendingUp className="w-3 h-3" />
            Live AI Security Events
          </div>
        </div>
        <div className="px-4 pb-4 space-y-1.5">
          {securityEvents.length === 0 && (
            <p className="text-xs text-slate-600 py-4 text-center">No events yet. Send a prompt to begin.</p>
          )}
          {securityEvents.map((event, i) => (
            <div
              key={`${event.timestamp}-${i}`}
              className={cn(
                "flex items-center gap-2 px-2.5 py-2 rounded-lg border transition-all animate-slide-in",
                event.decision === "BLOCK"
                  ? "bg-red-500/5 border-red-500/20"
                  : event.decision === "WARN"
                    ? "bg-yellow-500/5 border-yellow-500/20"
                    : "bg-emerald-500/5 border-emerald-500/20"
              )}
            >
              <span className="text-sm">{categoryIcon(event.category)}</span>
              <div className="flex-1 min-w-0">
                <div className="text-[11px] font-medium text-white truncate">{event.category}</div>
                <div className="text-[10px] text-slate-500">{formatTimestamp(event.timestamp)}</div>
              </div>
              <span className={cn(
                "text-[10px] font-bold px-1.5 py-0.5 rounded border",
                decisionColor(event.decision)
              )}>
                {event.decision}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
