"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { DashboardResponse } from "@/types";
import { cn, severityColor, decisionColor, formatTimestamp, categoryIcon } from "@/lib/utils";
import {
  Shield, ShieldCheck, ShieldBan, AlertTriangle, Activity,
  TrendingUp, BarChart3, Gauge, RefreshCw,
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from "recharts";

const PIE_COLORS = ["#ef4444", "#f59e0b", "#8b5cf6", "#ec4899", "#06b6d4", "#10b981"];

export default function DashboardPage() {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const res = await api.dashboard();
      setData(res);
    } catch {
      // Backend not running
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="w-10 h-10 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
      </div>
    );
  }

  const stats = data?.stats;
  const posture = data?.posture;

  return (
    <div className="p-6 space-y-6 max-w-[1600px]">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-slate-400 mt-0.5">Real-time AI firewall monitoring</p>
        </div>
        <button onClick={fetchData} className="flex items-center gap-2 text-xs text-slate-400 hover:text-white bg-white/5 px-3 py-2 rounded-lg border border-[#1e293b] hover:border-blue-500/30 transition-all">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-5 gap-4">
        <StatCard icon={Shield} label="Security Score" value={`${stats?.security_score ?? 100}%`} accent="blue" />
        <StatCard icon={Activity} label="Total Requests" value={stats?.total_requests ?? 0} accent="cyan" />
        <StatCard icon={ShieldCheck} label="Safe Requests" value={stats?.safe_requests ?? 0} accent="emerald" />
        <StatCard icon={ShieldBan} label="Blocked Threats" value={stats?.blocked_threats ?? 0} accent="red" />
        <StatCard icon={AlertTriangle} label="Critical Threats" value={stats?.critical_threats ?? 0} accent="orange" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-3 gap-4">
        {/* Trend Chart */}
        <div className="col-span-2 card p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-semibold text-white">Threat Trends</span>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={data?.threat_trends ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#0c1118", border: "1px solid #1e293b", borderRadius: 8, color: "#f1f5f9", fontSize: 12 }} />
              <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="safe" stroke="#10b981" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Pie Chart */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="w-4 h-4 text-violet-400" />
            <span className="text-sm font-semibold text-white">Attack Distribution</span>
          </div>
          {(data?.category_distribution?.length ?? 0) > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={data?.category_distribution} dataKey="count" nameKey="category" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}>
                  {data?.category_distribution?.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#0c1118", border: "1px solid #1e293b", borderRadius: 8, color: "#f1f5f9", fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[260px] text-xs text-slate-500">No threat data yet</div>
          )}
        </div>
      </div>

      {/* Security Posture + Timeline */}
      <div className="grid grid-cols-3 gap-4">
        {/* Security Posture */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Gauge className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-semibold text-white">AI Security Posture</span>
          </div>
          <div className="text-center mb-4">
            <div className="text-4xl font-bold text-white">{posture?.overall ?? 100}<span className="text-lg text-slate-500">%</span></div>
            <div className="text-xs text-slate-500 mt-1">Overall Security</div>
          </div>
          <div className="space-y-3">
            <PostureBar label="Prompt Security" value={posture?.prompt_security ?? 100} />
            <PostureBar label="Credential Protection" value={posture?.credential_protection ?? 100} />
            <PostureBar label="Source Protection" value={posture?.source_protection ?? 100} />
            <PostureBar label="Response Protection" value={posture?.response_protection ?? 100} />
            <PostureBar label="Memory Protection" value={posture?.memory_protection ?? 100} />
          </div>
        </div>

        {/* Attack Timeline */}
        <div className="col-span-2 card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-semibold text-white">Attack Timeline</span>
          </div>
          <div className="space-y-2 max-h-[340px] overflow-y-auto">
            {(data?.timeline?.length ?? 0) === 0 ? (
              <p className="text-xs text-slate-500 py-8 text-center">No events recorded. Use the simulator to generate data.</p>
            ) : (
              data?.timeline?.map((event, i) => (
                <div key={i} className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-lg border",
                  event.decision === "BLOCK" ? "bg-red-500/5 border-red-500/20" :
                  event.decision === "WARN" ? "bg-yellow-500/5 border-yellow-500/20" :
                  "bg-emerald-500/5 border-emerald-500/20"
                )}>
                  <span className="text-sm">{categoryIcon(event.category)}</span>
                  <div className="flex-1">
                    <div className="text-xs font-medium text-white">{event.category}</div>
                    <div className="text-[10px] text-slate-500">{formatTimestamp(event.timestamp)}</div>
                  </div>
                  <span className="text-[11px] font-medium text-slate-400">Risk: {event.risk_score}</span>
                  <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded border", decisionColor(event.decision))}>
                    {event.decision}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, accent }: { icon: React.ComponentType<{ className?: string }>; label: string; value: string | number; accent: string }) {
  const colors: Record<string, string> = {
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    cyan: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
    emerald: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    red: "text-red-400 bg-red-500/10 border-red-500/20",
    orange: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  };
  return (
    <div className="card card-hover p-4 transition-all duration-200">
      <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center border mb-3", colors[accent])}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-[11px] text-slate-500 mt-0.5">{label}</div>
    </div>
  );
}

function PostureBar({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] text-slate-400">{label}</span>
        <span className={cn("text-[11px] font-semibold", value >= 80 ? "text-emerald-400" : value >= 50 ? "text-yellow-400" : "text-red-400")}>
          {value}%
        </span>
      </div>
      <div className="w-full bg-[#1e293b] rounded-full h-1.5">
        <div
          className={cn("h-1.5 rounded-full transition-all duration-700",
            value >= 80 ? "bg-gradient-to-r from-emerald-500 to-cyan-500" :
            value >= 50 ? "bg-gradient-to-r from-yellow-500 to-orange-500" :
            "bg-gradient-to-r from-red-500 to-orange-500"
          )}
          style={{ width: `${value}%` }}
        />
      </div>
    </div>
  );
}
