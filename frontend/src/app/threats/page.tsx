"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { DashboardResponse } from "@/types";
import { cn, categoryIcon } from "@/lib/utils";
import { ShieldAlert, Shield, Lock, Key, Code2, Database, FileQuestion, TrendingUp } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis } from "recharts";

const CATEGORIES = [
  { key: "Prompt Injection", icon: Shield, color: "#3b82f6", description: "Attempts to override system instructions" },
  { key: "Jailbreak", icon: Lock, color: "#8b5cf6", description: "Attempts to bypass safety restrictions" },
  { key: "Credential Theft", icon: Key, color: "#10b981", description: "Attempts to extract secrets and API keys" },
  { key: "Source Code Leakage", icon: Code2, color: "#f59e0b", description: "Attempts to access internal source code" },
  { key: "Data Exfiltration", icon: Database, color: "#ef4444", description: "Attempts to steal organizational data" },
  { key: "Prompt Extraction", icon: FileQuestion, color: "#ec4899", description: "Attempts to extract the system prompt" },
];

export default function ThreatsPage() {
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.dashboard().then(setData).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="w-10 h-10 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
      </div>
    );
  }

  const distMap = new Map(data?.category_distribution?.map(d => [d.category, d.count]) ?? []);
  const radarData = CATEGORIES.map(c => ({
    category: c.key.split(" ").pop(),
    count: distMap.get(c.key) || 0,
  }));

  return (
    <div className="p-6 space-y-6 max-w-[1400px]">
      <div>
        <h1 className="text-2xl font-bold text-white">Threat Intelligence Center</h1>
        <p className="text-sm text-slate-400 mt-0.5">Attack statistics and threat landscape analysis</p>
      </div>

      {/* Category Cards */}
      <div className="grid grid-cols-3 gap-4">
        {CATEGORIES.map((cat) => {
          const count = distMap.get(cat.key) || 0;
          return (
            <div key={cat.key} className="card card-hover p-4 transition-all duration-200">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: `${cat.color}15`, border: `1px solid ${cat.color}30` }}>
                  <cat.icon className="w-5 h-5" style={{ color: cat.color }} />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-semibold text-white">{cat.key}</div>
                  <div className="text-xs text-slate-400">{cat.description}</div>
                </div>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div className="text-3xl font-bold text-white">{count}</div>
                <div className="text-[10px] text-slate-500">attacks detected</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-2 gap-4">
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-semibold text-white">Attacks by Category</span>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={data?.category_distribution ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="category" tick={{ fill: "#64748b", fontSize: 10 }} angle={-20} textAnchor="end" height={60} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#0c1118", border: "1px solid #1e293b", borderRadius: 8, color: "#f1f5f9", fontSize: 12 }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <ShieldAlert className="w-4 h-4 text-violet-400" />
            <span className="text-sm font-semibold text-white">Threat Radar</span>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#1e293b" />
              <PolarAngleAxis dataKey="category" tick={{ fill: "#94a3b8", fontSize: 11 }} />
              <PolarRadiusAxis tick={{ fill: "#64748b", fontSize: 10 }} />
              <Radar dataKey="count" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
