"use client";

import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import type { IncidentOut } from "@/types";
import { cn, formatTimestamp, severityColor, decisionColor, categoryIcon } from "@/lib/utils";
import { FileText, Search, Filter, ChevronLeft, ChevronRight } from "lucide-react";

export default function LogsPage() {
  const [incidents, setIncidents] = useState<IncidentOut[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("");
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.incidents({
        search: search || undefined,
        category: categoryFilter || undefined,
        severity: severityFilter || undefined,
        decision: decisionFilter || undefined,
        page,
        limit: 15,
      });
      setIncidents(res.incidents);
      setTotal(res.total);
      setPages(res.pages);
    } catch {}
    setLoading(false);
  }, [page, search, categoryFilter, severityFilter, decisionFilter]);

  useEffect(() => { fetchData(); }, [fetchData]);

  return (
    <div className="p-6 space-y-5 max-w-[1600px]">
      <div>
        <h1 className="text-2xl font-bold text-white">Incident Logs</h1>
        <p className="text-sm text-slate-400 mt-0.5">Complete record of all security events — {total} total</p>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-[400px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search prompts..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full bg-[#0c1118] border border-[#1e293b] rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500/50"
          />
        </div>
        <select value={categoryFilter} onChange={(e) => { setCategoryFilter(e.target.value); setPage(1); }}
          className="bg-[#0c1118] border border-[#1e293b] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50">
          <option value="">All Categories</option>
          <option value="Prompt Injection">Prompt Injection</option>
          <option value="Jailbreak">Jailbreak</option>
          <option value="Credential Theft">Credential Theft</option>
          <option value="Source Code Leakage">Source Code Leakage</option>
          <option value="Data Exfiltration">Data Exfiltration</option>
          <option value="Safe">Safe</option>
        </select>
        <select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
          className="bg-[#0c1118] border border-[#1e293b] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select value={decisionFilter} onChange={(e) => { setDecisionFilter(e.target.value); setPage(1); }}
          className="bg-[#0c1118] border border-[#1e293b] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50">
          <option value="">All Decisions</option>
          <option value="BLOCK">Blocked</option>
          <option value="WARN">Warned</option>
          <option value="ALLOW">Allowed</option>
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e293b]">
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Time</th>
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">ID</th>
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Prompt</th>
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Category</th>
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Severity</th>
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Risk</th>
                <th className="text-left px-4 py-3 text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Decision</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="text-center py-12 text-slate-500 text-xs">Loading...</td></tr>
              ) : incidents.length === 0 ? (
                <tr><td colSpan={7} className="text-center py-12 text-slate-500 text-xs">No incidents found</td></tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.id} className="border-b border-[#151d2e] hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">{formatTimestamp(inc.timestamp)}</td>
                    <td className="px-4 py-3 text-[10px] font-mono text-slate-500">{inc.attack_id || "—"}</td>
                    <td className="px-4 py-3 text-xs text-white max-w-[300px] truncate">{inc.prompt}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs flex items-center gap-1.5">
                        <span>{categoryIcon(inc.threat_category)}</span>
                        <span className="text-slate-300">{inc.threat_category}</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn("text-xs font-medium", severityColor(inc.severity))}>{inc.severity}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-white font-medium">{inc.risk_score}</td>
                    <td className="px-4 py-3">
                      <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded border", decisionColor(inc.decision))}>{inc.decision}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[#1e293b]">
            <span className="text-xs text-slate-500">Page {page} of {pages}</span>
            <div className="flex gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                className="px-3 py-1.5 text-xs text-slate-400 bg-white/5 rounded-md border border-[#1e293b] hover:bg-white/10 disabled:opacity-30">
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page >= pages}
                className="px-3 py-1.5 text-xs text-slate-400 bg-white/5 rounded-md border border-[#1e293b] hover:bg-white/10 disabled:opacity-30">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
