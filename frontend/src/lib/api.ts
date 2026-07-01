/* ─── Security.AI — API Client ───────────────────────────────────── */

import type { AnalyzeResponse, ChatResponse, DashboardResponse, IncidentListResponse, PolicyOut, AgentProfile } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const error = await res.text().catch(() => "Unknown error");
    throw new Error(`API Error ${res.status}: ${error}`);
  }
  return res.json();
}

export const api = {
  // Analyze a prompt through the firewall
  analyze: (prompt: string, session_id = "default", agent_profile = "developer", firewall_mode = "balanced") =>
    apiFetch<AnalyzeResponse>("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ prompt, session_id, agent_profile, firewall_mode }),
    }),

  // Full chat pipeline
  chat: (prompt: string, session_id = "default", conversation_id = "", agent_profile = "developer", firewall_mode = "balanced") =>
    apiFetch<ChatResponse>("/api/chat", {
      method: "POST",
      body: JSON.stringify({ prompt, session_id, conversation_id, agent_profile, firewall_mode }),
    }),

  // Dashboard
  dashboard: (session_id = "default") =>
    apiFetch<DashboardResponse>(`/api/dashboard?session_id=${session_id}`),

  // Incidents
  incidents: (params: { category?: string; severity?: string; decision?: string; search?: string; page?: number; limit?: number } = {}) => {
    const searchParams = new URLSearchParams();
    if (params.category) searchParams.set("category", params.category);
    if (params.severity) searchParams.set("severity", params.severity);
    if (params.decision) searchParams.set("decision", params.decision);
    if (params.search) searchParams.set("search", params.search);
    if (params.page) searchParams.set("page", params.page.toString());
    if (params.limit) searchParams.set("limit", params.limit.toString());
    return apiFetch<IncidentListResponse>(`/api/incidents?${searchParams.toString()}`);
  },

  // Policies
  policies: () => apiFetch<{ policies: PolicyOut[]; risk_threshold: number; firewall_mode: string }>("/api/policies"),
  updatePolicy: (slug: string, enabled: boolean) =>
    apiFetch<{ success: boolean }>(`/api/policies/${slug}`, {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    }),

  // Profiles
  profiles: () => apiFetch<AgentProfile[]>("/api/profiles"),

  // Firewall modes
  firewallModes: () => apiFetch<Record<string, { name: string; description: string }>>("/api/firewall-modes"),

  // Health
  health: () => apiFetch<{ status: string; app: string; version: string; demo_mode: boolean; ai_configured: boolean }>("/api/health"),
};
