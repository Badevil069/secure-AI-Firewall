/* ─── Security.AI — Zustand Store ────────────────────────────────── */

import { create } from "zustand";
import type { ChatMessage, ThreatAnalysis, TimelineEvent, DashboardStats, SecurityPosture } from "@/types";

interface SecurityState {
  // Chat
  messages: ChatMessage[];
  addMessage: (msg: ChatMessage) => void;
  clearMessages: () => void;

  // Session
  sessionId: string;
  firewallMode: "strict" | "balanced" | "learning";
  agentProfile: string;
  setFirewallMode: (mode: "strict" | "balanced" | "learning") => void;
  setAgentProfile: (profile: string) => void;

  // Live security events
  securityEvents: TimelineEvent[];
  addSecurityEvent: (event: TimelineEvent) => void;
  clearSecurityEvents: () => void;

  // Counters
  totalRequests: number;
  safeRequests: number;
  blockedThreats: number;
  incrementTotal: () => void;
  incrementSafe: () => void;
  incrementBlocked: () => void;

  // Current analysis
  currentAnalysis: ThreatAnalysis | null;
  setCurrentAnalysis: (analysis: ThreatAnalysis | null) => void;

  // Loading
  isAnalyzing: boolean;
  setIsAnalyzing: (v: boolean) => void;
}

export const useSecurityStore = create<SecurityState>((set) => ({
  messages: [],
  addMessage: (msg) => set((s) => ({ messages: [...s.messages, msg] })),
  clearMessages: () => set({ messages: [], totalRequests: 0, safeRequests: 0, blockedThreats: 0, securityEvents: [], currentAnalysis: null }),

  sessionId: `session-${Date.now()}`,
  firewallMode: "balanced",
  agentProfile: "developer",
  setFirewallMode: (mode) => set({ firewallMode: mode }),
  setAgentProfile: (profile) => set({ agentProfile: profile }),

  securityEvents: [],
  addSecurityEvent: (event) => set((s) => ({ securityEvents: [event, ...s.securityEvents].slice(0, 50) })),
  clearSecurityEvents: () => set({ securityEvents: [] }),

  totalRequests: 0,
  safeRequests: 0,
  blockedThreats: 0,
  incrementTotal: () => set((s) => ({ totalRequests: s.totalRequests + 1 })),
  incrementSafe: () => set((s) => ({ safeRequests: s.safeRequests + 1 })),
  incrementBlocked: () => set((s) => ({ blockedThreats: s.blockedThreats + 1 })),

  currentAnalysis: null,
  setCurrentAnalysis: (analysis) => set({ currentAnalysis: analysis }),

  isAnalyzing: false,
  setIsAnalyzing: (v) => set({ isAnalyzing: v }),
}));
