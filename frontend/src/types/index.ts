/* ─── Security.AI — TypeScript Types ─────────────────────────────── */

export interface PipelineStep {
  name: string;
  status: "passed" | "detected" | "ALLOW" | "WARN" | "BLOCK" | "skipped";
  detail: string;
}

export interface ThreatAnalysis {
  attack_id: string | null;
  category: string;
  technique: string;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  risk_score: number;
  trust_score: number;
  confidence: number;
  decision: "ALLOW" | "WARN" | "BLOCK";
  reason: string;
  explanation: string;
  matched_pattern: string;
  policy_triggered: string;
  pipeline: PipelineStep[];
}

export interface RedactionInfo {
  type: string;
  action: string;
  reason: string;
  original_snippet: string;
  redacted_snippet: string;
}

export interface AnalyzeResponse {
  threat_analysis: ThreatAnalysis;
  timestamp: string;
}

export interface ChatResponse {
  response: string;
  was_blocked: boolean;
  threat_analysis: ThreatAnalysis;
  redactions: RedactionInfo[];
  timestamp: string;
}

export interface DashboardStats {
  total_requests: number;
  safe_requests: number;
  blocked_threats: number;
  warned_requests: number;
  critical_threats: number;
  security_score: number;
  session_risk: number;
}

export interface SecurityPosture {
  overall: number;
  prompt_security: number;
  credential_protection: number;
  source_protection: number;
  response_protection: number;
  memory_protection: number;
}

export interface TimelineEvent {
  timestamp: string;
  category: string;
  decision: string;
  risk_score: number;
  attack_id: string | null;
}

export interface DashboardResponse {
  stats: DashboardStats;
  posture: SecurityPosture;
  timeline: TimelineEvent[];
  threat_trends: { date: string; total: number; blocked: number; safe: number }[];
  category_distribution: { category: string; count: number }[];
}

export interface IncidentOut {
  id: number;
  timestamp: string;
  prompt: string;
  response: string | null;
  attack_id: string | null;
  threat_category: string;
  technique: string | null;
  severity: string;
  risk_score: number;
  trust_score: number;
  confidence: number;
  decision: string;
  reason: string | null;
  matched_pattern: string | null;
  policy_triggered: string | null;
  agent_profile: string | null;
  firewall_mode: string | null;
  pipeline_results: PipelineStep[] | null;
  redactions_applied: RedactionInfo[] | null;
}

export interface IncidentListResponse {
  incidents: IncidentOut[];
  total: number;
  page: number;
  pages: number;
}

export interface PolicyOut {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  enabled: boolean;
  blocked_count: number;
  last_triggered: string | null;
}

export interface AgentProfile {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  allowed_topics: string[] | null;
  blocked_topics: string[] | null;
  policies: string[] | null;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  threat_analysis?: ThreatAnalysis;
  was_blocked?: boolean;
  redactions?: RedactionInfo[];
}
