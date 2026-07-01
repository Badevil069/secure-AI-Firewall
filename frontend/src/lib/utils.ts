import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatTimestamp(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "Critical": return "text-red-400";
    case "High": return "text-orange-400";
    case "Medium": return "text-yellow-400";
    case "Low": return "text-blue-400";
    default: return "text-emerald-400";
  }
}

export function decisionColor(decision: string): string {
  switch (decision) {
    case "BLOCK": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "WARN": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "ALLOW": return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
    default: return "text-slate-400 bg-slate-500/10 border-slate-500/30";
  }
}

export function decisionBgColor(decision: string): string {
  switch (decision) {
    case "BLOCK": return "bg-red-500";
    case "WARN": return "bg-yellow-500";
    case "ALLOW": return "bg-emerald-500";
    default: return "bg-slate-500";
  }
}

export function categoryIcon(category: string): string {
  switch (category) {
    case "Prompt Injection": return "🛡️";
    case "Jailbreak": return "🔓";
    case "Credential Theft": return "🔑";
    case "Source Code Leakage": return "💻";
    case "Data Exfiltration": return "📤";
    case "Memory Recall Blocked": return "🧠";
    case "Safe": return "✅";
    default: return "⚠️";
  }
}
