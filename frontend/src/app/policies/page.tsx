"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { PolicyOut, AgentProfile } from "@/types";
import { cn } from "@/lib/utils";
import {
  Shield, ShieldCheck, Lock, Code2, Database, FileSearch,
  Brain, Settings2, Users, ChevronRight,
} from "lucide-react";

const POLICY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  prompt_injection_protection: Shield,
  jailbreak_protection: Lock,
  credential_protection: ShieldCheck,
  source_code_protection: Code2,
  data_exfiltration_protection: Database,
  response_sanitization: FileSearch,
  memory_protection: Brain,
};

const POLICY_COLORS: Record<string, string> = {
  prompt_injection_protection: "from-blue-500 to-cyan-500",
  jailbreak_protection: "from-violet-500 to-purple-500",
  credential_protection: "from-emerald-500 to-teal-500",
  source_code_protection: "from-orange-500 to-amber-500",
  data_exfiltration_protection: "from-red-500 to-rose-500",
  response_sanitization: "from-pink-500 to-fuchsia-500",
  memory_protection: "from-cyan-500 to-blue-500",
};

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyOut[]>([]);
  const [profiles, setProfiles] = useState<AgentProfile[]>([]);
  const [threshold, setThreshold] = useState(75);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [polRes, profRes] = await Promise.all([api.policies(), api.profiles()]);
        setPolicies(polRes.policies);
        setThreshold(polRes.risk_threshold);
        setProfiles(profRes);
      } catch {}
      setLoading(false);
    }
    load();
  }, []);

  const togglePolicy = async (slug: string, enabled: boolean) => {
    try {
      await api.updatePolicy(slug, enabled);
      setPolicies((prev) =>
        prev.map((p) => (p.slug === slug ? { ...p, enabled } : p))
      );
    } catch {}
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="w-10 h-10 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-[1400px]">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Firewall Policies</h1>
        <p className="text-sm text-slate-400 mt-0.5">Configure security policies and protection rules</p>
      </div>

      {/* Risk Threshold */}
      <div className="card p-5">
        <div className="flex items-center gap-2 mb-3">
          <Settings2 className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-semibold text-white">Risk Threshold</span>
          <span className="ml-auto text-xl font-bold text-white">{threshold}%</span>
        </div>
        <input
          type="range"
          min={10}
          max={100}
          value={threshold}
          onChange={(e) => setThreshold(Number(e.target.value))}
          className="w-full accent-blue-500 cursor-pointer"
        />
        <div className="flex justify-between text-[10px] text-slate-500 mt-1">
          <span>Strict (10%)</span>
          <span>Balanced (75%)</span>
          <span>Permissive (100%)</span>
        </div>
      </div>

      {/* Policy Cards */}
      <div className="grid grid-cols-2 gap-4">
        {policies.map((policy) => {
          const Icon = POLICY_ICONS[policy.slug] ?? Shield;
          const gradient = POLICY_COLORS[policy.slug] ?? "from-blue-500 to-cyan-500";
          return (
            <div key={policy.slug} className="card card-hover p-4 flex items-start gap-4 transition-all duration-200">
              <div className={cn("w-10 h-10 rounded-lg bg-gradient-to-br flex items-center justify-center shrink-0", gradient)}>
                <Icon className="w-5 h-5 text-white" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-semibold text-white">{policy.name}</span>
                  <label className="ml-auto relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={policy.enabled}
                      onChange={(e) => togglePolicy(policy.slug, e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-slate-700 peer-checked:bg-emerald-500 rounded-full after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full" />
                  </label>
                </div>
                <p className="text-xs text-slate-400 mb-2">{policy.description}</p>
                <div className="flex items-center gap-3 text-[10px]">
                  <span className={cn("font-semibold", policy.enabled ? "text-emerald-400" : "text-red-400")}>
                    {policy.enabled ? "● Active" : "○ Disabled"}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Agent Profiles */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Users className="w-4 h-4 text-violet-400" />
          <span className="text-lg font-semibold text-white">AI Agent Profiles</span>
        </div>
        <div className="grid grid-cols-3 gap-4">
          {profiles.map((profile) => (
            <div key={profile.slug} className="card card-hover p-4 transition-all duration-200">
              <div className="text-sm font-semibold text-white mb-1">{profile.name}</div>
              <p className="text-xs text-slate-400 mb-3">{profile.description}</p>
              <div className="space-y-2">
                <div>
                  <div className="text-[10px] text-emerald-400 font-semibold mb-1">Allowed Topics</div>
                  <div className="flex flex-wrap gap-1">
                    {profile.allowed_topics?.slice(0, 3).map((t) => (
                      <span key={t} className="text-[10px] px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 rounded border border-emerald-500/20">{t}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-red-400 font-semibold mb-1">Blocked Topics</div>
                  <div className="flex flex-wrap gap-1">
                    {profile.blocked_topics?.slice(0, 3).map((t) => (
                      <span key={t} className="text-[10px] px-1.5 py-0.5 bg-red-500/10 text-red-400 rounded border border-red-500/20">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
