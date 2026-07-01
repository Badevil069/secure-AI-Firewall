"use client";

import SimulatorChat from "@/components/simulator/SimulatorChat";
import LeftPanel from "@/components/simulator/LeftPanel";
import RightPanel from "@/components/simulator/RightPanel";
import { useSecurityStore } from "@/store/useSecurityStore";

export default function HomePage() {
  const { agentProfile, setAgentProfile } = useSecurityStore();

  return (
    <div className="h-screen flex flex-col">
      {/* Top bar */}
      <div className="h-12 border-b border-[#151d2e] bg-[#080b12] flex items-center justify-between px-5">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-white">Live AI Firewall Simulator</h2>
          <span className="text-[10px] px-2 py-0.5 bg-red-500/10 text-red-400 rounded-full border border-red-500/20 font-bold animate-threat-pulse">
            ● MONITORING
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-slate-500">AI Agent:</span>
          <select
            value={agentProfile}
            onChange={(e) => setAgentProfile(e.target.value)}
            className="bg-[#0c1118] border border-[#1e293b] rounded-md px-2.5 py-1 text-xs text-white focus:outline-none focus:border-blue-500/50"
          >
            <option value="developer">Developer Assistant</option>
            <option value="customer_support">Customer Support</option>
            <option value="finance">Finance Bot</option>
            <option value="hr">HR Assistant</option>
            <option value="custom">Custom AI</option>
          </select>
        </div>
      </div>

      {/* 3-panel layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Panel */}
        <div className="w-[280px] border-r border-[#151d2e] bg-[#080b12] shrink-0">
          <LeftPanel />
        </div>

        {/* Center: Chat */}
        <div className="flex-1 bg-[#06080d]">
          <SimulatorChat />
        </div>

        {/* Right Panel */}
        <div className="w-[300px] border-l border-[#151d2e] bg-[#080b12] shrink-0">
          <RightPanel />
        </div>
      </div>
    </div>
  );
}
