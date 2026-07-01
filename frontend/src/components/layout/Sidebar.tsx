"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, LayoutDashboard, Crosshair, FileText,
  Settings2, Plug, ShieldAlert, Radio,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/", label: "AI Firewall Simulator", icon: Crosshair, accent: "text-cyan-400" },
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, accent: "text-blue-400" },
  { href: "/policies", label: "Firewall Policies", icon: Settings2, accent: "text-violet-400" },
  { href: "/threats", label: "Threat Intelligence", icon: ShieldAlert, accent: "text-orange-400" },
  { href: "/logs", label: "Incident Logs", icon: FileText, accent: "text-emerald-400" },
  { href: "/integrations", label: "Integrations", icon: Plug, accent: "text-pink-400" },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 bottom-0 w-[260px] bg-[#080b12] border-r border-[#151d2e] flex flex-col z-50">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-[#151d2e]">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:shadow-blue-500/40 transition-shadow">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white tracking-tight">Security.AI</h1>
            <p className="text-[10px] text-slate-500 font-medium tracking-widest uppercase">Zero-Trust AI Firewall</p>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
                isActive
                  ? "bg-white/[0.06] text-white border border-white/[0.08]"
                  : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.03] border border-transparent"
              )}
            >
              <item.icon className={cn("w-[18px] h-[18px]", isActive ? item.accent : "text-slate-500")} />
              <span>{item.label}</span>
              {isActive && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Status */}
      <div className="px-5 py-4 border-t border-[#151d2e]">
        <div className="flex items-center gap-2 mb-2">
          <div className="status-dot" />
          <span className="text-xs font-medium text-emerald-400">Firewall Active</span>
        </div>
        <div className="flex items-center gap-2">
          <Radio className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-[11px] text-slate-500">All systems operational</span>
        </div>
      </div>
    </aside>
  );
}
