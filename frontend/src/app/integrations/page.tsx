"use client";

import { Shield, Radar, BarChart3, Globe, MessageSquare, Activity, Database, Cloud } from "lucide-react";
import { cn } from "@/lib/utils";

const INTEGRATIONS = [
  {
    name: "Cisco SecureX",
    icon: Shield,
    description: "Centralized security visibility across all Cisco security products. Integrates Security.AI threat data into the SecureX unified dashboard.",
    status: "Planned",
    color: "from-blue-500 to-cyan-500",
  },
  {
    name: "Cisco XDR",
    icon: Radar,
    description: "Cross-platform threat correlation and extended detection and response. Feeds AI attack signatures into XDR for holistic threat analysis.",
    status: "Planned",
    color: "from-violet-500 to-purple-500",
  },
  {
    name: "Splunk",
    icon: BarChart3,
    description: "Export AI security events and incident logs to Splunk for advanced analytics, long-term storage, and compliance reporting.",
    status: "Planned",
    color: "from-emerald-500 to-teal-500",
  },
  {
    name: "Microsoft Sentinel",
    icon: Globe,
    description: "Cloud-native SIEM integration. Stream Security.AI incidents into Sentinel workbooks and automated playbooks.",
    status: "Planned",
    color: "from-sky-500 to-blue-500",
  },
  {
    name: "Slack Alerts",
    icon: MessageSquare,
    description: "Real-time threat notifications to Slack channels. Instant alerts when critical AI security incidents are detected.",
    status: "Planned",
    color: "from-orange-500 to-amber-500",
  },
  {
    name: "PagerDuty",
    icon: Activity,
    description: "Automated incident response escalation. Critical AI threats trigger PagerDuty alerts for on-call security teams.",
    status: "Planned",
    color: "from-red-500 to-rose-500",
  },
  {
    name: "Datadog",
    icon: Database,
    description: "AI firewall metrics and observability. Monitor detection latency, throughput, and false positive rates in Datadog dashboards.",
    status: "Planned",
    color: "from-pink-500 to-fuchsia-500",
  },
  {
    name: "Elastic SIEM",
    icon: Cloud,
    description: "Elasticsearch-based security analytics. Index all AI security events for full-text search and custom visualizations.",
    status: "Planned",
    color: "from-cyan-500 to-blue-500",
  },
];

export default function IntegrationsPage() {
  return (
    <div className="p-6 space-y-6 max-w-[1400px]">
      <div>
        <h1 className="text-2xl font-bold text-white">Enterprise Integrations</h1>
        <p className="text-sm text-slate-400 mt-0.5">Connect Security.AI with your existing security infrastructure</p>
      </div>

      {/* Integration Grid */}
      <div className="grid grid-cols-2 gap-4">
        {INTEGRATIONS.map((item) => (
          <div key={item.name} className="card card-hover p-5 flex items-start gap-4 transition-all duration-200">
            <div className={cn("w-12 h-12 rounded-xl bg-gradient-to-br flex items-center justify-center shrink-0 shadow-lg", item.color)}>
              <item.icon className="w-6 h-6 text-white" />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold text-white">{item.name}</span>
                <span className="text-[10px] px-2 py-0.5 bg-amber-500/10 text-amber-400 rounded-full border border-amber-500/20 font-medium">
                  {item.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Enterprise Note */}
      <div className="card p-5 border-blue-500/20">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-white mb-1">Enterprise Deployment Ready</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Security.AI is designed for enterprise deployment. The integration layer supports webhook-based
              event streaming, REST API endpoints for querying threat data, and standardized security event
              formats (CEF, LEEF, Syslog). Contact us for custom integration requirements and enterprise licensing.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
