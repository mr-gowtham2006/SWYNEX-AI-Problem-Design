import React from "react"
import type { SafetyGuidance, OfficialReportingChannel } from "@/types/api"
import { Badge } from "@/components/ui/badge"
import { AccordionItem } from "@/components/ui/accordion"
import {
  CheckCircle,
  ExternalLink,
  LifeBuoy,
  FileCheck2,
  ShieldAlert,
  PhoneCall,
} from "lucide-react"

interface SafetyReportingTabProps {
  guidance: SafetyGuidance
  reporting: OfficialReportingChannel[]
  primaryAction?: string
}

export const SafetyReportingTab: React.FC<SafetyReportingTabProps> = ({
  guidance,
  reporting,
  primaryAction,
}) => {
  // Extract key emergency numbers if present in channels
  const emergencyChannels = [
    { name: "Cyber Crime Helpline", number: "1930", note: "Financial fraud & identity theft" },
    { name: "Spam & UCC Reporting", number: "1909", note: "TRAI SMS reporting via SMS or call" },
  ]

  return (
    <div className="space-y-3 pt-2">
      {/* 1. Primary Recommended Action Shown First */}
      <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/20 via-slate-900/60 to-slate-900/60 p-4 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <LifeBuoy className="size-4 text-cyan-400" />
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Primary Recommended Action
            </h4>
          </div>
          <Badge
            variant={
              guidance.alert_type === "error"
                ? "destructive"
                : guidance.alert_type === "warning"
                ? "warning"
                : "default"
            }
            className="text-[10px] capitalize"
          >
            {guidance.alert_type} Priority
          </Badge>
        </div>

        <p className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <span>{primaryAction || (guidance.actions[0] ?? "Do not interact with unverified links.")}</span>
        </p>

        {/* Quick Hotline Badges */}
        <div className="flex flex-wrap gap-2 pt-1 border-t border-slate-800/80">
          {emergencyChannels.map((em, idx) => (
            <div
              key={idx}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-950/80 border border-slate-800 text-[11px] text-slate-300"
            >
              <PhoneCall className="size-3 text-cyan-400" />
              <span className="font-semibold text-slate-100">{em.name}:</span>
              <span className="font-mono text-cyan-400 font-bold">{em.number}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 2. Full Safety Checklist (Expandable) */}
      <AccordionItem
        title="Complete Safety Guidance Checklist"
        subtitle={`${guidance.actions.length} protective protocols recommended for this threat level`}
        icon={<ShieldAlert className="size-4 text-amber-400" />}
        badge={
          <Badge variant="outline" className="text-[10px] text-slate-300 border-slate-700">
            {guidance.actions.length} Steps
          </Badge>
        }
        defaultOpen={false}
      >
        <ul className="space-y-2 pt-1">
          {guidance.actions.map((act, idx) => (
            <li
              key={idx}
              className="flex items-start gap-2.5 text-xs text-slate-200 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80"
            >
              <CheckCircle className="size-3.5 text-cyan-400 shrink-0 mt-0.5" />
              <span className="leading-relaxed">{act}</span>
            </li>
          ))}
        </ul>
      </AccordionItem>

      {/* 3. Official Reporting Channels & Portals (Expandable) */}
      <AccordionItem
        title="Official Government Reporting Channels & Portals"
        subtitle="National Cyber Crime Reporting Portal (1930), DoT Sanchar Saathi Chakshu, TRAI 1909"
        icon={<FileCheck2 className="size-4 text-emerald-400" />}
        badge={
          <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-500/30">
            {reporting.length} Channels
          </Badge>
        }
        defaultOpen={false}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-1">
          {reporting.map((channel, idx) => (
            <div
              key={idx}
              className="rounded-lg border border-slate-800/80 bg-slate-950/70 p-3 space-y-2 flex flex-col justify-between"
            >
              <div className="space-y-1">
                <div className="flex items-start justify-between gap-2">
                  <h5 className="text-xs font-bold text-slate-100">{channel.agency}</h5>
                  <Badge variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/30 shrink-0">
                    {channel.portal}
                  </Badge>
                </div>
                <p className="text-[11px] text-slate-400 leading-snug">{channel.purpose}</p>
              </div>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between gap-2">
                <span className="text-[10px] font-medium text-slate-300">
                  {channel.action}
                </span>
                <a
                  href={channel.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-medium transition-colors shrink-0"
                >
                  <span>Open Portal</span>
                  <ExternalLink className="size-3" />
                </a>
              </div>
            </div>
          ))}
        </div>
      </AccordionItem>
    </div>
  )
}
