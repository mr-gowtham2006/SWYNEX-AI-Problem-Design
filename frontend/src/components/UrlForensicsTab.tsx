import React, { useState } from "react"
import type { UrlAnalysisItem } from "@/types/api"
import { Badge } from "@/components/ui/badge"
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  ChevronDown,
} from "lucide-react"

interface UrlForensicsTabProps {
  urls: UrlAnalysisItem[]
  count: number
}

export const UrlForensicsTab: React.FC<UrlForensicsTabProps> = ({ urls, count }) => {
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null)
  const [expandedUrls, setExpandedUrls] = useState<Record<number, boolean>>({})

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedUrl(text)
    setTimeout(() => setCopiedUrl(null), 2000)
  }

  const toggleExpand = (idx: number) => {
    setExpandedUrls((prev) => ({ ...prev, [idx]: !prev[idx] }))
  }

  if (count === 0 || urls.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-6 text-center space-y-1.5 mt-2">
        <div className="size-8 rounded-full bg-slate-800 mx-auto flex items-center justify-center text-slate-400">
          <Globe className="size-4" />
        </div>
        <h4 className="text-xs font-semibold text-slate-200">No Web Links Detected</h4>
        <p className="text-[11px] text-slate-400 max-w-xs mx-auto">
          The message contains no embedded HTTP/HTTPS links or raw IP addresses.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-3 pt-2">
      <div className="flex items-center justify-between text-xs pb-1">
        <div className="flex items-center gap-2">
          <Globe className="size-3.5 text-cyan-400" />
          <span className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
            Detected URLs ({count})
          </span>
        </div>
        <span className="text-[11px] text-slate-400">
          Defanged (hxxp) &bull; Click card to inspect signals
        </span>
      </div>

      <div className="space-y-2.5">
        {urls.map((item, idx) => {
          const verdictUpper = (item.verdict || "UNKNOWN").toUpperCase()
          const isPhish = verdictUpper === "PHISHING" || verdictUpper === "SUSPICIOUS"
          const isSafe = verdictUpper === "SAFE"
          const isExpanded = !!expandedUrls[idx]
          const signalCount = item.signals ? item.signals.length : 0

          return (
            <div
              key={idx}
              className={`rounded-xl border transition-all overflow-hidden bg-slate-900/60 ${
                isPhish
                  ? "border-rose-500/40 bg-rose-950/10"
                  : isSafe
                  ? "border-emerald-500/30 bg-emerald-950/10"
                  : "border-slate-800"
              }`}
            >
              {/* Main Compact Row: Defanged URL, Verdict, Risk Score, Toggle */}
              <div className="p-3 sm:p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="p-1.5 rounded-lg bg-slate-800/80 text-cyan-400 shrink-0">
                    <Globe className="size-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-slate-100 truncate">
                        {item.defanged_url}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(item.defanged_url)}
                        className="text-slate-400 hover:text-slate-200 p-0.5 rounded transition-colors"
                        title="Copy defanged URL"
                      >
                        {copiedUrl === item.defanged_url ? (
                          <Check className="size-3 text-emerald-400" />
                        ) : (
                          <Copy className="size-3" />
                        )}
                      </button>
                    </div>
                    <div className="text-[10px] text-slate-400 truncate mt-0.5 font-mono">
                      Target: {item.url}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                  {item.risk_score !== null && (
                    <Badge
                      variant="outline"
                      className="text-[10px] font-mono border-slate-700 bg-slate-800/80 text-slate-200"
                    >
                      Risk: {(item.risk_score * 100).toFixed(0)}%
                    </Badge>
                  )}
                  <Badge
                    variant={isPhish ? "destructive" : isSafe ? "success" : "warning"}
                    className="text-[10px] font-bold tracking-wide"
                  >
                    {item.verdict || "UNAVAILABLE"}
                  </Badge>

                  {/* Expand / Collapse Button */}
                  <button
                    type="button"
                    onClick={() => toggleExpand(idx)}
                    className="flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-slate-100 transition-colors border border-slate-700/60 cursor-pointer ml-1"
                  >
                    <span>{isExpanded ? "Hide Signals" : `Signals (${signalCount})`}</span>
                    <ChevronDown
                      className={`size-3 text-slate-400 transition-transform ${
                        isExpanded ? "rotate-180 text-cyan-400" : ""
                      }`}
                    />
                  </button>
                </div>
              </div>

              {/* Deeper Collapsed Data: Forensic signals, severity, descriptions, errors */}
              {isExpanded && (
                <div className="p-3.5 pt-2 border-t border-slate-800/70 bg-slate-950/40 space-y-2 animate-in fade-in-50 duration-200">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Forensic Signals ({signalCount})
                  </div>

                  {signalCount > 0 ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {item.signals.map((sig, sIdx) => {
                        const sev = (sig.severity || "info").toLowerCase()
                        const isHigh = sev === "high" || sev === "critical"
                        const isMed = sev === "medium" || sev === "warning"

                        return (
                          <div
                            key={sIdx}
                            className={`text-xs p-2 rounded-lg border flex items-start gap-2 ${
                              isHigh
                                ? "bg-rose-950/20 border-rose-500/30 text-rose-300"
                                : isMed
                                ? "bg-amber-950/20 border-amber-500/30 text-amber-300"
                                : "bg-slate-900/60 border-slate-800 text-slate-300"
                            }`}
                          >
                            {isHigh ? (
                              <ShieldAlert className="size-3.5 text-rose-400 shrink-0 mt-0.5" />
                            ) : isMed ? (
                              <AlertTriangle className="size-3.5 text-amber-400 shrink-0 mt-0.5" />
                            ) : (
                              <ShieldCheck className="size-3.5 text-slate-400 shrink-0 mt-0.5" />
                            )}
                            <div className="min-w-0">
                              <span className="text-[10px] font-semibold uppercase tracking-wider block text-slate-400">
                                {sig.severity || "INFO"}
                              </span>
                              <span className="leading-tight text-[11px] block mt-0.5">
                                {sig.message}
                              </span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div className="text-xs text-slate-400 italic">
                      No malicious behavioral or structural heuristics triggered.
                    </div>
                  )}

                  {/* Sandbox error if present */}
                  {item.error && (
                    <div className="text-xs p-2 rounded bg-amber-950/20 border border-amber-500/30 text-amber-300 flex items-start gap-2">
                      <AlertTriangle className="size-3.5 shrink-0 text-amber-400 mt-0.5" />
                      <span>
                        <strong>Sandbox note:</strong> {item.error}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
