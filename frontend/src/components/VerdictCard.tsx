import React from "react"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { AnalyzeResponse } from "@/types/api"
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Shield,
  Zap,
  CheckCircle2,
  ArrowRight,
} from "lucide-react"

interface VerdictCardProps {
  data: AnalyzeResponse | null
  loading: boolean
}

type BadgeVariantType = "default" | "secondary" | "destructive" | "outline" | "success" | "warning" | "danger"

export const VerdictCard: React.FC<VerdictCardProps> = ({ data, loading }) => {
  if (loading) {
    return (
      <Card className="border-slate-800 bg-slate-900/70 shadow-xl backdrop-blur-sm flex flex-col justify-center items-center min-h-[310px] p-6 text-center">
        <div className="relative">
          <div className="size-16 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center"></div>
          <Shield className="size-6 text-cyan-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-pulse" />
        </div>
        <p className="mt-4 text-sm font-semibold text-slate-200">
          Synthesizing Multi-Modal Security Signals
        </p>
        <p className="mt-1 text-xs text-slate-400 max-w-xs">
          Running TF-IDF classifier, local URL forensics, OOV checks, and explainability rules...
        </p>
      </Card>
    )
  }

  if (!data) {
    return (
      <Card className="border-slate-800 border-dashed bg-slate-900/40 shadow-lg flex flex-col justify-center items-center min-h-[310px] p-6 text-center">
        <div className="size-14 rounded-2xl bg-slate-800/60 border border-slate-700/50 flex items-center justify-center text-slate-400 mb-3">
          <Shield className="size-7" />
        </div>
        <h3 className="text-base font-semibold text-slate-200">Awaiting Message Input</h3>
        <p className="text-xs text-slate-400 mt-1 max-w-sm">
          Enter an SMS message on the left or select a preset scenario to perform instant risk synthesis and forensics.
        </p>
        <div className="flex items-center gap-2 mt-4 text-[11px] text-slate-400">
          <span className="inline-block size-2 rounded-full bg-cyan-400 animate-pulse"></span>
          <span>FastAPI Engine Ready &bull; Offline URL Sandbox Active</span>
        </div>
      </Card>
    )
  }

  // Determine styling based on data.overall_state
  const state = data.overall_state.toUpperCase()

  let stateConfig: {
    badgeVariant: BadgeVariantType
    badgeBg: string
    borderClass: string
    gradientClass: string
    icon: React.ReactNode
    accentText: string
    glowColor: string
  } = {
    badgeVariant: "destructive",
    badgeBg: "bg-rose-500/20 text-rose-300 border-rose-500/40",
    borderClass: "border-rose-500/50 shadow-rose-950/30",
    gradientClass: "from-rose-950/40 via-slate-900/80 to-slate-900/90",
    icon: <ShieldAlert className="size-8 text-rose-400" />,
    accentText: "text-rose-400",
    glowColor: "rgba(244, 63, 94, 0.15)",
  }

  if (state === "SCAM") {
    stateConfig = {
      badgeVariant: "destructive",
      badgeBg: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      borderClass: "border-rose-500/60 shadow-rose-950/40",
      gradientClass: "from-rose-950/40 via-slate-900/80 to-slate-900/90",
      icon: <ShieldAlert className="size-8 text-rose-400" />,
      accentText: "text-rose-400",
      glowColor: "rgba(244, 63, 94, 0.18)",
    }
  } else if (state === "SPAM") {
    stateConfig = {
      badgeVariant: "warning",
      badgeBg: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      borderClass: "border-amber-500/60 shadow-amber-950/40",
      gradientClass: "from-amber-950/40 via-slate-900/80 to-slate-900/90",
      icon: <AlertTriangle className="size-8 text-amber-400" />,
      accentText: "text-amber-400",
      glowColor: "rgba(245, 158, 11, 0.15)",
    }
  } else if (state === "UNCERTAIN") {
    stateConfig = {
      badgeVariant: "warning",
      badgeBg: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
      borderClass: "border-yellow-500/50 shadow-yellow-950/30",
      gradientClass: "from-yellow-950/30 via-slate-900/80 to-slate-900/90",
      icon: <HelpCircle className="size-8 text-yellow-400" />,
      accentText: "text-yellow-400",
      glowColor: "rgba(234, 179, 8, 0.15)",
    }
  } else if (state.includes("NO THREAT") || state === "SAFE" || state === "HAM") {
    stateConfig = {
      badgeVariant: "success",
      badgeBg: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      borderClass: "border-emerald-500/50 shadow-emerald-950/30",
      gradientClass: "from-emerald-950/30 via-slate-900/80 to-slate-900/90",
      icon: <ShieldCheck className="size-8 text-emerald-400" />,
      accentText: "text-emerald-400",
      glowColor: "rgba(16, 185, 129, 0.15)",
    }
  }

  return (
    <Card
      className={`border bg-gradient-to-b ${stateConfig.gradientClass} ${stateConfig.borderClass} shadow-xl backdrop-blur-sm relative overflow-hidden transition-all duration-300`}
      style={{ boxShadow: `0 8px 30px ${stateConfig.glowColor}` }}
    >
      <CardHeader className="pb-3 pt-4 px-5 border-b border-slate-800/80 flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap className="size-4 text-cyan-400" />
          <CardTitle className="text-sm font-semibold tracking-wide text-slate-300 uppercase">
            Risk Synthesis Verdict
          </CardTitle>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="border-slate-700 bg-slate-800/70 text-[11px] text-slate-300 font-mono">
            {data.rule}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="p-5 space-y-4">
        {/* Main Verdict Banner */}
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800/80 shrink-0">
              {stateConfig.icon}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className={`text-2xl font-black tracking-tight ${stateConfig.accentText}`}>
                  {data.overall_state}
                </span>
              </div>
              <p className="text-xs text-slate-300 font-medium mt-0.5 max-w-sm line-clamp-2">
                {data.reason}
              </p>
            </div>
          </div>

          {/* Metric Pill */}
          <div className="text-right shrink-0 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
              Confidence
            </div>
            <div className="text-lg font-bold text-slate-100 flex items-center justify-end gap-1">
              <span>{data.confidence.toFixed(1)}%</span>
            </div>
            <div className="text-[10px] font-medium text-slate-400">
              Risk: <span className={stateConfig.accentText}>{data.risk_level}</span>
            </div>
          </div>
        </div>

        {/* Immediate Action Recommendation Banner */}
        <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-3 flex items-start gap-2.5">
          <ArrowRight className={`size-4 ${stateConfig.accentText} shrink-0 mt-0.5`} />
          <div className="text-xs">
            <span className="font-semibold text-slate-200">Recommended Action: </span>
            <span className="text-slate-300">{data.action_recommendation}</span>
          </div>
        </div>

        {/* Key Signal Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
          <div className="bg-slate-950/40 rounded border border-slate-800/60 p-2 text-center">
            <div className="text-[10px] text-slate-400">Model Output</div>
            <div className="text-xs font-semibold text-slate-200 truncate mt-0.5">
              {data.prediction}
            </div>
          </div>
          <div className="bg-slate-950/40 rounded border border-slate-800/60 p-2 text-center">
            <div className="text-[10px] text-slate-400">URLs Analyzed</div>
            <div className="text-xs font-semibold text-slate-200 mt-0.5">
              {data.urls_detected} {data.urls_detected === 1 ? "Link" : "Links"}
            </div>
          </div>
          <div className="bg-slate-950/40 rounded border border-slate-800/60 p-2 text-center">
            <div className="text-[10px] text-slate-400">TF-IDF Tokens</div>
            <div className="text-xs font-semibold text-slate-200 mt-0.5">
              {data.tokens_matched} Matched
            </div>
          </div>
          <div className="bg-slate-950/40 rounded border border-slate-800/60 p-2 text-center">
            <div className="text-[10px] text-slate-400">Synthesis Engine</div>
            <div className="text-xs font-semibold text-cyan-400 mt-0.5 flex items-center justify-center gap-1">
              <CheckCircle2 className="size-3" />
              Verified
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
