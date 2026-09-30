import React from "react"
import type { AnalyzeResponse } from "@/types/api"
import { Badge } from "@/components/ui/badge"
import { AccordionItem } from "@/components/ui/accordion"
import {
  Activity,
  AlertCircle,
  ExternalLink,
  Smartphone,
  Sparkles,
  ShieldCheck,
  Cpu,
} from "lucide-react"

interface OverviewTabProps {
  data: AnalyzeResponse
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ data }) => {
  return (
    <div className="space-y-3 pt-2">
      {/* 1. Model Output & Vocabulary Overlap (Compact summary, expandable) */}
      <AccordionItem
        title="Machine Learning Model Signals"
        subtitle={`Logistic Regression: ${data.prediction} (${data.confidence.toFixed(1)}% confidence, ${data.tokens_matched} tokens matched)`}
        icon={<Activity className="size-4 text-cyan-400" />}
        badge={
          <Badge variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/30">
            {data.prediction}
          </Badge>
        }
        defaultOpen={true}
      >
        <div className="space-y-2.5 text-xs pt-1">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
              <span className="text-slate-400 text-[11px]">Classification Output:</span>
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-100">{data.prediction}</span>
                <span className="text-slate-400 font-mono">{data.confidence.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden mt-1">
                <div
                  className="bg-cyan-400 h-1.5 rounded-full"
                  style={{ width: `${Math.min(100, Math.max(0, data.confidence))}%` }}
                />
              </div>
            </div>

            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
              <span className="text-slate-400 text-[11px]">TF-IDF Active Vocabulary (nnz):</span>
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-100 font-mono">
                  {data.tokens_matched} {data.tokens_matched === 1 ? "token" : "tokens"}
                </span>
                <span className="text-[11px] text-slate-400">
                  {data.tokens_matched > 0 ? "In-Vocabulary" : "Zero Overlap"}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 pt-0.5">
                Model training vocabulary size: 5,000 unigrams/bigrams
              </div>
            </div>
          </div>

          {data.tokens_matched === 0 && (
            <div className="rounded-lg bg-amber-500/10 border border-amber-500/30 p-2.5 text-[11px] text-amber-300 flex items-start gap-2">
              <AlertCircle className="size-4 shrink-0 text-amber-400 mt-0.5" />
              <div>
                <strong>Out-of-Vocabulary (OOV) Alert:</strong> Message terms fall outside the standard English SMS training corpus (e.g. Hinglish transliteration or dialect). Handled safely by multi-signal risk synthesis.
              </div>
            </div>
          )}
        </div>
      </AccordionItem>

      {/* 2. Message Indicators (Collapsed by default) */}
      <AccordionItem
        title="Message Risk Indicators"
        subtitle={
          data.indicators.length > 0
            ? `${data.indicators.length} heuristic pattern${data.indicators.length === 1 ? "" : "s"} flagged in message`
            : "No suspicious regex or keyword indicators triggered"
        }
        icon={<Sparkles className="size-4 text-amber-400" />}
        badge={
          <Badge
            variant={data.indicators.length > 0 ? "warning" : "outline"}
            className="text-[10px]"
          >
            {data.indicators.length} {data.indicators.length === 1 ? "Flag" : "Flags"}
          </Badge>
        }
        defaultOpen={false}
      >
        <div className="pt-1">
          {data.indicators.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {data.indicators.map((ind, idx) => (
                <span
                  key={idx}
                  className="text-xs px-2.5 py-1 rounded-md bg-amber-950/20 text-amber-300 border border-amber-500/30 font-medium"
                >
                  {ind}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">
              Clean text: No high-risk banking urgency, prize claims, lottery, or OTP extraction phrases identified.
            </p>
          )}
        </div>
      </AccordionItem>

      {/* 3. Sender Verification (Collapsed if no sender or standard format) */}
      {data.sender_info && (
        <AccordionItem
          title="Sender Header & TRAI Verification"
          subtitle={`Header: ${data.sender_info.sender_id || "None"} &bull; ${data.sender_info.is_valid_format ? "Matches TRAI Commercial Format" : "Non-Standard / Individual Format"}`}
          icon={<Smartphone className="size-4 text-blue-400" />}
          badge={
            data.sender_info.is_valid_format ? (
              <Badge variant="success" className="text-[10px]">
                TRAI Format OK
              </Badge>
            ) : (
              <Badge variant="warning" className="text-[10px]">
                Verify Header
              </Badge>
            )
          }
          defaultOpen={false}
        >
          <div className="text-xs space-y-2 pt-1">
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Submitted Header:</span>
                <span className="font-mono font-bold text-slate-100">
                  {data.sender_info.sender_id}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed bg-slate-900/80 p-2 rounded border border-slate-800">
                {data.sender_info.note}
              </p>
              <div className="pt-1 flex items-center justify-between">
                <span className="text-[10px] text-slate-400">
                  Official TRAI DLT registry verification:
                </span>
                <a
                  href={data.sender_info.trai_portal_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <span>smsheader.trai.gov.in</span>
                  <ExternalLink className="size-3" />
                </a>
              </div>
            </div>
          </div>
        </AccordionItem>
      )}

      {/* 4. Detection Details & Synthesis Rule (Collapsed by default) */}
      <AccordionItem
        title="Synthesis Rule & Pipeline Diagnostics"
        subtitle={`Active Rule: ${data.rule} &bull; Risk Level: ${data.risk_level}`}
        icon={<Cpu className="size-4 text-slate-400" />}
        badge={
          <Badge variant="outline" className="text-[10px] font-mono text-slate-300 border-slate-700">
            {data.rule}
          </Badge>
        }
        defaultOpen={false}
      >
        <div className="text-xs space-y-2 pt-1">
          <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Synthesis Rule Triggered:</span>
              <span className="font-mono font-bold text-cyan-400">{data.rule}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Assessed Threat Level:</span>
              <span className="font-semibold text-slate-200">{data.risk_level}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">Synthesized Reason:</span>
              <span className="text-slate-300 text-right max-w-sm">{data.reason}</span>
            </div>
            <div className="flex justify-between items-center border-t border-slate-800/80 pt-1.5 text-[10px] text-slate-400">
              <span className="flex items-center gap-1">
                <ShieldCheck className="size-3 text-cyan-400" />
                Offline URL sandbox + Logistic Regression model pipeline
              </span>
              <span>Local Execution</span>
            </div>
          </div>
        </div>
      </AccordionItem>
    </div>
  )
}
