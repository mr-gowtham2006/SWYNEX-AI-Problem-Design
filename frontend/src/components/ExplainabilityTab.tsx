import React, { useState } from "react"
import type { ExplainabilityResult } from "@/types/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Cpu, ArrowUpRight, ArrowDownRight, HelpCircle, ChevronDown, ListFilter } from "lucide-react"

interface ExplainabilityTabProps {
  explainability: ExplainabilityResult
  prediction?: string
  confidence?: number
}

export const ExplainabilityTab: React.FC<ExplainabilityTabProps> = ({
  explainability,
  prediction,
  confidence,
}) => {
  const { has_features, nnz, spam_features, ham_features, summary } = explainability
  const [showAllFeatures, setShowAllFeatures] = useState(false)

  // Top 2 contributing features for compact initial summary
  const topSpam = spam_features.slice(0, 2)
  const topHam = ham_features.slice(0, 2)
  const totalFeatures = spam_features.length + ham_features.length

  // Calculate maximum absolute contribution for relative bar widths
  const allContribs = [
    ...spam_features.map((f) => Math.abs(f.contribution)),
    ...ham_features.map((f) => Math.abs(f.contribution)),
  ]
  const maxContrib = allContribs.length > 0 ? Math.max(...allContribs, 0.001) : 1

  return (
    <div className="space-y-3 pt-2">
      {/* 1. Compact Summary First */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <Cpu className="size-4 text-cyan-400" />
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Explainability & Feature Attribution
            </h4>
          </div>
          <div className="flex items-center gap-2">
            {prediction && (
              <Badge variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/30">
                {prediction} {confidence !== undefined ? `(${confidence.toFixed(1)}%)` : ""}
              </Badge>
            )}
            <Badge variant="outline" className="text-[10px] text-slate-300 font-mono border-slate-700">
              {nnz} active tokens
            </Badge>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">{summary}</p>

        {/* Top Contributing Features Preview */}
        {has_features && (
          <div className="pt-2 border-t border-slate-800/80 space-y-2">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Top Influencing Tokens
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {/* Top Spam token */}
              {topSpam.length > 0 && (
                <div className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/20 space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-mono font-bold text-rose-300">
                      "{topSpam[0].token}"
                    </span>
                    <span className="text-rose-400 font-mono text-[11px]">
                      +{topSpam[0].contribution.toFixed(2)}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 flex justify-between">
                    <span>Pushes toward Spam</span>
                    <span>weight: {topSpam[0].weight.toFixed(2)}</span>
                  </div>
                </div>
              )}

              {/* Top Ham token */}
              {topHam.length > 0 && (
                <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-mono font-bold text-emerald-300">
                      "{topHam[0].token}"
                    </span>
                    <span className="text-emerald-400 font-mono text-[11px]">
                      {topHam[0].contribution.toFixed(2)}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 flex justify-between">
                    <span>Pushes toward Legitimate</span>
                    <span>weight: {topHam[0].weight.toFixed(2)}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Toggle Button for Full Feature Breakdown */}
        {has_features && totalFeatures > 2 && (
          <div className="pt-2 flex justify-center">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setShowAllFeatures(!showAllFeatures)}
              className="text-xs border-slate-700/80 bg-slate-850 hover:bg-slate-800 text-slate-200 cursor-pointer flex items-center gap-1.5"
            >
              <ListFilter className="size-3.5 text-cyan-400" />
              <span>
                {showAllFeatures
                  ? "Hide Detailed Feature Breakdown"
                  : `View all model features (${totalFeatures})`}
              </span>
              <ChevronDown
                className={`size-3.5 text-slate-400 transition-transform ${
                  showAllFeatures ? "rotate-180" : ""
                }`}
              />
            </Button>
          </div>
        )}
      </div>

      {!has_features && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 text-center text-xs text-slate-400 flex flex-col items-center gap-1.5">
          <HelpCircle className="size-5 text-slate-500" />
          <span>No specific TF-IDF feature contributions could be attributed to this text.</span>
        </div>
      )}

      {/* 2. Deep Complete Feature List (Behind "View all model features") */}
      {has_features && showAllFeatures && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-in fade-in-50 duration-200">
          {/* Spam-Pushing Features */}
          <div className="rounded-xl border border-rose-500/20 bg-rose-950/10 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-rose-500/20 pb-2">
              <h5 className="text-xs font-semibold text-rose-300 flex items-center gap-1.5">
                <ArrowUpRight className="size-4 text-rose-400" />
                Spam-Indicative Tokens ({spam_features.length})
              </h5>
              <span className="text-[10px] text-rose-400/80">Pushes verdict toward Spam</span>
            </div>

            {spam_features.length > 0 ? (
              <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
                {spam_features.map((feat, idx) => {
                  const barWidth = Math.min(100, (Math.abs(feat.contribution) / maxContrib) * 100)
                  return (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between items-center text-xs">
                        <span className="font-mono font-bold text-slate-200 bg-slate-900/80 px-1.5 py-0.5 rounded border border-rose-500/20">
                          "{feat.token}"
                        </span>
                        <div className="flex items-center gap-2 text-[11px]">
                          <span className="text-slate-400 font-mono">wt: {feat.weight.toFixed(2)}</span>
                          <span className="text-rose-400 font-mono font-semibold">
                            +{feat.contribution.toFixed(2)}
                          </span>
                        </div>
                      </div>
                      <div className="w-full bg-slate-800/80 rounded-full h-1 overflow-hidden">
                        <div
                          className="bg-rose-500 h-1 rounded-full transition-all"
                          style={{ width: `${barWidth}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">
                No tokens with positive spam weights identified.
              </p>
            )}
          </div>

          {/* Ham-Pushing (Safe) Features */}
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2">
              <h5 className="text-xs font-semibold text-emerald-300 flex items-center gap-1.5">
                <ArrowDownRight className="size-4 text-emerald-400" />
                Legitimate / Ham Tokens ({ham_features.length})
              </h5>
              <span className="text-[10px] text-emerald-400/80">Pushes verdict toward Safe</span>
            </div>

            {ham_features.length > 0 ? (
              <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
                {ham_features.map((feat, idx) => {
                  const barWidth = Math.min(100, (Math.abs(feat.contribution) / maxContrib) * 100)
                  return (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between items-center text-xs">
                        <span className="font-mono font-bold text-slate-200 bg-slate-900/80 px-1.5 py-0.5 rounded border border-emerald-500/20">
                          "{feat.token}"
                        </span>
                        <div className="flex items-center gap-2 text-[11px]">
                          <span className="text-slate-400 font-mono">wt: {feat.weight.toFixed(2)}</span>
                          <span className="text-emerald-400 font-mono font-semibold">
                            {feat.contribution.toFixed(2)}
                          </span>
                        </div>
                      </div>
                      <div className="w-full bg-slate-800/80 rounded-full h-1 overflow-hidden">
                        <div
                          className="bg-emerald-500 h-1 rounded-full transition-all"
                          style={{ width: `${barWidth}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">
                No tokens with negative (ham) weights identified.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
