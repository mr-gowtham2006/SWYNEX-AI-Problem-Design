import { Shield, Lock, AlertCircle, Terminal } from "lucide-react"
import { useAnalyzer } from "@/hooks/useAnalyzer"
import { AnalyzerForm } from "@/components/AnalyzerForm"
import { VerdictCard } from "@/components/VerdictCard"
import { OverviewTab } from "@/components/OverviewTab"
import { UrlForensicsTab } from "@/components/UrlForensicsTab"
import { ExplainabilityTab } from "@/components/ExplainabilityTab"
import { SafetyReportingTab } from "@/components/SafetyReportingTab"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"

export default function App() {
  const { data, loading, error, analyze, reset } = useAnalyzer()

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background ambient subtle gradients */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute top-0 left-1/4 w-[500px] h-[300px] bg-cyan-500/5 blur-[120px] rounded-full" />
        <div className="absolute top-1/3 right-1/4 w-[400px] h-[300px] bg-blue-600/5 blur-[140px] rounded-full" />
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 py-4 sm:py-6 flex flex-col gap-5">
        {/* Top Header */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-3">
            <div className="size-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-950/50">
              <div className="size-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <Shield className="size-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-slate-100">
                  AI SMS Safety Analyzer
                </h1>
                <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  v2.0
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Hybrid Machine Learning &bull; Offline URL Forensics &bull; TRAI Sender Verification
              </p>
            </div>
          </div>

          {/* Privacy & System Status Indicator */}
          <div className="flex items-center gap-2 self-start sm:self-auto bg-slate-900/80 border border-slate-800/80 rounded-lg px-3 py-1.5 shadow-sm">
            <Lock className="size-3.5 text-emerald-400 shrink-0" />
            <div className="text-[11px] text-slate-300">
              <span className="font-semibold text-emerald-400">Local / Private: </span>
              <span className="text-slate-400">
                Analysis runs through your configured local backend.
              </span>
            </div>
          </div>
        </header>

        {/* Global Error Banner */}
        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-950/20 p-4 text-xs text-rose-300 flex items-start gap-3 shadow-lg">
            <AlertCircle className="size-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold text-rose-200">Backend Communication Error</span>
              <p className="text-[11px] text-rose-300/90">{error}</p>
              <p className="text-[10px] text-rose-400/80">
                Ensure the FastAPI backend is running at <code className="bg-slate-900 px-1 py-0.5 rounded">http://127.0.0.1:8000</code>
              </p>
            </div>
          </div>
        )}

        {/* Top 2-Column Section: Input Form & Focal Verdict Card */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          {/* Left Column: Input Form (5 cols on lg) */}
          <div className="lg:col-span-6 xl:col-span-5">
            <AnalyzerForm
              onAnalyze={(msg, sender) => analyze({ message: msg, sender_id: sender })}
              loading={loading}
              onReset={reset}
            />
          </div>

          {/* Right Column: Focal Verdict Card (7 cols on lg) */}
          <div className="lg:col-span-6 xl:col-span-7">
            <VerdictCard data={data} loading={loading} />
          </div>
        </section>

        {/* Bottom Section: Forensic & Explainability Tabs */}
        {data && (
          <section className="mt-1">
            <Tabs defaultValue="overview" className="w-full">
              <div className="border-b border-slate-800/80 pb-1">
                <TabsList className="bg-slate-900/80 border border-slate-800 p-1 rounded-lg gap-1">
                  <TabsTrigger
                    value="overview"
                    className="text-xs px-3 py-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400 data-[state=active]:border data-[state=active]:border-cyan-500/30 text-slate-400"
                  >
                    Overview
                  </TabsTrigger>
                  <TabsTrigger
                    value="forensics"
                    className="text-xs px-3 py-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400 data-[state=active]:border data-[state=active]:border-cyan-500/30 text-slate-400"
                  >
                    URL Forensics
                    {data.urls_detected > 0 && (
                      <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-200">
                        {data.urls_detected}
                      </span>
                    )}
                  </TabsTrigger>
                  <TabsTrigger
                    value="explainability"
                    className="text-xs px-3 py-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400 data-[state=active]:border data-[state=active]:border-cyan-500/30 text-slate-400"
                  >
                    Explainability
                    {data.explainability.has_features && (
                      <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-200">
                        {data.explainability.nnz}
                      </span>
                    )}
                  </TabsTrigger>
                  <TabsTrigger
                    value="safety"
                    className="text-xs px-3 py-1.5 data-[state=active]:bg-cyan-500/10 data-[state=active]:text-cyan-400 data-[state=active]:border data-[state=active]:border-cyan-500/30 text-slate-400"
                  >
                    Safety & Reporting
                  </TabsTrigger>
                </TabsList>
              </div>

              <TabsContent value="overview">
                <OverviewTab data={data} />
              </TabsContent>

              <TabsContent value="forensics">
                <UrlForensicsTab urls={data.url_analysis} count={data.urls_detected} />
              </TabsContent>

              <TabsContent value="explainability">
                <ExplainabilityTab
                  explainability={data.explainability}
                  prediction={data.prediction}
                  confidence={data.confidence}
                />
              </TabsContent>

              <TabsContent value="safety">
                <SafetyReportingTab
                  guidance={data.safety_guidance}
                  reporting={data.official_reporting}
                  primaryAction={data.action_recommendation}
                />
              </TabsContent>
            </Tabs>
          </section>
        )}

        {/* Footer */}
        <footer className="mt-4 pt-4 border-t border-slate-900 flex flex-col sm:flex-row items-center justify-between gap-2 text-[11px] text-slate-500">
          <div className="flex items-center gap-1.5">
            <Terminal className="size-3 text-cyan-500" />
            <span>SWYNEX Technologies AI SMS Safety Analyzer &bull; Task 4 Modern Frontend</span>
          </div>
          <div>React 19 &bull; Vite 8 &bull; Tailwind CSS v4 &bull; FastAPI Local Bridge</div>
        </footer>
      </div>
    </div>
  )
}
