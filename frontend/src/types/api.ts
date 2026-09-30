// ============================================================
// TypeScript types matching the FastAPI AnalyzeResponse schema
// Source: api.py — DO NOT invent fields
// ============================================================

export interface FeatureContribution {
  token: string
  contribution: number
  weight: number
  direction: string
}

export interface ExplainabilityResult {
  has_features: boolean
  nnz: number
  spam_features: FeatureContribution[]
  ham_features: FeatureContribution[]
  summary: string
}

export interface SafetyGuidance {
  title: string
  alert_type: string // "error" | "warning" | "info" | "success"
  actions: string[]
}

export interface OfficialReportingChannel {
  agency: string
  portal: string
  purpose: string
  url: string
  action: string
}

export interface UrlSignal {
  severity: string
  message: string
}

export interface UrlAnalysisItem {
  url: string
  defanged_url: string
  exit_code: number | null
  verdict: string | null   // "SAFE" | "SUSPICIOUS" | "PHISHING" | "UNAVAILABLE" | "TIMEOUT" | "ERROR"
  risk_score: number | null
  signals: UrlSignal[]
  error: string | null
}

export interface SenderIdInfo {
  sender_id: string | null
  is_valid_format: boolean | null
  note: string | null
  trai_portal_url: string
}

export interface AnalyzeResponse {
  // Synthesized verdict
  overall_state: string        // "SCAM" | "SPAM" | "UNCERTAIN" | "NO THREAT DETECTED"
  reason: string
  rule: string
  action_recommendation: string

  // SMS model output
  prediction: string           // "SPAM" | "NOT SPAM"
  confidence: number           // 0–100
  risk_level: string           // "LOW" | "MEDIUM" | "HIGH"
  indicators: string[]
  tokens_matched: number

  // URL forensics
  urls_detected: number
  url_analysis: UrlAnalysisItem[]

  // Explainability
  explainability: ExplainabilityResult

  // Guidance & reporting
  safety_guidance: SafetyGuidance
  official_reporting: OfficialReportingChannel[]
  sender_info: SenderIdInfo | null
}

export interface AnalyzeRequest {
  message: string
  sender_id?: string
}

export interface HealthResponse {
  status: string
  model_loaded: boolean
  model_error: string | null
  model_name: string
  barb_phish_available: boolean
}

export type OverallState = "SCAM" | "SPAM" | "UNCERTAIN" | "NO THREAT DETECTED"