import { useState, useCallback } from "react"
import type { AnalyzeRequest, AnalyzeResponse } from "@/types/api"

const API_BASE = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "")

export interface AnalyzerState {
  data: AnalyzeResponse | null
  loading: boolean
  error: string | null
  apiUrl: string
}

export function useAnalyzer() {
  const [state, setState] = useState<AnalyzerState>({
    data: null,
    loading: false,
    error: null,
    apiUrl: API_BASE,
  })

  const analyze = useCallback(async (req: AnalyzeRequest) => {
    setState((prev) => ({ ...prev, data: null, loading: true, error: null }))
    try {
      const res = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      })
      if (!res.ok) {
        const detail = await res.text()
        throw new Error(`API error ${res.status}: ${detail}`)
      }
      const data: AnalyzeResponse = await res.json()
      setState((prev) => ({ ...prev, data, loading: false, error: null }))
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error"
      setState((prev) => ({ ...prev, data: null, loading: false, error: msg }))
    }
  }, [])

  const reset = useCallback(() => {
    setState((prev) => ({ ...prev, data: null, loading: false, error: null }))
  }, [])

  return { ...state, analyze, reset }
}