import { useState, useCallback } from "react"
import type { AnalyzeRequest, AnalyzeResponse } from "@/types/api"

const API_BASE = "http://127.0.0.1:8000"

export interface AnalyzerState {
  data: AnalyzeResponse | null
  loading: boolean
  error: string | null
}

export function useAnalyzer() {
  const [state, setState] = useState<AnalyzerState>({
    data: null,
    loading: false,
    error: null,
  })

  const analyze = useCallback(async (req: AnalyzeRequest) => {
    setState({ data: null, loading: true, error: null })
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
      setState({ data, loading: false, error: null })
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error"
      setState({ data: null, loading: false, error: msg })
    }
  }, [])

  const reset = useCallback(() => {
    setState({ data: null, loading: false, error: null })
  }, [])

  return { ...state, analyze, reset }
}