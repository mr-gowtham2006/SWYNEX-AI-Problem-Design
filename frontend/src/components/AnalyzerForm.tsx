import React, { useState } from "react"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Send, Loader2, RefreshCw, MessageSquare, Tag, Sparkles } from "lucide-react"

interface AnalyzerFormProps {
  onAnalyze: (message: string, senderId?: string) => void
  loading: boolean
  onReset: () => void
}

const SAMPLE_MESSAGES = [
  {
    label: "Normal SMS",
    category: "Ham",
    sender: "AM-SWIGGY",
    text: "Hey! Your order has been picked up and will arrive in 15 minutes. Enjoy your meal!",
  },
  {
    label: "Obvious Spam",
    category: "Spam",
    sender: "TX-WINNER",
    text: "CONGRATULATIONS! You have won £1,000 cash or a prize guaranteed! Call 09050000301 now to claim. T&Cs apply.",
  },
  {
    label: "Phishing URL",
    category: "Scam",
    sender: "AD-SBIINB",
    text: "Dear customer, your SBI NetBanking account will be suspended today. Update your KYC immediately at http://sbi-kyc-verify-portal.tk to keep access.",
  },
  {
    label: "Hinglish / OOV",
    category: "Uncertain",
    sender: "9876543210",
    text: "Bhai kal sham ko meeting me aana mat bhulna, sab dost log aa rahe hai chai pe.",
  },
  {
    label: "Multiple URLs",
    category: "Multi-URL",
    sender: "VM-OFFERS",
    text: "Exclusive flash sale! View deals: http://deal-hub.xyz/offer or track your cart: http://track-status.net/login immediately.",
  },
]

export const AnalyzerForm: React.FC<AnalyzerFormProps> = ({
  onAnalyze,
  loading,
  onReset,
}) => {
  const [message, setMessage] = useState("")
  const [senderId, setSenderId] = useState("")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!message.trim() || loading) return
    onAnalyze(message.trim(), senderId.trim() || undefined)
  }

  const handleSelectSample = (sample: (typeof SAMPLE_MESSAGES)[0]) => {
    setMessage(sample.text)
    setSenderId(sample.sender)
    onAnalyze(sample.text, sample.sender)
  }

  const handleClear = () => {
    setMessage("")
    setSenderId("")
    onReset()
  }

  const charCount = message.length

  return (
    <Card className="border-slate-800 bg-slate-900/70 shadow-xl backdrop-blur-sm">
      <CardHeader className="pb-3 pt-4 px-5 border-b border-slate-800/80">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <MessageSquare className="size-4 text-cyan-400" />
            Analyze Message
          </CardTitle>
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
            <span>{charCount} chars</span>
            {charCount > 160 && (
              <span className="text-amber-400 font-medium">({Math.ceil(charCount / 160)} SMS)</span>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-5 pt-4 space-y-4">
        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div className="space-y-1.5">
            <label
              htmlFor="sms-input"
              className="text-xs font-medium text-slate-300 flex items-center justify-between"
            >
              <span>SMS Content <span className="text-rose-400">*</span></span>
              <span className="text-[11px] text-slate-400">Paste raw message text</span>
            </label>
            <Textarea
              id="sms-input"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="e.g. Urgent: Your account has been locked. Verify immediately at http://..."
              className="min-h-[110px] resize-none border-slate-800 bg-slate-950/80 text-sm text-slate-100 placeholder:text-slate-500 focus-visible:ring-cyan-500/50 focus-visible:border-cyan-500/50"
              disabled={loading}
            />
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="sender-input"
              className="text-xs font-medium text-slate-300 flex items-center justify-between"
            >
              <span className="flex items-center gap-1.5">
                <Tag className="size-3 text-slate-400" />
                Sender Header / Phone Number
              </span>
              <span className="text-[11px] text-slate-400">Optional (e.g. VK-HDFCBK)</span>
            </label>
            <input
              id="sender-input"
              type="text"
              value={senderId}
              onChange={(e) => setSenderId(e.target.value)}
              placeholder="e.g. VK-HDFCBK or +919876543210"
              className="flex h-9 w-full rounded-md border border-slate-800 bg-slate-950/80 px-3 py-1 text-sm text-slate-100 placeholder:text-slate-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/50 focus-visible:border-cyan-500/50 disabled:opacity-50"
              disabled={loading}
            />
          </div>

          <div className="flex items-center gap-2 pt-1">
            <Button
              type="submit"
              disabled={!message.trim() || loading}
              className="flex-1 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold shadow-md shadow-cyan-950/40 transition-all cursor-pointer"
            >
              {loading ? (
                <>
                  <Loader2 className="size-4 animate-spin mr-1.5 text-slate-950" />
                  Analyzing Security Signals...
                </>
              ) : (
                <>
                  <Send className="size-4 mr-1.5" />
                  Analyze Security
                </>
              )}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={handleClear}
              disabled={loading || (!message && !senderId)}
              className="border-slate-800 text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 px-3"
              title="Clear input"
            >
              <RefreshCw className="size-4" />
            </Button>
          </div>
        </form>

        {/* Quick Sample Messages */}
        <div className="pt-2 border-t border-slate-800/80 space-y-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 font-medium">
            <Sparkles className="size-3 text-cyan-400" />
            <span>Load Test Scenarios</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SAMPLE_MESSAGES.map((sample) => (
              <button
                key={sample.label}
                type="button"
                onClick={() => handleSelectSample(sample)}
                disabled={loading}
                className="text-[11px] px-2.5 py-1 rounded bg-slate-800/60 hover:bg-slate-700/80 text-slate-300 hover:text-slate-100 border border-slate-700/60 transition-colors disabled:opacity-50 cursor-pointer"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
