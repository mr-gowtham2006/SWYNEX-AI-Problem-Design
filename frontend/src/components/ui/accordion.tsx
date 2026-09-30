import React, { useState } from "react"
import { ChevronDown } from "lucide-react"
import { cn } from "@/lib/utils"

interface AccordionItemProps {
  title: string
  subtitle?: string
  badge?: React.ReactNode
  icon?: React.ReactNode
  defaultOpen?: boolean
  children: React.ReactNode
  className?: string
}

export const AccordionItem: React.FC<AccordionItemProps> = ({
  title,
  subtitle,
  badge,
  icon,
  defaultOpen = false,
  children,
  className,
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div
      className={cn(
        "rounded-xl border border-slate-800/80 bg-slate-900/50 transition-all overflow-hidden",
        isOpen ? "border-slate-700/80 shadow-md" : "hover:border-slate-800",
        className
      )}
    >
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-3.5 text-left transition-colors hover:bg-slate-800/40 cursor-pointer select-none"
        aria-expanded={isOpen}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          {icon && <span className="shrink-0">{icon}</span>}
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-200 tracking-wide">
                {title}
              </span>
              {badge}
            </div>
            {subtitle && (
              <p className="text-[11px] text-slate-400 truncate mt-0.5">{subtitle}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0 ml-3">
          <span className="text-[11px] text-slate-400 font-medium hidden sm:inline">
            {isOpen ? "Collapse" : "Inspect"}
          </span>
          <ChevronDown
            className={cn(
              "size-4 text-slate-400 transition-transform duration-200",
              isOpen && "rotate-180 text-cyan-400"
            )}
          />
        </div>
      </button>

      {isOpen && (
        <div className="p-3.5 pt-1 border-t border-slate-800/60 animate-in fade-in-50 duration-200">
          {children}
        </div>
      )}
    </div>
  )
}
