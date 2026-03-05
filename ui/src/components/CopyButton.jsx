import { useCallback, useEffect, useRef, useState } from 'react'

export default function CopyButton({ text, className = '', color = '' }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    return () => { if (timerRef.current) clearTimeout(timerRef.current) }
  }, [])

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }, [text])

  const colorClass = color || 'text-gray-500 hover:text-gray-300'

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Copy"
      className={`ml-1.5 ${colorClass} transition-colors inline-flex items-center ${className}`}
    >
      {copied ? (
        <span className="text-xs text-emerald-400">Copied</span>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <rect x="9" y="9" width="13" height="13" rx="2" strokeWidth="2" />
          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" strokeWidth="2" />
        </svg>
      )}
    </button>
  )
}
