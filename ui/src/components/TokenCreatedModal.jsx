import { createPortal } from 'react-dom'
import { useCallback, useEffect, useId, useLayoutEffect, useRef } from 'react'
import CopyButton from './CopyButton'

export default function TokenCreatedModal({ token, title = 'Token Created', onClose }) {
  const titleId = useId()
  const descId = useId()
  const dialogRef = useRef(null)
  const previousFocusRef = useRef(null)

  // Stabilize onClose to prevent effect re-runs from identity changes.
  // useLayoutEffect (not bare assignment) avoids ref mutation during render,
  // which can cause tearing in React concurrent mode.
  const onCloseRef = useRef(onClose)
  useLayoutEffect(() => { onCloseRef.current = onClose }, [onClose])

  // Document-level Escape listener + focus management + scroll lock
  useEffect(() => {
    if (!token) return
    previousFocusRef.current = document.activeElement
    dialogRef.current?.focus()

    // Lock background scroll while modal is open.
    // Simple save/restore is sufficient — no other component locks scroll.
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    // Document-level listener: stopPropagation/preventDefault unnecessary —
    // nothing above document to propagate to, and Escape has no default action
    // in this context (div-based modal, not <dialog> or fullscreen).
    const onKeyDown = (e) => {
      if (e.key === 'Escape') onCloseRef.current()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = prevOverflow
      previousFocusRef.current?.focus()
    }
  }, [token]) // onClose accessed via ref to avoid identity-change re-runs (#43)

  // Focus trap: cycle Tab within the dialog
  const handleKeyDown = useCallback((e) => {
    if (e.key !== 'Tab') return
    const dialog = dialogRef.current
    if (!dialog) return
    const focusable = dialog.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    if (focusable.length === 0) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (e.shiftKey) {
      if (document.activeElement === first || document.activeElement === dialog) {
        e.preventDefault()
        last.focus()
      }
    } else {
      if (document.activeElement === last || document.activeElement === dialog) {
        e.preventDefault()
        first.focus()
      }
    }
  }, [])

  if (!token) return null
  // onClick handlers use onClose directly (always fresh from props on each render).
  // onCloseRef is only needed inside the useEffect which doesn't re-run on identity changes.
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className="bg-gray-950 border border-gray-700 rounded-lg shadow-xl max-w-lg w-full mx-4 outline-none"
        onClick={e => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <span id={titleId} className="text-sm font-semibold text-gray-200">{title}</span>
          <button onClick={onClose} aria-label="Close" className="text-gray-400 hover:text-gray-200 text-lg leading-none">
            &times;
          </button>
        </div>
        <div className="px-4 py-4 space-y-3">
          <p id={descId} className="text-sm text-gray-400">
            This token is shown only once. Copy it now and store it securely.
          </p>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={token}
              aria-label="Generated token"
              className="flex-1 px-3 py-2 rounded bg-black border border-gray-700 text-sm text-gray-200 font-mono"
            />
            <CopyButton text={token} />
          </div>
        </div>
        <div className="px-4 py-3 border-t border-gray-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded text-sm font-medium bg-teal-600 hover:bg-teal-500 text-white transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}
