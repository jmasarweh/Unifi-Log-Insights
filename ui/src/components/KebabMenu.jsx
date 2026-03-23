import { useState, useEffect, useRef, useCallback } from 'react'
import { createPortal } from 'react-dom'

/**
 * Reusable 3-dot kebab menu with portal-rendered dropdown.
 *
 * Props:
 * - children: render-prop `({ close }) => <menu items>` — called with a close function
 * - onOpen: optional callback fired when the menu opens (e.g. to close conflicting menus)
 * - className: optional extra classes for the trigger button
 */
export default function KebabMenu({ children, onOpen, className = '' }) {
  const [open, setOpen] = useState(false)
  const btnRef = useRef(null)
  const menuRef = useRef(null)
  const [pos, setPos] = useState({ top: 0, right: 0 })

  const close = useCallback(() => setOpen(false), [])

  const toggle = useCallback(() => {
    setOpen(prev => {
      const next = !prev
      if (next) {
        onOpen?.()
        // Position relative to button
        const rect = btnRef.current?.getBoundingClientRect()
        if (rect) {
          setPos({
            top: rect.bottom + 4,
            right: window.innerWidth - rect.right,
          })
        }
      }
      return next
    })
  }, [onOpen])

  // Close on click outside or Escape
  useEffect(() => {
    if (!open) return
    const handlePointerDown = (e) => {
      if (btnRef.current?.contains(e.target)) return
      if (menuRef.current?.contains(e.target)) return
      close()
    }
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('pointerdown', handlePointerDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, close])

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={toggle}
        className={`p-1 rounded text-gray-400 hover:text-teal-400 transition-colors ${className}`}
        aria-label="Menu"
        aria-haspopup="true"
        aria-expanded={open}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <circle cx="8" cy="3" r="1.5" />
          <circle cx="8" cy="8" r="1.5" />
          <circle cx="8" cy="13" r="1.5" />
        </svg>
      </button>

      {open && createPortal(
        <div
          ref={menuRef}
          className="fixed z-[60] min-w-[200px] py-1.5 bg-black border border-gray-700 rounded-lg shadow-xl"
          style={{
            top: pos.top,
            right: Math.max(8, pos.right),
            maxHeight: 'calc(100vh - 100px)',
            overflowY: 'auto',
          }}
        >
          {children({ close })}
        </div>,
        document.body
      )}
    </>
  )
}

/**
 * Shared Save/Load/Delete menu items used by both SankeyChart and TopIPPairs kebab menus.
 * Renders Save View (inline input), Load View (expandable sub-list with delete), and a separator.
 * Callers append their own unique action (Download Image or Export CSV) after this block.
 */
export function SaveLoadMenuItems({ onSaveView, onLoadView, savedViews, onDeleteView, close }) {
  const [saveName, setSaveName] = useState('')
  const [saveError, setSaveError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [showLoadList, setShowLoadList] = useState(false)

  const doSave = () => {
    if (!saveName.trim() || saving) return
    setSaving(true)
    setSaveError(null)
    Promise.resolve(onSaveView?.(saveName.trim()))
      .then(() => { setSaveName(''); close() })
      .catch(err => setSaveError(err.message || 'Failed to save view'))
      .finally(() => setSaving(false))
  }

  return (
    <>
      {/* Save View — inline input */}
      <div className="px-3 py-2">
        <div className="text-xs text-gray-500 uppercase tracking-wider mb-1.5">Save View</div>
        <div className="flex items-center gap-1.5">
          <input
            type="text"
            placeholder="View name..."
            value={saveName}
            onChange={e => { setSaveName(e.target.value); setSaveError(null) }}
            maxLength={100}
            className={`flex-1 bg-black text-gray-300 text-xs rounded px-2 py-1 border placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-teal-500/20 ${saveError ? 'border-red-500/60 focus:border-red-500' : 'border-gray-700 focus:border-teal-500'}`}
            onKeyDown={e => { if (e.key === 'Enter') doSave() }}
          />
          <button
            type="button"
            disabled={!saveName.trim() || saving}
            onClick={doSave}
            className="px-2 py-1 text-xs rounded bg-teal-600 text-white hover:bg-teal-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {saving ? '...' : 'Save'}
          </button>
        </div>
        {saveError && (
          <p className="text-xs text-red-400 mt-1">{saveError}</p>
        )}
      </div>

      <div className="border-t border-gray-800 my-1" />

      {/* Load View — expandable list */}
      <button
        type="button"
        onClick={() => setShowLoadList(v => !v)}
        className="w-full text-left px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 transition-colors flex items-center justify-between"
      >
        <span>Load View</span>
        <svg className={`w-3 h-3 text-gray-500 transition-transform ${showLoadList ? 'rotate-180' : ''}`} viewBox="0 0 10 6" fill="currentColor" aria-hidden="true"><path d="M0 0l5 6 5-6z" /></svg>
      </button>

      {showLoadList && (
        <div className="max-h-40 overflow-y-auto">
          {(!savedViews || savedViews.length === 0) ? (
            <div className="px-3 py-2 text-xs text-gray-600">No saved views</div>
          ) : savedViews.map(v => (
            <div key={v.id} className="flex items-center gap-1 px-3 py-1 hover:bg-gray-800 group">
              <button
                type="button"
                onClick={() => { onLoadView?.(v); close() }}
                className="flex-1 text-left text-xs text-gray-300 truncate"
              >
                {v.name}
              </button>
              <button
                type="button"
                onClick={e => { e.stopPropagation(); onDeleteView?.(v.id); close() }}
                className="shrink-0 text-gray-600 hover:text-red-400 text-xs opacity-0 group-hover:opacity-100 transition-opacity"
                title="Delete view"
                aria-label={`Delete view "${v.name}"`}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m2 0v14a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V6h14z"/></svg>
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="border-t border-gray-800 my-1" />
    </>
  )
}
