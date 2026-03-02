import { useState, useEffect } from 'react'
import { fetchZoneMatrix } from '../api'
import { formatNumber } from '../utils'
import FullscreenToggle from './FullscreenToggle'

const THEMES = {
  dark: {
    labelBg: '#1f2937',
    labelText: '#d1d5db',
    mutedText: '#9ca3af',
    emptyBg: '#273549',
    emptyText: '#9fb1c8',
    tiers: [
      { bg: '#253447', color: '#d1d5db' },
      { bg: '#20527a', color: '#e0f2fe' },
      { bg: '#1d67a3', color: '#f0f9ff' },
      { bg: '#1d4ed8', color: '#dbeafe' },
      { bg: '#312e81', color: '#eef2ff' },
    ],
  },
  light: {
    labelBg: '#f8fafc',
    labelText: '#334155',
    mutedText: '#64748b',
    emptyBg: '#eef2f7',
    emptyText: '#64748b',
    tiers: [
      { bg: '#eff6ff', color: '#1e3a8a' },
      { bg: '#dbeafe', color: '#1e40af' },
      { bg: '#bfdbfe', color: '#1e3a8a' },
      { bg: '#93c5fd', color: '#1e3a8a' },
      { bg: '#3b82f6', color: '#eff6ff' },
    ],
  },
}

const getTier = (total, maxTotal, theme) => {
  if (!total || maxTotal <= 0) return null
  const r = Math.log10(total + 1) / Math.log10(maxTotal + 1)
  if (r < 0.2) return theme.tiers[0]
  if (r < 0.4) return theme.tiers[1]
  if (r < 0.6) return theme.tiers[2]
  if (r < 0.8) return theme.tiers[3]
  return theme.tiers[4]
}

// Shared card shell (matches header alignment with TopIPPairs)
function Shell({ children, headerContent, isFullscreen, onToggleFullscreen }) {
  return (
    <div className={`${isFullscreen ? 'fixed inset-0 z-50 bg-gray-950' : 'border border-gray-800 rounded-lg'} flex flex-col h-full overflow-hidden`}>
      <div className="flex h-11 items-center gap-3 px-4 border-b border-gray-800 shrink-0">
        <h3 className="text-xs font-semibold text-gray-300 uppercase tracking-wider shrink-0">Zone Traffic Matrix</h3>
        {headerContent}
        {onToggleFullscreen && (
          <FullscreenToggle isFullscreen={isFullscreen} onToggle={onToggleFullscreen} className="ml-auto" />
        )}
      </div>
      {children}
    </div>
  )
}

export default function ZoneMatrix({ filters, refreshKey, onCellClick, activeCell }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [tooltip, setTooltip] = useState(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const toggleFullscreen = () => setIsFullscreen(f => !f)
  const [themeMode, setThemeMode] = useState(() => {
    if (typeof document === 'undefined') return 'dark'
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'
  })
  const theme = themeMode === 'light' ? THEMES.light : THEMES.dark

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetchZoneMatrix(filters)
      .then(d => { if (!cancelled) setData(d) })
      .catch(err => { if (!cancelled) setError(err.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [filters.time_range, filters.rule_action, filters.direction, refreshKey])

  useEffect(() => {
    const root = document.documentElement
    const onThemeChange = () => {
      setThemeMode(root.getAttribute('data-theme') === 'light' ? 'light' : 'dark')
    }
    const obs = new MutationObserver(onThemeChange)
    obs.observe(root, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])

  if (loading) return <Shell isFullscreen={isFullscreen} onToggleFullscreen={toggleFullscreen}><div className="flex items-center justify-center h-48 text-xs text-gray-500">Loading zone matrix...</div></Shell>
  if (error) return <Shell isFullscreen={isFullscreen} onToggleFullscreen={toggleFullscreen}><div className="flex items-center justify-center h-48 text-xs text-red-400">{error}</div></Shell>
  if (!data?.cells?.length) return <Shell isFullscreen={isFullscreen} onToggleFullscreen={toggleFullscreen}><div className="flex items-center justify-center h-48 text-xs text-gray-500">No zone traffic data for this time range</div></Shell>

  const { cells, interfaces, labels } = data
  const cellMap = new Map()
  let maxTotal = 0
  for (const cell of cells) {
    cellMap.set(`${cell.interface_in}|${cell.interface_out}`, cell)
    if (cell.total > maxTotal) maxTotal = cell.total
  }

  const isActive = (iIn, iOut) =>
    activeCell && activeCell.interface_in === iIn && activeCell.interface_out === iOut

  const n = interfaces.length

  const showTooltip = (e, cell, iIn, iOut) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setTooltip({
      x: rect.left + rect.width / 2,
      y: rect.top - 4,
      cell,
      inLabel: labels[iIn] || iIn,
      outLabel: labels[iOut] || iOut,
    })
  }

  return (
    <Shell headerContent={<span className="portrait:hidden text-[11px]" style={{ color: theme.mutedText }}>Click a zone pair to filter</span>} isFullscreen={isFullscreen} onToggleFullscreen={toggleFullscreen}>
      <div className="overflow-auto flex-1 min-h-0 scroll-fade p-4">
        <table className="w-full border-separate text-[11px]" style={{ borderSpacing: 3 }}>
          <tbody>
            {/* "Destination" label */}
            <tr>
              <td />
              <td />
              <td colSpan={n} className="text-center text-[10px] pb-0.5 uppercase tracking-widest font-normal" style={{ color: theme.mutedText }}>
                Destination
              </td>
            </tr>

            {/* Header: empty corner + destination zone labels */}
            <tr>
              <td className="w-4" />
              <td className="rounded-tl-lg" style={{ backgroundColor: theme.labelBg }} />
              {interfaces.map((iOut, i) => (
                <td
                  key={iOut}
                  className={`px-3 py-2.5 font-medium text-center whitespace-nowrap ${
                    i === n - 1 ? 'rounded-tr-lg' : ''
                  }`}
                  style={{ backgroundColor: theme.labelBg, color: theme.labelText }}
                >
                  {labels[iOut] || iOut}
                </td>
              ))}
            </tr>

            {/* Data rows */}
            {interfaces.map((iIn, ri) => (
              <tr key={iIn}>
                {ri === 0 && (
                  <td
                    rowSpan={n}
                    className="text-[10px] uppercase tracking-widest w-4 select-none font-normal"
                    style={{
                      color: theme.mutedText,
                      backgroundColor: 'transparent',
                      writingMode: 'vertical-lr',
                      transform: 'rotate(180deg)',
                    }}
                  >
                    <div className="flex items-center justify-center h-full">Source</div>
                  </td>
                )}
                <td className={`px-3 py-2.5 font-medium whitespace-nowrap text-right ${
                  ri === n - 1 ? 'rounded-bl-lg' : ''
                }`} style={{ backgroundColor: theme.labelBg, color: theme.labelText }}>
                  {labels[iIn] || iIn}
                </td>

                {interfaces.map((iOut, ci) => {
                  const cell = cellMap.get(`${iIn}|${iOut}`)
                  const active = isActive(iIn, iOut)
                  const isLast = ri === n - 1 && ci === n - 1
                  const corner = isLast ? 'rounded-br-lg' : ''

                  if (!cell) {
                    return (
                      <td key={iOut} className={`p-0 ${corner}`}>
                        <div
                          className={`px-3 py-2.5 text-center rounded-md border-2 border-transparent ${corner}`}
                          style={{ backgroundColor: theme.emptyBg, color: theme.emptyText }}
                        >
                          &ndash;
                        </div>
                      </td>
                    )
                  }

                  const tier = getTier(cell.total, maxTotal, theme)

                  return (
                    <td key={iOut} className={`p-0 ${corner}`}>
                      <button
                        onClick={() => onCellClick?.({ interface_in: iIn, interface_out: iOut, in_label: labels[iIn] || iIn, out_label: labels[iOut] || iOut })}
                        className={`block w-full px-3 py-2.5 text-center font-medium whitespace-nowrap transition-all cursor-pointer rounded-md ${
                          active
                            ? `border-chase border-chase-blue ${corner}`
                            : `border-2 border-transparent hover:border-blue-400/40 ${corner}`
                        }`}
                        style={!active && tier ? { background: tier.bg, color: tier.color } : undefined}
                        onMouseEnter={(e) => showTooltip(e, cell, iIn, iOut)}
                        onMouseLeave={() => setTooltip(null)}
                      >
                        {formatNumber(cell.total)}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>

        {tooltip && (
          <div
            className="fixed z-50 px-3 py-2 rounded-md bg-gray-900 border border-gray-700 text-xs text-gray-200 whitespace-nowrap pointer-events-none shadow-lg"
            style={{ left: tooltip.x, top: tooltip.y, transform: 'translate(-50%, -100%)' }}
          >
            <div className="font-medium text-gray-100 mb-1">{tooltip.inLabel} → {tooltip.outLabel}</div>
            <div className="tabular-nums">{formatNumber(tooltip.cell.total)} total events</div>
            <div className="flex gap-3 tabular-nums">
              <span className="text-emerald-400">{formatNumber(tooltip.cell.allow_count)} allow</span>
              <span className="text-red-400">{formatNumber(tooltip.cell.block_count)} block</span>
            </div>
            <div className="text-gray-400 tabular-nums">{formatNumber(tooltip.cell.unique_pairs)} unique pairs</div>
          </div>
        )}
      </div>
    </Shell>
  )
}
