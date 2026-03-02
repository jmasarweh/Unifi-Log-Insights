import { useState, useEffect, useMemo, useRef } from 'react'
import { sankey as d3Sankey, sankeyLinkHorizontal } from 'd3-sankey'
import { fetchFlowGraph } from '../api'
import { formatNumber, formatServiceName, getInterfaceName } from '../utils'
import FullscreenToggle from './FullscreenToggle'

const DIMENSION_OPTIONS = [
  { value: 'src_ip', label: 'Source IP' },
  { value: 'dst_ip', label: 'Dest IP' },
  { value: 'dst_port', label: 'Dest Port' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'service_name', label: 'Service' },
  { value: 'direction', label: 'Direction' },
  { value: 'interface_in', label: 'Interface In' },
  { value: 'interface_out', label: 'Interface Out' },
]

const COLUMN_COLORS = [
  { node: '#3b82f6', link: 'rgba(59,130,246,0.45)' },  // blue
  { node: '#a855f7', link: 'rgba(168,85,247,0.45)' },   // purple
  { node: '#22c55e', link: 'rgba(34,197,94,0.45)' },    // green
]

const OTHER_COLOR = { node: '#6b7280', link: 'rgba(107,114,128,0.35)' }

// Margin for column headers at top
const HEADER_HEIGHT = 24

const linkPath = sankeyLinkHorizontal()

const getIfaceBadgeClass = (iface, wanList = []) => {
  if (wanList.includes(iface))
    return 'bg-blue-500/15 text-blue-400 border-blue-500/30'
  if (iface.startsWith('br'))
    return 'bg-violet-500/15 text-violet-400 border-violet-500/30'
  if (iface.startsWith('tun') || iface.startsWith('wg') || iface.startsWith('vti'))
    return 'bg-teal-500/15 text-teal-400 border-teal-500/30'
  return 'bg-gray-500/15 text-gray-400 border-gray-500/30'
}

export default function SankeyChart({ filters, refreshKey, onNodeClick, activeFilter, hostIp }) {
  const [dims, setDims] = useState(['src_ip', 'dst_port', 'dst_ip'])
  const [topN, setTopN] = useState(15)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [tooltip, setTooltip] = useState(null)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const svgRef = useRef(null)
  const containerRef = useRef(null)
  const [chartWidth, setChartWidth] = useState(0)

  // Measure container width (use clientWidth minus scrollbar to prevent resize loop)
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const measure = () => {
      // clientWidth excludes scrollbar, so SVG never triggers scrollbar toggle
      const w = el.clientWidth
      setChartWidth(prev => Math.abs(prev - w) > 2 ? w : prev)
    }
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetchFlowGraph({
      ...filters,
      dimensions: dims.join(','),
      top_n: topN,
      ip: hostIp || undefined,
    })
      .then(d => { if (!cancelled) setData(d) })
      .catch(err => { if (!cancelled) setError(err.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [filters.time_range, filters.rule_action, filters.direction, dims, topN, hostIp, refreshKey])

  const setDim = (index, value) => {
    setDims(prev => {
      const next = [...prev]
      next[index] = value
      return next
    })
  }

  const dimLabel = (value) => DIMENSION_OPTIONS.find(o => o.value === value)?.label || value

  const layout = useMemo(() => {
    if (!data?.nodes?.length || !data?.links?.length || !chartWidth) return null

    // Build index map
    const nodeMap = new Map(data.nodes.map((n, i) => [n.id, i]))
    const nodes = data.nodes.map(n => ({ ...n }))
    const links = data.links
      .filter(l => nodeMap.has(l.source) && nodeMap.has(l.target))
      .map(l => ({
        source: nodeMap.get(l.source),
        target: nodeMap.get(l.target),
        value: l.value,
      }))

    if (!links.length) return null

    const width = Math.max(280, chartWidth - 24) // subtract p-3 padding (12px each side)
    const height = Math.max(300, nodes.length * 20)
    const labelMargin = width < 400 ? 20 : 40

    try {
      const generator = d3Sankey()
        .nodeId(d => d.index)
        .nodeWidth(12)
        .nodePadding(6)
        .nodeSort(null)
        .extent([[labelMargin, HEADER_HEIGHT + 4], [width - labelMargin, height - 1]])

      const graph = generator({ nodes, links })
      return { ...graph, width, height }
    } catch (err) {
      console.warn('Sankey layout failed (%d nodes, %d links):', nodes.length, links.length, err)
      return null
    }
  }, [data, chartWidth])

  // Sorted unique x0 positions (one per column) — cached to avoid O(n²) in color lookups
  const sortedCols = useMemo(() => {
    if (!layout) return []
    return [...new Set(layout.nodes.map(n => n.x0))].sort((a, b) => a - b)
  }, [layout])

  const getNodeColor = (node) => {
    if (node.label === 'Other') return OTHER_COLOR.node
    if (!sortedCols.length) return COLUMN_COLORS[0].node
    const colIdx = sortedCols.indexOf(node.x0)
    return (COLUMN_COLORS[colIdx] || COLUMN_COLORS[0]).node
  }

  const getLinkColor = (link) => {
    const srcNode = link.source
    if (srcNode.label === 'Other') return OTHER_COLOR.link
    if (!sortedCols.length) return COLUMN_COLORS[0].link
    const colIdx = sortedCols.indexOf(srcNode.x0)
    return (COLUMN_COLORS[colIdx] || COLUMN_COLORS[0]).link
  }

  const handleMouseMove = (e, label, value) => {
    const el = containerRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    const total = data?.nodes?.reduce((sum, n) => sum + n.value, 0) / dims.length || 1
    const pct = ((value / total) * 100).toFixed(1)
    setTooltip({
      x: e.clientX - rect.left + el.scrollLeft + 12,
      y: e.clientY - rect.top + el.scrollTop - 10,
      text: `${label}: ${formatNumber(value)} (${pct}%)`,
    })
  }

  // Column headers (dimension labels) positioned above each column
  const columnHeaders = useMemo(() => {
    if (!layout) return []
    const cols = [...new Set(layout.nodes.map(n => n.x0))].sort((a, b) => a - b)
    return cols.map((x0, i) => {
      const nodesInCol = layout.nodes.filter(n => n.x0 === x0)
      const x1 = nodesInCol[0]?.x1 || x0 + 12
      const center = (x0 + x1) / 2
      // Anchor left/right headers to SVG edges so they don't clip
      const isFirst = i === 0
      const isLast = i === cols.length - 1
      return {
        x: isFirst ? 4 : isLast ? layout.width - 4 : center,
        anchor: isFirst ? 'start' : isLast ? 'end' : 'middle',
        label: dimLabel(dims[i]),
        color: (COLUMN_COLORS[i] || COLUMN_COLORS[0]).node,
      }
    })
  }, [layout, dims])

  // Render node label based on type
  const renderLabel = (node, isDimmed) => {
    const nodeH = node.y1 - node.y0
    if (nodeH <= 6) return null

    const isLeft = node.x0 < layout.width / 2
    const x = isLeft ? node.x1 + 6 : node.x0 - 6
    const cy = (node.y0 + node.y1) / 2
    const anchor = isLeft ? 'start' : 'end'
    const isOther = node.label === 'Other'
    const opacity = isDimmed ? 0.3 : 1

    // Interface badge (foreignObject for HTML with Tailwind classes)
    if ((node.type === 'interface_in' || node.type === 'interface_out') && !isOther) {
      const label = data?.interface_labels?.[node.label] || getInterfaceName(node.label)
      const badgeCls = getIfaceBadgeClass(node.label, data?.wan_interfaces)
      const foW = 130
      const foX = isLeft ? x : x - foW
      return (
        <foreignObject x={foX} y={cy - 10} width={foW} height={22}
                        className="pointer-events-none" style={{ opacity }}>
          <div className={`flex ${isLeft ? 'justify-start' : 'justify-end'}`}>
            <span className={`text-[9px] font-medium whitespace-nowrap px-1.5 py-0.5 rounded border ${badgeCls}`}>
              {label}
            </span>
          </div>
        </foreignObject>
      )
    }

    // IP nodes — device name + badge (VLAN / VPN) matching LogTable IPCell pattern
    const isIp = (node.type === 'src_ip' || node.type === 'dst_ip') && !isOther
    if (isIp) {
      const deviceName = data?.device_names?.[node.label]
      const vlan = data?.gateway_vlans?.[node.label]
      const vpnBadge = data?.vpn_badges?.[node.label]
      const hasBadge = vlan != null || vpnBadge
      const hasExtra = deviceName || hasBadge

      if (hasExtra && nodeH > 12) {
        const foW = 180
        const foX = isLeft ? x : x - foW
        const foH = deviceName ? 32 : 24
        return (
          <foreignObject x={foX} y={cy - foH / 2} width={foW} height={foH}
                          className="pointer-events-none" style={{ opacity }}>
            <div className={`flex flex-col ${isLeft ? 'items-start' : 'items-end'}`}>
              {(deviceName || hasBadge) && (
                <div className="flex items-center gap-1">
                  {deviceName && (
                    <span className="text-[11px] font-medium text-gray-200 whitespace-nowrap overflow-hidden text-ellipsis max-w-[120px]">
                      {deviceName}
                    </span>
                  )}
                  {vlan != null ? (
                    <span className="text-[10px] font-medium whitespace-nowrap px-1 py-0 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0">
                      VLAN {vlan}
                    </span>
                  ) : vpnBadge ? (
                    <span className="text-[10px] font-medium whitespace-nowrap px-1 py-0 rounded bg-teal-500/15 text-teal-400 border border-teal-500/30 shrink-0">
                      {vpnBadge}
                    </span>
                  ) : null}
                </div>
              )}
              <span className="text-[12px] font-mono text-gray-500 whitespace-nowrap">
                {node.label}
              </span>
            </div>
          </foreignObject>
        )
      }
    }

    // Service name (uppercase except Unknown)
    let displayLabel = node.label
    if (node.type === 'service_name' && !isOther) {
      displayLabel = formatServiceName(node.label)
    }

    // Default single line
    const truncLabel = displayLabel.length > 28 ? displayLabel.slice(0, 26) + '\u2026' : displayLabel
    return (
      <text x={x} y={cy} textAnchor={anchor}
            dominantBaseline="central" className="text-gray-200" fill="currentColor"
            style={{ fontSize: '11px', fontWeight: 500, pointerEvents: 'none', opacity }}>
        {truncLabel}
      </text>
    )
  }

  return (
    <div className={`${isFullscreen ? 'fixed inset-0 z-50 bg-gray-950' : 'border border-gray-800 rounded-lg'} flex flex-col h-full overflow-hidden`}>
      {/* Header — single row, matched height with TopIPPairs */}
      <div className="flex flex-wrap h-auto min-h-[2.75rem] items-center gap-2 sm:gap-3 px-4 py-2 sm:py-0 border-b border-gray-800 shrink-0 overflow-x-auto">
        <h3 className="hidden sm:block text-xs font-semibold text-gray-300 uppercase tracking-wider mr-1">Flow Graph</h3>

        <div className="hidden sm:block h-5 w-px bg-gray-700" />

        {/* Dimension selectors with labels */}
        {dims.map((d, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <span className="hidden sm:inline text-[10px] text-gray-500 uppercase tracking-wider">{['Left', 'Center', 'Right'][i]}</span>
            <select
              value={d}
              onChange={e => setDim(i, e.target.value)}
              className="bg-gray-800/50 text-gray-300 text-xs rounded px-2 py-0.5 border border-gray-700 focus:outline-none focus:border-gray-500 cursor-pointer"
            >
              {DIMENSION_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value} disabled={dims.includes(opt.value) && dims[i] !== opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        ))}

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1.5">
          <label htmlFor="sankey-top-n" className="text-[10px] text-gray-500 uppercase tracking-wider" title="Number of top values per dimension">Top N</label>
          <input
            id="sankey-top-n"
            type="number"
            min={3}
            max={50}
            value={topN}
            onChange={e => setTopN(Math.max(3, Math.min(50, Number(e.target.value) || 3)))}
            className="w-12 bg-gray-800/50 text-gray-300 text-xs rounded px-1.5 py-0.5 border border-gray-700 text-center focus:outline-none focus:border-gray-500"
          />
        </div>

        {data?.meta?.capped && (
          <span className="text-[10px] text-amber-400">
            Capped to top {data.meta.applied_top_n} per dimension
          </span>
        )}

        <FullscreenToggle isFullscreen={isFullscreen} onToggle={() => setIsFullscreen(f => !f)} className="ml-auto" />
      </div>

      {/* Chart — scrollable vertically and horizontally (originally vertical-only; horizontal added for mobile) */}
      <div className="relative p-3 overflow-y-auto overflow-x-auto min-h-0 flex-1" ref={containerRef}>
        {loading ? (
          <div className="flex items-center justify-center h-48 text-xs text-gray-500">Loading flow data...</div>
        ) : error ? (
          <div className="flex items-center justify-center h-48 text-xs text-red-400">{error}</div>
        ) : !layout ? (
          <div className="flex items-center justify-center h-48 text-xs text-gray-500">No flow data for this time range</div>
        ) : (
          <div onMouseLeave={() => setTooltip(null)}>
            <svg
              ref={svgRef}
              width={layout.width}
              height={layout.height}
            >
              {/* Column headers */}
              {columnHeaders.map((col, i) => (
                <text
                  key={i}
                  x={col.x}
                  y={12}
                  textAnchor={col.anchor}
                  className="font-semibold uppercase"
                  fill={col.color}
                  style={{ fontSize: '10px', letterSpacing: '0.05em', pointerEvents: 'none' }}
                >
                  {col.label}
                </text>
              ))}

              {/* Links */}
              <g fill="none">
                {layout.links.map((link, i) => (
                  <path
                    key={i}
                    d={linkPath(link)}
                    stroke={getLinkColor(link)}
                    strokeWidth={Math.max(1, link.width)}
                    fill="none"
                    opacity={0.3}
                    className="hover:opacity-100 transition-opacity"
                    onMouseMove={e => handleMouseMove(e, `${link.source.label} \u2192 ${link.target.label}`, link.value)}
                    onMouseLeave={() => setTooltip(null)}
                  />
                ))}
              </g>

              {/* Nodes */}
              {layout.nodes.map((node, i) => {
                const isOther = node.label === 'Other'
                const isPlaceholder = node.label === 'Unknown' || node.label === 'unknown'
                const isClickable = !isOther && !isPlaceholder && onNodeClick
                const isActive = activeFilter && activeFilter.type === node.type && activeFilter.value === node.label
                const isDimmed = activeFilter && activeFilter.type === node.type && !isActive && !isOther
                return (
                <g key={i}>
                  <rect
                    x={node.x0}
                    y={node.y0}
                    width={node.x1 - node.x0}
                    height={Math.max(2, node.y1 - node.y0)}
                    fill={getNodeColor(node)}
                    rx={2}
                    opacity={isDimmed ? 0.3 : isOther ? 0.5 : isActive ? 1 : 0.85}
                    strokeDasharray={isOther ? '3,2' : undefined}
                    stroke={isActive ? '#ffffff' : isOther ? '#6b7280' : 'none'}
                    strokeWidth={isActive ? 2 : 1}
                    onMouseMove={e => handleMouseMove(e, node.label, node.value)}
                    onMouseLeave={() => setTooltip(null)}
                    onClick={isClickable ? () => onNodeClick({ type: node.type, value: node.label }) : undefined}
                    className={isClickable ? 'cursor-pointer' : 'cursor-default'}
                  />
                  {renderLabel(node, isDimmed)}
                </g>
                )
              })}
            </svg>

            {/* HTML tooltip — positioned over container, not inside SVG */}
            {tooltip && (
              <div
                className="absolute z-10 px-2.5 py-1.5 rounded bg-gray-900 border border-gray-700 text-xs text-gray-200 whitespace-nowrap pointer-events-none shadow-lg"
                style={{ left: tooltip.x, top: tooltip.y }}
              >
                {tooltip.text}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
