import React, { useState, useEffect, useCallback, useRef } from 'react'
import { fetchLogs, fetchLog, getExportUrl, fetchUiSettings } from '../api'
import { TR_KEY } from '../utils'
import FilterBar from './FilterBar'
import LogTable from './LogTable'
import Pagination from './Pagination'

const DEFAULT_FILTERS = {
  time_range: '24h',
  log_type: null,
  rule_action: null,
  direction: null,
  ip: null,
  src_ip: null,
  dst_ip: null,
  rule_name: null,
  search: null,
  service: null,
  country: null,
  asn: null,
  dst_port: null,
  src_port: null,
  protocol: null,
  time_from: null,
  time_to: null,
  page: 1,
  per_page: 50,
  sort: 'timestamp',
  order: 'desc',
}

const STORAGE_KEY = 'unifi-log-insight:log-types'
const ACTION_STORAGE_KEY = 'unifi-log-insight:rule-action'
const DIRECTION_STORAGE_KEY = 'unifi-log-insight:direction'
const COLUMNS_STORAGE_KEY = 'unifi-log-insight:hidden-columns'

const TOGGLEABLE_COLUMNS = [
  { key: 'country', label: 'Country' },
  { key: 'asn', label: 'ASN' },
  { key: 'proto', label: 'Protocol' },
  { key: 'rule', label: 'Rule / Info' },
  { key: 'threat', label: 'AbuseIPDB' },
  { key: 'categories', label: 'Categories' },
]

export default function LogStream({ version, latestRelease, maxFilterDays, drillFilters, onDrillConsumed, interfaces: prefetchedInterfaces }) {
  const [filters, setFilters] = useState(() => {
    const restored = { ...DEFAULT_FILTERS }
    try {
      restored.time_range = sessionStorage.getItem(TR_KEY) || '24h'
      const savedTypes = localStorage.getItem(STORAGE_KEY)
      if (savedTypes) restored.log_type = savedTypes
      const savedAction = localStorage.getItem(ACTION_STORAGE_KEY)
      if (savedAction) restored.rule_action = savedAction
      const savedDirection = localStorage.getItem(DIRECTION_STORAGE_KEY)
      if (savedDirection) restored.direction = savedDirection
    } catch (e) { /* private browsing */ }
    return restored
  })
  const [data, setData] = useState({ data: [], total: 0, page: 1, pages: 0 })
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [detailedLog, setDetailedLog] = useState(null)
  const [pendingCount, setPendingCount] = useState(0)
  const [hiddenColumns, setHiddenColumns] = useState(() => {
    try {
      const saved = localStorage.getItem(COLUMNS_STORAGE_KEY)
      if (saved) return new Set(JSON.parse(saved))
    } catch (e) { /* private browsing */ }
    return new Set()
  })
  const [uiSettings, setUiSettings] = useState(null)
  const [showColumnsMenu, setShowColumnsMenu] = useState(false)
  const columnsMenuRef = useRef(null)
  const intervalRef = useRef(null)
  const pendingRef = useRef(null)
  const scrollRef = useRef(null)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [drillContext, setDrillContext] = useState(null)

  // Apply drill filters from FlowView (F1/F4/F8)
  useEffect(() => {
    if (!drillFilters) return
    setFilters(prev => ({
      ...DEFAULT_FILTERS,
      time_range: drillFilters.time_range || prev.time_range,
      ip: null,
      src_ip: drillFilters.src_ip || null,
      dst_ip: drillFilters.dst_ip || null,
      dst_port: drillFilters.dst_port?.toString() || null,
      service: drillFilters.service || null,
      log_type: 'firewall',
      page: 1,
      per_page: prev.per_page,
      sort: prev.sort,
      order: prev.order,
    }))
    // Build display string for drill indicator banner
    const parts = []
    if (drillFilters.src_ip) parts.push(drillFilters.src_ip)
    if (drillFilters.dst_ip) parts.push(drillFilters.dst_ip)
    const label = parts.join(' \u2192 ')
    const portProto = [
      drillFilters.dst_port && `:${drillFilters.dst_port}`,
      drillFilters.service,
    ].filter(Boolean).join(' ')
    setDrillContext(label + (portProto ? ` ${portProto}` : ''))
    onDrillConsumed?.()
  }, [drillFilters]) // eslint-disable-line react-hooks/exhaustive-deps

  const clearDrill = useCallback(() => {
    setDrillContext(null)
    setFilters(prev => ({ ...DEFAULT_FILTERS, per_page: prev.per_page, sort: prev.sort, order: prev.order }))
    window.dispatchEvent(new Event('returnFromDrill'))
  }, [])

  // Load UI display settings
  useEffect(() => {
    fetchUiSettings().then(setUiSettings).catch(() => {})
  }, [])

  // Persist filter toggles to localStorage
  useEffect(() => {
    try {
      if (filters.log_type) localStorage.setItem(STORAGE_KEY, filters.log_type)
      else localStorage.removeItem(STORAGE_KEY)
    } catch (e) { /* private browsing */ }
  }, [filters.log_type])

  useEffect(() => {
    try {
      if (filters.rule_action) localStorage.setItem(ACTION_STORAGE_KEY, filters.rule_action)
      else localStorage.removeItem(ACTION_STORAGE_KEY)
    } catch (e) { /* private browsing */ }
  }, [filters.rule_action])

  useEffect(() => {
    try {
      if (filters.direction) localStorage.setItem(DIRECTION_STORAGE_KEY, filters.direction)
      else localStorage.removeItem(DIRECTION_STORAGE_KEY)
    } catch (e) { /* private browsing */ }
  }, [filters.direction])

  // Persist hidden columns to localStorage
  const toggleColumn = (key) => {
    setHiddenColumns(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      try { localStorage.setItem(COLUMNS_STORAGE_KEY, JSON.stringify([...next])) } catch (e) { /* private browsing */ }
      return next
    })
  }

  // Close columns menu on click outside
  useEffect(() => {
    if (!showColumnsMenu) return
    const handler = (e) => {
      if (columnsMenuRef.current && !columnsMenuRef.current.contains(e.target)) {
        setShowColumnsMenu(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showColumnsMenu])

  // Effective auto-refresh: paused when a row is expanded
  const isRefreshing = autoRefresh && expandedId === null

  // When paused (manually or by expanding a row), silently check for new logs count
  useEffect(() => {
    if (pendingRef.current) clearInterval(pendingRef.current)
    if (!isRefreshing && filters.page === 1) {
      pendingRef.current = setInterval(async () => {
        try {
          const qs = new URLSearchParams()
          for (const [k, v] of Object.entries(filters)) {
            if (v !== null && v !== undefined && v !== '') qs.set(k, v)
          }
          qs.set('per_page', '1')
          const resp = await fetch(`/api/logs?${qs}`)
          const result = await resp.json()
          const diff = result.total - data.total
          if (diff > 0) setPendingCount(diff)
        } catch {}
      }, 5000)
    }
    return () => { if (pendingRef.current) clearInterval(pendingRef.current) }
  }, [isRefreshing, filters, data.total])

  // Fetch detail data when a row is expanded
  useEffect(() => {
    if (expandedId === null) { setDetailedLog(null); return }
    let cancelled = false
    fetchLog(expandedId)
      .then(detail => { if (!cancelled) setDetailedLog(detail) })
      .catch(() => { if (!cancelled) setDetailedLog(null) })
    return () => { cancelled = true }
  }, [expandedId])

  // Auto-resume: when row is collapsed, refresh immediately
  const handleToggleExpand = (id) => {
    if (expandedId === id) {
      setExpandedId(null)
      setPendingCount(0)
      // Refresh immediately on collapse
      load(filters)
    } else {
      setExpandedId(id)
      setPendingCount(0)
    }
  }

  // Show scroll-to-top button when scrolled down
  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const handleScroll = () => setShowScrollTop(el.scrollTop > 300)
    el.addEventListener('scroll', handleScroll, { passive: true })
    return () => el.removeEventListener('scroll', handleScroll)
  }, [])

  const load = useCallback(async (f, { background } = {}) => {
    try {
      if (!background) setLoading(true)
      const result = await fetchLogs(f || filters)
      setData(result)
      setLastUpdate(new Date())
    } catch (err) {
      console.error('Failed to fetch logs:', err)
    } finally {
      if (!background) setLoading(false)
    }
  }, [filters])

  // Load on filter change
  useEffect(() => {
    load(filters)
  }, [filters]) // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh every 5s when on page 1 and no row expanded
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current)
    if (isRefreshing && filters.page === 1) {
      intervalRef.current = setInterval(() => load(filters, { background: true }), 5000)
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [isRefreshing, filters, load])

  const handleFilterChange = (newFilters) => {
    setExpandedId(null)
    setPendingCount(0)
    setFilters({ ...newFilters, page: 1 })
    // Persist time range within this session (shared across views via sessionStorage)
    try {
      if (newFilters.time_range) sessionStorage.setItem(TR_KEY, newFilters.time_range)
      else sessionStorage.removeItem(TR_KEY)
    } catch (e) { /* private browsing */ }
  }

  const handlePageChange = (page) => {
    setExpandedId(null)
    setPendingCount(0)
    setFilters(f => ({ ...f, page }))
  }

  return (
    <div className="flex flex-col h-full">
      {/* Drill indicator banner (F8) */}
      {drillContext && (
        <div className="flex items-center justify-between px-4 py-1.5 bg-blue-500/10 border-b border-blue-500/30 text-xs text-blue-400">
          <span>Showing: <span className="font-medium text-blue-300">{drillContext}</span></span>
          <button onClick={clearDrill} className="text-blue-400 hover:text-blue-300 ml-4">&#x2715;</button>
        </div>
      )}
      {/* Filters */}
      <div className="px-4 py-2.5 border-b border-gray-800 bg-gray-950 relative z-20">
        <FilterBar filters={filters} onChange={handleFilterChange} maxFilterDays={maxFilterDays} prefetchedInterfaces={prefetchedInterfaces} />
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-gray-800/50 bg-gray-950">
        <div className="flex items-center gap-3">
          <button
            onClick={() => { setAutoRefresh(!autoRefresh); setPendingCount(0) }}
            className={`flex items-center gap-1.5 text-[11px] transition-colors ${
              isRefreshing ? 'text-emerald-400' : 'text-amber-400'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${isRefreshing ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {isRefreshing ? 'Live' : 'Paused'}
          </button>
          {pendingCount > 0 && (
            <button
              onClick={() => { setExpandedId(null); setPendingCount(0); load(filters) }}
              className="text-[11px] text-amber-400 hover:text-amber-300 transition-colors"
            >
              {pendingCount} new log{pendingCount !== 1 ? 's' : ''} ↻
            </button>
          )}
          {lastUpdate && (
            <span className="text-[10px] text-gray-500">
              Updated {lastUpdate.toLocaleTimeString('en-GB')}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative inline-flex items-center" ref={columnsMenuRef}>
            {(() => {
              const asnAsSubline = uiSettings?.ui_ip_subline === 'asn_or_abuse'
              const menuColumns = TOGGLEABLE_COLUMNS.filter(col => !(col.key === 'asn' && asnAsSubline))
              return (
                <>
                  <button
                    onClick={() => setShowColumnsMenu(v => !v)}
                    className={`text-[11px] transition-colors ${hiddenColumns.size > 0 ? 'text-amber-400' : 'text-gray-400 hover:text-gray-200'}`}
                  >
                    Columns{hiddenColumns.size > 0 ? ` (${menuColumns.length - hiddenColumns.size}/${menuColumns.length})` : ''}
                  </button>
                  {showColumnsMenu && (
                    <div className="absolute right-0 top-full mt-1 w-40 bg-gray-950 border border-gray-700 rounded shadow-lg z-20 py-1">
                      {menuColumns.map(col => (
                        <label
                          key={col.key}
                          className="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 cursor-pointer select-none"
                        >
                          <input
                            type="checkbox"
                            checked={!hiddenColumns.has(col.key)}
                            onChange={() => toggleColumn(col.key)}
                            className="ui-checkbox"
                          />
                          {col.label}
                        </label>
                      ))}
                      <div className="border-t border-gray-700 mt-1 pt-1 px-3 pb-1">
                        <button
                          onClick={() => setShowColumnsMenu(false)}
                          className="w-full text-xs text-gray-300 hover:text-gray-200 py-1 transition-colors"
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )
            })()}
          </div>
          <button
            onClick={() => load(filters)}
            className="text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
          >
            ↻ Refresh
          </button>
          <a
            href={getExportUrl(filters)}
            className="text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
          >
            ↓ Export CSV
          </a>
        </div>
      </div>

      {/* Log table */}
      <div className="flex-1 relative overflow-hidden">
        <div className="h-full overflow-auto" ref={scrollRef}>
          <LogTable logs={data.data} loading={loading} expandedId={expandedId} detailedLog={detailedLog} onToggleExpand={handleToggleExpand} hiddenColumns={hiddenColumns} uiSettings={uiSettings} />
        </div>
        {showScrollTop && (
          <button
            onClick={() => scrollRef.current?.scrollTo({ top: 0, behavior: 'smooth' })}
            className="absolute bottom-4 right-4 z-20 w-8 h-8 rounded-full bg-gray-800 border border-gray-700 text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition-colors shadow-lg flex items-center justify-center"
            title="Scroll to top"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
            </svg>
          </button>
        )}
      </div>

      {/* Pagination */}
      <Pagination
        page={data.page}
        pages={data.pages}
        total={data.total}
        perPage={filters.per_page}
        onChange={handlePageChange}
        version={version}
        latestRelease={latestRelease}
      />
    </div>
  )
}
