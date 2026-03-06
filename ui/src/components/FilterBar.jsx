import React, { useState, useEffect, useRef, useCallback } from 'react'
import { fetchServices, fetchInterfaces, fetchProtocols } from '../api'
import { getInterfaceName, DIRECTION_ICONS, DIRECTION_COLORS, LOG_TYPE_STYLES, ACTION_STYLES, timeRangeToDays, filterVisibleRanges } from '../utils'
import DateRangePicker from './DateRangePicker'

const LOG_TYPES = ['firewall', 'dns', 'dhcp', 'wifi', 'system']
const TIME_RANGES = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: '60d', label: '60d' },
  { value: '90d', label: '90d' },
  { value: '180d', label: '180d' },
  { value: '365d', label: '365d' },
]
const ACTIONS = ['allow', 'block', 'redirect']
const DIRECTIONS = ['inbound', 'outbound', 'inter_vlan', 'nat']

const RESET_FILTERS = {
  time_range: '24h', time_from: null, time_to: null,
  page: 1, per_page: 50,
  ip: null, rule_name: null, search: null, service: null,
  interface: null, protocol: null, dst_port: null, src_port: null,
  country: null, asn: null,
  log_type: null, rule_action: null, direction: null, vpn_only: null,
}

export default function FilterBar({ filters, onChange, maxFilterDays, prefetchedInterfaces }) {
  const [ipSearch, setIpSearch] = useState(filters.ip || '')
  const [ruleSearch, setRuleSearch] = useState(filters.rule_name || '')
  const [textSearch, setTextSearch] = useState(filters.search || '')
  const [serviceSearch, setServiceSearch] = useState('')
  const [services, setServices] = useState([])
  const [showServiceDropdown, setShowServiceDropdown] = useState(false)
  const [selectedServices, setSelectedServices] = useState(
    filters.service ? filters.service.split(',') : []
  )
  const [interfaceSearch, setInterfaceSearch] = useState('')
  const [interfaces, setInterfaces] = useState([])
  const [showInterfaceDropdown, setShowInterfaceDropdown] = useState(false)
  const [selectedInterfaces, setSelectedInterfaces] = useState(
    filters.interface ? filters.interface.split(',') : []
  )
  const [countrySearch, setCountrySearch] = useState(filters.country || '')
  const [asnSearch, setAsnSearch] = useState(filters.asn || '')
  const [dstPortSearch, setDstPortSearch] = useState(filters.dst_port ?? '')
  const [srcPortSearch, setSrcPortSearch] = useState(filters.src_port ?? '')
  const [protocolSearch, setProtocolSearch] = useState('')
  const [protocols, setProtocols] = useState([])
  const [showProtocolDropdown, setShowProtocolDropdown] = useState(false)
  const [selectedProtocols, setSelectedProtocols] = useState(
    filters.protocol ? filters.protocol.split(',') : []
  )
  const parsePort = (v) => {
    if (v === '' || v === '!') return null
    const clean = v.startsWith('!') ? v.slice(1) : v
    const n = parseInt(clean, 10)
    if (isNaN(n) || n < 1 || n > 65535) return null
    // Return as string to preserve '!' prefix for negation
    return v.startsWith('!') ? `!${n}` : String(n)
  }

  // Ref to avoid stale closures in debounce effects
  const filtersRef = useRef(filters)
  useEffect(() => { filtersRef.current = filters }, [filters])

  // Sync local input state when filters change externally (e.g. drill-to-logs).
  // Use a ref guard so our own debounced onChange calls don't trigger a sync loop.
  const isInternalChange = useRef(false)
  const wrappedOnChange = useCallback((f) => {
    isInternalChange.current = true
    onChange(f)
  }, [onChange])
  useEffect(() => {
    if (isInternalChange.current) { isInternalChange.current = false; return }
    setIpSearch(filters.ip || '')
    setRuleSearch(filters.rule_name || '')
    setTextSearch(filters.search || '')
    setCountrySearch(filters.country || '')
    setAsnSearch(filters.asn || '')
    setDstPortSearch(filters.dst_port ?? '')
    setSrcPortSearch(filters.src_port ?? '')
    setSelectedServices(filters.service ? filters.service.split(',') : [])
    setSelectedInterfaces(filters.interface ? filters.interface.split(',') : [])
    setSelectedProtocols(filters.protocol ? filters.protocol.split(',') : [])
  }, [filters.ip, filters.rule_name, filters.search, filters.country, filters.asn, filters.dst_port, filters.src_port, filters.service, filters.interface, filters.protocol]) // eslint-disable-line react-hooks/exhaustive-deps

  // Load services for autocomplete
  useEffect(() => {
    fetchServices()
      .then(data => setServices(data.services || []))
      .catch(err => { console.error('Failed to load services:', err); setServices([]) })
  }, [])

  // Load protocols for dropdown
  useEffect(() => {
    fetchProtocols()
      .then(data => setProtocols(data.protocols || []))
      .catch(err => { console.error('Failed to load protocols:', err); setProtocols([]) })
  }, [])

  // Load interfaces for filtering (skip fetch if parent already provided them)
  useEffect(() => {
    if (prefetchedInterfaces) { setInterfaces(prefetchedInterfaces); return }
    fetchInterfaces()
      .then(data => setInterfaces(data.interfaces || []))
      .catch(err => { console.error('Failed to load interfaces:', err); setInterfaces([]) })
  }, [prefetchedInterfaces])

  // Debounce text inputs (skip initial mount to avoid a redundant fetch)
  const mountedRef = useRef(false)

  useEffect(() => {
    if (!mountedRef.current) return
    const t = setTimeout(() => wrappedOnChange({ ...filtersRef.current, ip: ipSearch || null }), 400)
    return () => clearTimeout(t)
  }, [ipSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!mountedRef.current) return
    // Normalize: UI displays "] " (space after bracket) for readability but DB stores "]" (no space)
    const normalized = ruleSearch ? ruleSearch.replace(/\]\s+/g, ']') : null
    const t = setTimeout(() => wrappedOnChange({ ...filtersRef.current, rule_name: normalized }), 400)
    return () => clearTimeout(t)
  }, [ruleSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!mountedRef.current) return
    const t = setTimeout(() => wrappedOnChange({ ...filtersRef.current, search: textSearch || null }), 400)
    return () => clearTimeout(t)
  }, [textSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!mountedRef.current) return
    const t = setTimeout(() => wrappedOnChange({ ...filtersRef.current, country: countrySearch || null }), 400)
    return () => clearTimeout(t)
  }, [countrySearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!mountedRef.current) return
    const t = setTimeout(() => wrappedOnChange({ ...filtersRef.current, asn: asnSearch || null }), 400)
    return () => clearTimeout(t)
  }, [asnSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!mountedRef.current) return
    const t = setTimeout(() => {
      wrappedOnChange({ ...filtersRef.current, dst_port: parsePort(dstPortSearch) })
    }, 400)
    return () => clearTimeout(t)
  }, [dstPortSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!mountedRef.current) return
    const t = setTimeout(() => {
      wrappedOnChange({ ...filtersRef.current, src_port: parsePort(srcPortSearch) })
    }, 400)
    return () => clearTimeout(t)
  }, [srcPortSearch]) // eslint-disable-line react-hooks/exhaustive-deps

  // Mark mounted AFTER all debounce effects so the guard skips the initial run
  useEffect(() => { mountedRef.current = true }, [])

  // Auto-correct selected range if it exceeds visible ranges (respects ceiling)
  // Skip when in custom date mode (time_range is null, time_from/time_to are set)
  useEffect(() => {
    if (!maxFilterDays || visibleRanges.length === 0) return
    if (!filters.time_range && filters.time_from) return
    if (visibleRanges.some(tr => tr.value === filters.time_range)) return
    const largest = visibleRanges.findLast(tr => timeRangeToDays(tr.value) >= 1) || visibleRanges[visibleRanges.length - 1]
    if (largest && largest.value !== filters.time_range) {
      wrappedOnChange({ ...filters, time_range: largest.value })
    }
  }, [maxFilterDays]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleType = (type) => {
    const current = filters.log_type ? filters.log_type.split(',') : LOG_TYPES
    const updated = current.includes(type)
      ? current.filter(t => t !== type)
      : [...current, type]
    wrappedOnChange({ ...filters, log_type: updated.length === LOG_TYPES.length ? null : updated.join(',') })
  }

  const activeTypes = filters.log_type ? filters.log_type.split(',') : LOG_TYPES
  const activeActions = filters.rule_action ? filters.rule_action.split(',') : ACTIONS
  const activeDirections = filters.direction ? filters.direction.split(',') : DIRECTIONS

  const [filtersExpanded, setFiltersExpanded] = useState(false)

  const visibleRanges = filterVisibleRanges(TIME_RANGES, maxFilterDays, tr => tr.value)

  // Count active (non-default) filters for mobile badge
  const activeFilterCount = [
    filters.log_type,              // types narrowed
    filters.rule_action,           // actions narrowed
    filters.direction,             // directions narrowed
    filters.vpn_only,              // VPN filter active
    (filters.time_from || filters.time_to) || (filters.time_range !== '24h' ? filters.time_range : null),
    ipSearch,
    ruleSearch,
    textSearch,
    selectedServices.length > 0 ? true : null,
    selectedInterfaces.length > 0 ? true : null,
    selectedProtocols.length > 0 ? true : null,
    countrySearch,
    asnSearch,
    dstPortSearch,
    srcPortSearch,
  ].filter(Boolean).length

  const toggleAction = (action) => {
    const current = filters.rule_action ? filters.rule_action.split(',') : ACTIONS
    const updated = current.includes(action)
      ? current.filter(a => a !== action)
      : [...current, action]
    wrappedOnChange({ ...filters, rule_action: updated.length === ACTIONS.length ? null : updated.join(',') })
  }

  const toggleDirection = (dir) => {
    const current = filters.direction ? filters.direction.split(',') : DIRECTIONS
    const updated = current.includes(dir)
      ? current.filter(d => d !== dir)
      : [...current, dir]
    wrappedOnChange({ ...filters, direction: updated.length === DIRECTIONS.length ? null : updated.join(',') })
  }

  return (
    <div className="space-y-3 lg:space-y-0">
      {/* Mobile filter toggle */}
      <button
        type="button"
        onClick={() => setFiltersExpanded(v => !v)}
        className="lg:hidden flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors w-full justify-between"
        aria-expanded={filtersExpanded}
        aria-controls="log-filters-panel"
      >
        <span>Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}</span>
        <svg className={`w-3.5 h-3.5 transition-transform ${filtersExpanded ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" focusable="false">
          <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
        </svg>
      </button>

      {/* Filter content — always visible on desktop, collapsible on mobile */}
      <div id="log-filters-panel" className={`${filtersExpanded ? 'block' : 'hidden'} lg:block space-y-3`}>
      {/* Row 1: Log types + time range */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-1.5">
          {LOG_TYPES.map(type => (
            <button
              key={type}
              onClick={() => toggleType(type)}
              className={`px-2.5 py-[3px] rounded text-xs font-medium uppercase border transition-all ${
                activeTypes.includes(type)
                  ? LOG_TYPE_STYLES[type]
                  : 'border-transparent text-gray-500 hover:text-gray-400'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1.5">
          {ACTIONS.map(action => (
            <button
              key={action}
              onClick={() => toggleAction(action)}
              className={`px-2 py-[3px] rounded text-xs font-medium uppercase border transition-all ${
                activeActions.includes(action)
                  ? ACTION_STYLES[action]
                  : 'border-transparent text-gray-500 hover:text-gray-400'
              }`}
            >
              {action}
            </button>
          ))}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1">
          {DIRECTIONS.map(dir => {
            const dirLocked = !!filters.vpn_only
            if (dir === 'nat') {
              return (
                <React.Fragment key={dir}>
                  <button
                    onClick={() => !dirLocked && toggleDirection(dir)}
                    className={`px-2 py-1 rounded text-xs font-medium uppercase transition-all ${
                      dirLocked
                        ? 'bg-gray-700 text-white opacity-40 cursor-not-allowed'
                        : activeDirections.includes(dir)
                          ? 'bg-gray-700 text-white'
                          : 'text-gray-500 hover:text-gray-400'
                    }`}
                  >
                    <span className={activeDirections.includes(dir) ? DIRECTION_COLORS[dir] : ''}>{DIRECTION_ICONS[dir]}</span> {dir}
                  </button>
                  <button
                    onClick={() => wrappedOnChange({
                      ...filters,
                      vpn_only: filters.vpn_only ? null : true,
                      // When activating VPN, clear direction filter so all directions show
                      ...(!filters.vpn_only ? { direction: null } : {}),
                    })}
                    className={`px-2 py-1 rounded text-xs font-medium uppercase transition-all ${
                      filters.vpn_only
                        ? 'bg-gray-700 text-white'
                        : 'text-gray-500 hover:text-gray-400'
                    }`}
                  >
                    <span className={filters.vpn_only ? 'text-teal-400' : ''}>⛨</span> vpn
                  </button>
                </React.Fragment>
              )
            }
            return (
              <button
                key={dir}
                onClick={() => !dirLocked && toggleDirection(dir)}
                className={`px-2 py-1 rounded text-xs font-medium uppercase transition-all ${
                  dirLocked
                    ? 'bg-gray-700 text-white opacity-40 cursor-not-allowed'
                    : activeDirections.includes(dir)
                      ? 'bg-gray-700 text-white'
                      : 'text-gray-500 hover:text-gray-400'
                }`}
              >
                <span className={activeDirections.includes(dir) ? DIRECTION_COLORS[dir] : ''}>{DIRECTION_ICONS[dir]}</span> {dir === 'inter_vlan' ? 'vlan' : dir}
              </button>
            )
          })}
        </div>

        <div className="h-5 w-px bg-gray-700" />

        <div className="flex items-center gap-1">
          {visibleRanges.map(tr => (
            <button
              key={tr.value}
              onClick={() => wrappedOnChange({ ...filters, time_range: tr.value, time_from: null, time_to: null })}
              className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                filters.time_range === tr.value
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-400 hover:text-gray-300'
              }`}
            >
              {tr.label}
            </button>
          ))}
          <DateRangePicker
            isActive={!filters.time_range && !!(filters.time_from || filters.time_to)}
            timeFrom={filters.time_from}
            timeTo={filters.time_to}
            maxFilterDays={maxFilterDays}
            onApply={({ time_from, time_to }) =>
              wrappedOnChange({ ...filters, time_range: null, time_from, time_to })
            }
            onClear={() =>
              wrappedOnChange({ ...filters, time_range: '24h', time_from: null, time_to: null })
            }
          />
        </div>
      </div>

      {/* Row 2: Text searches */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="relative">
          <input
            type="text"
            placeholder="IP address..."
            title="Prefix with ! to exclude matching IPs"
            value={ipSearch}
            onChange={e => setIpSearch(e.target.value)}
            className={`bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-40 ${ipSearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {ipSearch && (
            <button onClick={() => setIpSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Rule name..."
            title="Prefix with ! to exclude matching rules"
            value={ruleSearch}
            onChange={e => setRuleSearch(e.target.value)}
            className={`bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-40 ${ruleSearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {ruleSearch && (
            <button onClick={() => setRuleSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder={selectedInterfaces.length > 0 ? `${selectedInterfaces.length} interface(s)` : "Interface..."}
            value={interfaceSearch}
            onChange={e => {
              setInterfaceSearch(e.target.value)
              setShowInterfaceDropdown(true)
            }}
            onFocus={() => setShowInterfaceDropdown(true)}
            onBlur={() => setTimeout(() => setShowInterfaceDropdown(false), 200)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-40"
          />
          {selectedInterfaces.length > 0 && (
            <button
              onClick={() => {
                setSelectedInterfaces([])
                wrappedOnChange({ ...filters, interface: null })
              }}
              className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs"
            >✕</button>
          )}
          {showInterfaceDropdown && (
            <div className="absolute top-full left-0 mt-1 w-64 bg-gray-950 border border-gray-700 rounded shadow-lg max-h-60 overflow-y-auto z-20">
              {(() => {
                const q = interfaceSearch.toLowerCase()
                const filtered = interfaces.filter(iface =>
                  iface.name.toLowerCase().includes(q) ||
                  iface.label.toLowerCase().includes(q) ||
                  (iface.description || '').toLowerCase().includes(q)
                )
                return filtered.length === 0
                  ? <div className="px-3 py-2 text-xs text-gray-400">No matching interfaces</div>
                  : filtered.slice(0, 50).map(iface => {
                      const displayName = iface.iface_type === 'vpn' && iface.description
                        ? iface.description
                        : (iface.label !== iface.name ? iface.label : (iface.description || iface.name))
                      return (
                        <div
                          key={iface.name}
                          onClick={() => {
                            const updated = selectedInterfaces.includes(iface.name)
                              ? selectedInterfaces.filter(i => i !== iface.name)
                              : [...selectedInterfaces, iface.name]
                            setSelectedInterfaces(updated)
                            wrappedOnChange({ ...filters, interface: updated.length ? updated.join(',') : null })
                            setInterfaceSearch('')
                          }}
                          className={`px-3 py-1.5 cursor-pointer transition-colors ${
                            selectedInterfaces.includes(iface.name)
                              ? 'bg-blue-500/20 text-blue-400'
                              : 'text-gray-300 hover:bg-gray-800'
                          }`}
                        >
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs truncate">{displayName}</span>
                            {iface.iface_type === 'wan' && (
                              <span className="text-[9px] px-1 py-0 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 shrink-0">WAN</span>
                            )}
                            {iface.iface_type === 'vpn' && (
                              <span className="text-[9px] px-1 py-0 rounded bg-teal-500/15 text-teal-400 border border-teal-500/30 shrink-0">VPN</span>
                            )}
                            {iface.iface_type === 'vlan' && iface.vlan_id != null && (
                              <span className="text-[9px] px-1 py-0 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0">VLAN {iface.vlan_id}</span>
                            )}
                          </div>
                          <span className="text-xs font-mono text-gray-500">{iface.name}</span>
                        </div>
                      )
                    })
              })()}
            </div>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Src port..."
            title="Prefix with ! to exclude this port"
            value={srcPortSearch}
            onChange={e => { const raw = e.target.value; const hasNeg = raw.startsWith('!'); const digits = raw.replace(/[^0-9]/g, ''); setSrcPortSearch(hasNeg ? '!' + digits : digits); }}
            className={`bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-24 ${srcPortSearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {srcPortSearch && (
            <button onClick={() => setSrcPortSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Dst port..."
            title="Prefix with ! to exclude this port"
            value={dstPortSearch}
            onChange={e => { const raw = e.target.value; const hasNeg = raw.startsWith('!'); const digits = raw.replace(/[^0-9]/g, ''); setDstPortSearch(hasNeg ? '!' + digits : digits); }}
            className={`bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-24 ${dstPortSearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {dstPortSearch && (
            <button onClick={() => setDstPortSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder={selectedProtocols.length > 0 ? `${selectedProtocols.length} protocol(s)` : "Protocol..."}
            value={protocolSearch}
            onChange={e => {
              setProtocolSearch(e.target.value)
              setShowProtocolDropdown(true)
            }}
            onFocus={() => setShowProtocolDropdown(true)}
            onBlur={() => setTimeout(() => setShowProtocolDropdown(false), 200)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-32"
          />
          {selectedProtocols.length > 0 && (
            <button
              onClick={() => {
                setSelectedProtocols([])
                wrappedOnChange({ ...filters, protocol: null })
              }}
              className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs"
            >✕</button>
          )}
          {showProtocolDropdown && (
            <div className="absolute top-full left-0 mt-1 w-40 bg-gray-950 border border-gray-700 rounded shadow-lg max-h-60 overflow-y-auto z-20">
              {protocols
                .filter(p => p.toLowerCase().includes(protocolSearch.toLowerCase()))
                .map(protocol => (
                  <div
                    key={protocol}
                    onClick={() => {
                      const updated = selectedProtocols.includes(protocol)
                        ? selectedProtocols.filter(p => p !== protocol)
                        : [...selectedProtocols, protocol]
                      setSelectedProtocols(updated)
                      wrappedOnChange({ ...filters, protocol: updated.length ? updated.join(',') : null })
                      setProtocolSearch('')
                    }}
                    className={`px-3 py-2 text-xs cursor-pointer transition-colors ${
                      selectedProtocols.includes(protocol)
                        ? 'bg-blue-500/20 text-blue-400'
                        : 'text-gray-300 hover:bg-gray-800'
                    }`}
                  >
                    {protocol.toUpperCase()}
                  </div>
                ))}
              {protocols.filter(p => p.toLowerCase().includes(protocolSearch.toLowerCase())).length === 0 && (
                <div className="px-3 py-2 text-xs text-gray-400">No matching protocols</div>
              )}
            </div>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder={selectedServices.length > 0 ? `${selectedServices.length} service(s)` : "Service..."}
            value={serviceSearch}
            onChange={e => {
              setServiceSearch(e.target.value)
              setShowServiceDropdown(true)
            }}
            onFocus={() => setShowServiceDropdown(true)}
            onBlur={() => setTimeout(() => setShowServiceDropdown(false), 200)}
            className="bg-gray-800/50 border border-gray-700 rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-40"
          />
          {selectedServices.length > 0 && (
            <button
              onClick={() => {
                setSelectedServices([])
                wrappedOnChange({ ...filters, service: null })
              }}
              className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs"
            >✕</button>
          )}
          {showServiceDropdown && (
            <div className="absolute top-full left-0 mt-1 w-56 bg-gray-950 border border-gray-700 rounded shadow-lg max-h-60 overflow-y-auto z-20">
              {services
                .filter(s => s.toLowerCase().includes(serviceSearch.toLowerCase()))
                .slice(0, 50)
                .map(service => (
                  <div
                    key={service}
                    onClick={() => {
                      const updated = selectedServices.includes(service)
                        ? selectedServices.filter(s => s !== service)
                        : [...selectedServices, service]
                      setSelectedServices(updated)
                      wrappedOnChange({ ...filters, service: updated.length ? updated.join(',') : null })
                      setServiceSearch('')
                    }}
                    className={`px-3 py-2 text-xs cursor-pointer transition-colors ${
                      selectedServices.includes(service)
                        ? 'bg-blue-500/20 text-blue-400'
                        : 'text-gray-300 hover:bg-gray-800'
                    }`}
                  >
                    {service}
                  </div>
                ))}
              {services.filter(s => s.toLowerCase().includes(serviceSearch.toLowerCase())).length === 0 && (
                <div className="px-3 py-2 text-xs text-gray-400">No matching services</div>
              )}
            </div>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Country code..."
            title="Comma-separated codes (e.g. US,CN). Prefix with ! to exclude all listed countries."
            value={countrySearch}
            onChange={e => setCountrySearch(e.target.value)}
            className={`bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-28 ${countrySearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {countrySearch && (
            <button onClick={() => setCountrySearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="ASN..."
            title="Prefix with ! to exclude matching ASNs"
            value={asnSearch}
            onChange={e => setAsnSearch(e.target.value)}
            className={`bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 w-full sm:w-36 ${asnSearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {asnSearch && (
            <button onClick={() => setAsnSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        <div className="relative flex-1 sm:max-w-xs">
          <input
            type="text"
            placeholder="Search raw log..."
            title="Prefix with ! to exclude matching log entries"
            value={textSearch}
            onChange={e => setTextSearch(e.target.value)}
            className={`w-full bg-gray-800/50 border rounded px-3 py-1.5 text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-gray-500 ${textSearch.startsWith('!') ? 'border-amber-400/60' : 'border-gray-700'}`}
          />
          {textSearch && (
            <button onClick={() => setTextSearch('')} className="absolute right-2 top-1.5 text-gray-400 hover:text-gray-200 text-xs">✕</button>
          )}
        </div>
        {activeFilterCount > 0 && (
          <button
            type="button"
            onClick={() => {
              setIpSearch('')
              setRuleSearch('')
              setTextSearch('')
              setServiceSearch('')
              setSelectedServices([])
              setInterfaceSearch('')
              setSelectedInterfaces([])
              setCountrySearch('')
              setAsnSearch('')
              setDstPortSearch('')
              setSrcPortSearch('')
              setProtocolSearch('')
              setSelectedProtocols([])
              wrappedOnChange(RESET_FILTERS)
            }}
            className="text-xs text-gray-400 hover:text-gray-200 transition-colors"
          >
            Reset
          </button>
        )}
      </div>
      </div>{/* end collapsible wrapper */}
    </div>
  )
}
