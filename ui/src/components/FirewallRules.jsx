import React, { useState, useEffect, useMemo } from 'react'
import { fetchFirewallPolicies, patchFirewallPolicy, bulkUpdateFirewallLoggingStream } from '../api'

// ── Helpers ──────────────────────────────────────────────────────────────────

// Standard zones in UniFi's default display order; custom zones go after these
const STANDARD_ZONE_ORDER = ['Internal', 'External', 'Gateway', 'VPN', 'Hotspot', 'DMZ']

// Abbreviations that should always be UPPERCASE
const UPPER_NAMES = { vpn: 'VPN', dmz: 'DMZ' }

function normalizeZoneName(name) {
  return UPPER_NAMES[name.toLowerCase()] || name
}

function sortZones(zones) {
  return [...zones].sort((a, b) => {
    const ai = STANDARD_ZONE_ORDER.indexOf(normalizeZoneName(a.name))
    const bi = STANDARD_ZONE_ORDER.indexOf(normalizeZoneName(b.name))
    // Standard zones first (by defined order), then custom zones alphabetically
    if (ai !== -1 && bi !== -1) return ai - bi
    if (ai !== -1) return -1
    if (bi !== -1) return 1
    return a.name.localeCompare(b.name)
  })
}

function buildZoneMap(zones) {
  const m = {}
  for (const z of zones) m[z.id] = normalizeZoneName(z.name)
  return m
}

const ANY_SENTINELS = new Set(['ANY', 'ALL', 'ALL_TRAFFIC', 'ALL_PROTOCOLS', 'ALL_PORTS', 'ALL_ADDRESSES'])
const PORT_RANGE_KEYS = new Set(['ports', 'port', 'portRange', 'portRanges', 'portRangeSet', 'portSet'])

function isMeaningfulValue(value) {
  if (value === null || value === undefined) return false
  if (Array.isArray(value)) return value.some(isMeaningfulValue)
  if (typeof value === 'object') return Object.values(value).some(isMeaningfulValue)
  if (typeof value === 'string') {
    const trimmed = value.trim()
    return trimmed !== '' && !ANY_SENTINELS.has(trimmed.toUpperCase())
  }
  return true
}

function hasNonTrivialKeys(obj, allowedKeys) {
  if (!obj || typeof obj !== 'object') return false
  return Object.entries(obj).some(([key, val]) => !allowedKeys.has(key) && isMeaningfulValue(val))
}

function isAnyPortRange(range) {
  if (!range || typeof range !== 'object') return false
  const from = range.from ?? range.start ?? range.min ?? range.portFrom ?? range.port_start
  const to = range.to ?? range.end ?? range.max ?? range.portTo ?? range.port_end
  if (from === undefined || to === undefined) return false
  const fromNum = Number(from)
  const toNum = Number(to)
  if (!Number.isFinite(fromNum) || !Number.isFinite(toNum)) return false
  return fromNum <= 1 && toNum >= 65535
}

function isAnyPortsValue(value) {
  if (value === null || value === undefined) return true
  if (Array.isArray(value)) {
    if (value.length === 0) return true
    return value.every(v => ANY_SENTINELS.has(String(v).toUpperCase()))
  }
  if (typeof value === 'object') return isAnyPortRange(value)
  if (typeof value === 'string') return ANY_SENTINELS.has(value.trim().toUpperCase())
  return false
}

function hasProtocolConstraint(protocolFilter) {
  if (!protocolFilter) return false
  const protoName = (
    protocolFilter.protocol?.name ||
    protocolFilter.protocol ||
    protocolFilter.name ||
    protocolFilter.type ||
    ''
  ).toString().trim()
  const isAnyProto = protoName === '' || ANY_SENTINELS.has(protoName.toUpperCase())
  const hasExtras = Object.entries(protocolFilter).some(([key, val]) => {
    if (['protocol', 'name', 'type', 'label'].includes(key)) return false
    if (PORT_RANGE_KEYS.has(key)) return !isAnyPortsValue(val)
    return isMeaningfulValue(val)
  })
  return !isAnyProto || hasExtras
}

function allowsReturnTraffic(policy) {
  if (policy.action?.type !== 'ALLOW') return false
  if (policy.action?.allowReturnTraffic === true) return true
  const csf = policy.connectionStateFilter
  return Array.isArray(csf) && csf.some(s => s === 'ESTABLISHED' || s === 'RELATED')
}

function isReturnBlanket(policy, zoneKeys) {
  if (!allowsReturnTraffic(policy)) return false
  if (hasNonTrivialKeys(policy.source, zoneKeys)) return false
  if (hasNonTrivialKeys(policy.destination, zoneKeys)) return false
  if (hasProtocolConstraint(policy.ipProtocolScope?.protocolFilter)) return false
  if (Array.isArray(policy.connectionStateFilter) && policy.connectionStateFilter.length > 0) {
    const states = policy.connectionStateFilter.map(s => String(s).toUpperCase())
    if (!states.every(s => s === 'ESTABLISHED' || s === 'RELATED')) return false
  }
  return true
}

function getDefaultAction(policies) {
  // Baseline considers USER_DEFINED + SYSTEM_DEFINED (enabled only).
  // DERIVED policies are device-specific auto-rules and don't set zone-pair posture.
  const candidates = policies.filter(p =>
    p.enabled !== false && p.metadata?.origin !== 'DERIVED'
  )

  if (candidates.length === 0) {
    return policies.length > 0 ? 'Block All' : null
  }

  // Sort by index ascending (firewall evaluation order)
  const sorted = [...candidates].sort((a, b) => (a.index ?? 0) - (b.index ?? 0))

  // A "blanket" policy matches all traffic — no specific conditions.
  // Policies with meaningful filters are specific.
  const zoneKeys = new Set(['zoneId', 'zoneType', 'type', 'name', 'id'])
  const isBlanket = (p) => {
    if (hasNonTrivialKeys(p.source, zoneKeys)) return false
    if (hasNonTrivialKeys(p.destination, zoneKeys)) return false
    if (isMeaningfulValue(p.connectionStateFilter)) return false
    if (hasProtocolConstraint(p.ipProtocolScope?.protocolFilter)) return false
    return true
  }

  // First blanket policy in evaluation order = effective catch-all.
  // It matches all traffic not caught by earlier specific rules.
  const effectiveCatchAll = sorted.find(isBlanket)

  if (!effectiveCatchAll || effectiveCatchAll.action?.type === 'BLOCK') {
    // Effective baseline is BLOCK — check if return/established is allowed before it
    const limit = effectiveCatchAll?.index ?? Infinity
    const hasReturn = sorted.some(p =>
      (p.index ?? 0) < limit &&
      isReturnBlanket(p, zoneKeys)
    )
    return hasReturn ? 'Allow Return' : 'Block All'
  }

  return 'Allow All'
}

function buildMatrixData(policies, zones) {
  const zoneIds = zones.map(z => z.id)
  const cells = {}
  for (const srcId of zoneIds) {
    for (const dstId of zoneIds) {
      const key = `${srcId}:${dstId}`
      const pair = policies.filter(
        p => p.source?.zoneId === srcId && p.destination?.zoneId === dstId
      )
      const policyCount = pair.length
      const defaultAction = srcId === dstId && pair.length === 0
        ? null
        : getDefaultAction(pair)
      cells[key] = { defaultAction, policyCount }
    }
  }
  return cells
}

function cellStyle(action, selected) {
  // Non-selected cells get a transparent 2px border to match border-chase size and prevent layout shift
  switch (action) {
    case 'Allow All':
      return selected
        ? 'border-chase border-chase-emerald text-emerald-300 zone-pair-selected-emerald'
        : 'bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 border-2 border-transparent'
    case 'Block All':
      return selected
        ? 'border-chase border-chase-red text-red-300 zone-pair-selected-red'
        : 'bg-red-500/20 text-red-400 hover:bg-red-500/30 border-2 border-transparent'
    case 'Allow Return':
      return selected
        ? 'border-chase border-chase-cyan text-cyan-300 zone-pair-selected-cyan'
        : 'bg-cyan-500/15 text-cyan-400 hover:bg-cyan-500/25 border-2 border-transparent'
    default:
      return 'bg-white/[0.04] text-[#676f79] border-2 border-transparent'
  }
}

// ── Toggle Switch (matches UniFi: 32×16 track, 14×14 knob) ─────────────────

function SyslogToggle({ checked, disabled, onChange, title }) {
  return (
    <button
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className="relative"
      aria-label="Toggle syslog"
      title={title}
    >
      <div
        className={`w-8 h-4 rounded-full transition-colors duration-200 ${
          disabled
            ? (checked ? 'bg-teal-800' : 'bg-[#282b2f]')
            : (checked ? 'bg-teal-500' : 'bg-[#42474d]')
        } ${disabled ? 'cursor-not-allowed' : 'cursor-pointer'}`}
      >
        <div
          className="absolute top-[1px] w-[14px] h-[14px] rounded-full bg-white"
          style={{
            left: checked ? '17px' : '1px',
            transition: 'left .25s cubic-bezier(.8, 0, .6, 1.4)',
            boxShadow: '0 4px 12px 0 rgba(0,0,0,.4), 0 0 1px 0 hsla(214,8%,98%,.08)',
          }}
        />
      </div>
    </button>
  )
}

// ── ZoneMatrix ───────────────────────────────────────────────────────────────

function ZoneMatrix({ zones, cells, selectedCell, onSelectCell, totalPolicyCount, syslogLabel, onRefresh, refreshDisabled }) {
  const allSelected = selectedCell === null

  return (
    <div className="mb-5">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 text-[13px] text-[#cbced2] font-medium">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4 text-[#676f79]">
            <path fillRule="evenodd" d="M4.25 2A2.25 2.25 0 002 4.25v2.5A2.25 2.25 0 004.25 9h2.5A2.25 2.25 0 009 6.75v-2.5A2.25 2.25 0 006.75 2h-2.5zm0 9A2.25 2.25 0 002 13.25v2.5A2.25 2.25 0 004.25 18h2.5A2.25 2.25 0 009 15.75v-2.5A2.25 2.25 0 006.75 11h-2.5zm9-9A2.25 2.25 0 0011 4.25v2.5A2.25 2.25 0 0013.25 9h2.5A2.25 2.25 0 0018 6.75v-2.5A2.25 2.25 0 0015.75 2h-2.5zm0 9A2.25 2.25 0 0011 13.25v2.5A2.25 2.25 0 0013.25 18h2.5A2.25 2.25 0 0018 15.75v-2.5A2.25 2.25 0 0015.75 11h-2.5z" clipRule="evenodd" />
          </svg>
          Zone Matrix
          <span className="text-[11px] font-normal text-[#676f79] ml-1">
            Click on any zone pair to filter policies below
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-[#676f79]">{syslogLabel}</span>
          <button
            onClick={onRefresh}
            disabled={refreshDisabled}
            className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white disabled:opacity-40 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="w-full rounded-lg scroll-fade">
        <table className="w-full border-separate text-[11px]" style={{ borderSpacing: 0, borderStyle: 'none' }}>
          <tbody>
            <tr>
              <td />
              <td />
              <td
                colSpan={zones.length}
                className="text-center text-[10px] font-normal text-[#676f79] pb-1 uppercase tracking-widest"
              >
                Destination
              </td>
            </tr>
            <tr>
              <td className="w-4" />
              <td className="p-0">
                <button
                  onClick={() => onSelectCell(null)}
                  className={`block w-full px-2.5 py-1.5 text-left font-medium whitespace-nowrap transition-colors rounded-tl-lg ${
                    allSelected
                      ? 'border-chase text-teal-400'
                      : 'bg-black text-[#cbced2] hover:bg-gray-800/30 border-2 border-transparent'
                  }`}
                >
                  All Policies ({totalPolicyCount})
                </button>
              </td>
              {zones.map((z, i) => (
                <td
                  key={z.id}
                  className={`zone-label-cell px-2.5 py-1.5 font-medium text-[#cbced2] text-center bg-black whitespace-nowrap ${
                    i === zones.length - 1 ? 'rounded-tr-lg' : ''
                  }`}
                >
                  {normalizeZoneName(z.name)}
                </td>
              ))}
            </tr>
            {zones.map((src, ri) => (
              <tr key={src.id}>
                {ri === 0 && (
                  <td
                    rowSpan={zones.length}
                    className="text-[10px] text-[#676f79] font-normal uppercase tracking-widest w-4 select-none"
                    style={{ writingMode: 'vertical-lr', transform: 'rotate(180deg)' }}
                  >
                    <div className="flex items-center justify-center h-full">Source</div>
                  </td>
                )}
                <td className={`zone-label-cell px-2.5 py-1.5 font-medium text-[#cbced2] bg-black whitespace-nowrap text-[11px] ${
                  ri === zones.length - 1 ? 'rounded-bl-lg' : ''
                }`}>
                  {normalizeZoneName(src.name)}
                </td>
                {zones.map((dst, ci) => {
                  const key = `${src.id}:${dst.id}`
                  const cell = cells[key]
                  const sel = selectedCell?.srcZoneId === src.id && selectedCell?.dstZoneId === dst.id
                  const isLastRow = ri === zones.length - 1
                  const isLastCol = ci === zones.length - 1
                  const cornerClass = isLastRow && isLastCol ? 'rounded-br-lg' : ''

                  if (!cell || cell.defaultAction === null) {
                    return (
                      <td key={dst.id} className={`p-0 ${cornerClass}`}>
                        <div className={`px-2.5 py-1.5 text-center text-[#676f79] bg-white/[0.04] border-2 border-transparent ${cornerClass}`}>
                          &ndash;
                        </div>
                      </td>
                    )
                  }

                  return (
                    <td key={dst.id} className={`p-0 ${cornerClass}`}>
                      <button
                        onClick={() => onSelectCell({ srcZoneId: src.id, dstZoneId: dst.id })}
                        className={`block w-full px-2.5 py-1.5 text-center font-medium whitespace-nowrap transition-colors cursor-pointer ${cornerClass} ${cellStyle(cell.defaultAction, sel)}`}
                      >
                        {cell.defaultAction}
                        {cell.policyCount > 0 && (
                          <span className="ml-1 opacity-70">({cell.policyCount})</span>
                        )}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[11px] text-[#676f79] mt-2">
        Zone pairs labels may differ slightly from the UniFi Controller due to custom rule evaluation.
      </p>
    </div>
  )
}

// ── FilterBar ────────────────────────────────────────────────────────────────

const FILTER_OPTIONS = [
  { key: 'ipv4', label: 'IPv4' },
  { key: 'ipv6', label: 'IPv6' },
  { key: 'builtIn', label: 'Built-In' },
  { key: 'custom', label: 'Custom' },
  { key: 'inUse', label: 'In Use' },
  { key: 'paused', label: 'Paused' },
]

function FilterBar({ filters, onFilterChange, onBulk, bulkAction, zoneScopeLabel, allEnabled, allDisabled }) {
  return (
    <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
      <div className="flex items-center gap-3">
        {FILTER_OPTIONS.map(opt => (
          <label
            key={opt.key}
            className="flex items-center gap-1.5 text-[11px] text-[#cbced2] cursor-pointer select-none hover:text-[#f9fafa] transition-colors"
          >
            <input
              type="checkbox"
              checked={filters[opt.key]}
              onChange={() => onFilterChange({ ...filters, [opt.key]: !filters[opt.key] })}
              className="ui-checkbox"
            />
            {opt.label}
          </label>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[11px] text-[#676f79] flex items-center gap-1">
          {zoneScopeLabel ? (
            <>
              <span className="text-[#cbced2]">{zoneScopeLabel}</span> Toggles
            </>
          ) : (
            <>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" className="w-3.5 h-3.5 text-amber-400 shrink-0">
                <path fillRule="evenodd" d="M6.701 2.25c.577-1 2.02-1 2.598 0l5.196 9a1.5 1.5 0 01-1.299 2.25H2.804a1.5 1.5 0 01-1.3-2.25l5.197-9zM8 4a.75.75 0 01.75.75v3a.75.75 0 01-1.5 0v-3A.75.75 0 018 4zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
              </svg>
              All Policies Toggle
            </>
          )}
        </span>
        <button
          onClick={() => onBulk(true)}
          disabled={!!bulkAction || allEnabled}
          className="px-2.5 py-1 rounded text-[11px] font-medium text-teal-400 bg-teal-500/10 hover:bg-teal-500/20 border border-teal-500/20 disabled:opacity-40 transition-colors"
        >
          {bulkAction === 'enable' ? 'Enabling...' : 'Enable All Logging'}
        </button>
        <button
          onClick={() => onBulk(false)}
          disabled={!!bulkAction || allDisabled}
          className="disable-logging-btn px-2.5 py-1 rounded text-[11px] font-medium text-[#cbced2] hover:text-[#f9fafa] border border-white/[0.07] hover:border-white/[0.15] disabled:opacity-40 transition-colors"
        >
          {bulkAction === 'disable' ? 'Disabling...' : 'Disable All Logging'}
        </button>
      </div>
    </div>
  )
}

// ── PolicyRow ────────────────────────────────────────────────────────────────

function PolicyRow({ policy, zoneMap, onToggle, toggling, isSubRow }) {
  const origin = policy.metadata?.origin
  const isDerived = origin === 'DERIVED'
  const isDisabled = policy.enabled === false
  const action = policy.action?.type || ''
  const logging = policy.loggingEnabled
  const canToggle = !isDerived && !isDisabled && !toggling

  return (
    <tr className={`border-b border-white/[0.07] hover:bg-white/[0.02] ${isDisabled ? 'opacity-40 pointer-events-none' : ''}`}>
      {/* Name */}
      <td className={`${isSubRow ? 'pl-7' : 'px-2'} pr-8 py-0 h-8`}>
        <span
          className={`block truncate text-[12px] ${isDerived ? 'text-[#676f79]' : isSubRow ? 'text-[#cbced2]' : 'text-[#f9fafa]'}`}
          title={policy.description || policy.name}
        >
          {policy.name || '(unnamed)'}
        </span>
      </td>
      {/* Action */}
      <td className="px-2 pr-8 py-0 h-8">
        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
          action === 'BLOCK'
            ? 'bg-[#f0383b]/15 text-[#f36267]'
            : action === 'ALLOW'
              ? 'bg-[#38cc65]/15 text-[#61d684]'
              : 'bg-white/[0.04] text-[#676f79]'
        }`}>
          {action || '\u2014'}
        </span>
      </td>
      {/* Protocol */}
      <td className="px-2 pr-8 py-0 h-8 text-[11px] text-[#676f79] uppercase truncate">
        {policy.ipProtocolScope?.protocolFilter?.protocol?.name || policy.protocol || 'All'}
      </td>
      {/* Src Zone */}
      <td className="hidden sm:table-cell px-2 pr-8 py-0 h-8 text-[11px] text-[#cbced2] truncate">
        {zoneMap[policy.source?.zoneId] || '\u2014'}
      </td>
      {/* Dst Zone */}
      <td className="hidden sm:table-cell px-2 pr-8 py-0 h-8 text-[11px] text-[#cbced2] truncate">
        {zoneMap[policy.destination?.zoneId] || '\u2014'}
      </td>
      {/* ID */}
      <td className="px-2 pr-8 py-0 h-8 text-[11px] font-mono text-[#676f79]">
        {policy.index != null && policy.index < 2147483647 ? policy.index : '\u2014'}
      </td>
      {/* Syslog toggle */}
      <td className="px-2 py-0 h-8">
        <SyslogToggle
          checked={logging}
          disabled={!canToggle}
          onChange={(val) => onToggle(policy.id, val, origin)}
          title={isDerived ? 'Derived policies cannot be changed' : undefined}
        />
      </td>
    </tr>
  )
}

// ── GroupHeaderRow ──────────────────────────────────────────────────────────

function GroupHeaderRow({ group, expanded, onToggle, onToggleExpand, toggling }) {
  const { name, policies } = group
  const count = policies.length

  const actions = new Set(policies.map(p => p.action?.type || ''))
  const uniformAction = actions.size === 1 ? [...actions][0] : null

  const protocols = new Set(policies.map(p =>
    p.ipProtocolScope?.protocolFilter?.protocol?.name || p.protocol || 'All'
  ))
  const uniformProtocol = protocols.size === 1 ? [...protocols][0] : null

  const controllable = policies.filter(p =>
    p.metadata?.origin !== 'DERIVED' && p.enabled !== false
  )
  const enabledCount = controllable.filter(p => p.loggingEnabled).length
  const allEnabled = enabledCount === controllable.length && controllable.length > 0
  const noneEnabled = enabledCount === 0
  const canToggle = controllable.length > 0 && !toggling

  return (
    <tr
      className="border-b border-white/[0.07] hover:bg-white/[0.04] cursor-pointer"
      onClick={() => onToggleExpand(name)}
    >
      <td className="px-2 pr-8 py-0 h-8">
        <span className="flex items-center gap-1.5 text-[12px] text-[#f9fafa]">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor"
            className={`w-3 h-3 text-[#676f79] shrink-0 transition-transform duration-150 ${expanded ? 'rotate-90' : ''}`}
          >
            <path fillRule="evenodd" d="M6.22 4.22a.75.75 0 011.06 0l3.25 3.25a.75.75 0 010 1.06l-3.25 3.25a.75.75 0 01-1.06-1.06L8.94 8 6.22 5.28a.75.75 0 010-1.06z" clipRule="evenodd" />
          </svg>
          <span className="truncate" title={name}>{name}</span>
          <span className="shrink-0 ml-1 px-1.5 py-0.5 rounded-full bg-white/[0.07] text-[10px] text-[#676f79] font-medium">
            {count}
          </span>
        </span>
      </td>
      <td className="px-2 pr-8 py-0 h-8">
        {uniformAction ? (
          <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
            uniformAction === 'BLOCK'
              ? 'bg-[#f0383b]/15 text-[#f36267]'
              : uniformAction === 'ALLOW'
                ? 'bg-[#38cc65]/15 text-[#61d684]'
                : 'bg-white/[0.04] text-[#676f79]'
          }`}>
            {uniformAction}
          </span>
        ) : (
          <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase bg-white/[0.04] text-[#676f79]">
            Mixed
          </span>
        )}
      </td>
      <td className="px-2 pr-8 py-0 h-8 text-[11px] text-[#676f79] uppercase truncate">
        {uniformProtocol || 'Mixed'}
      </td>
      <td className="hidden sm:table-cell px-2 pr-8 py-0 h-8 text-[11px] text-[#676f79] truncate">Multiple</td>
      <td className="hidden sm:table-cell px-2 pr-8 py-0 h-8 text-[11px] text-[#676f79] truncate">Multiple</td>
      <td className="px-2 pr-8 py-0 h-8 text-[11px] font-mono text-[#676f79]">&mdash;</td>
      <td className="px-2 py-0 h-8" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-1">
          <SyslogToggle
            checked={allEnabled}
            disabled={!canToggle}
            onChange={(val) => onToggle(group, val)}
          />
          {!allEnabled && !noneEnabled && canToggle && (
            <span className="text-[9px] text-amber-400">&bull;</span>
          )}
        </div>
      </td>
    </tr>
  )
}

// ── Confirmation Modal ──────────────────────────────────────────────────────

function BulkConfirmModal({ action, count, srcZone, dstZone, onConfirm, onCancel, progress }) {
  const verb = action === 'enable' ? 'Enable' : 'Disable'
  const isRunning = !!progress

  const pct = progress && progress.total > 0 ? Math.round((progress.completed / progress.total) * 100) : 0

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60" onClick={isRunning ? undefined : onCancel}>
      <div
        className="bg-black border border-white/[0.07] rounded-xl shadow-2xl w-full max-w-sm mx-4 p-5"
        onClick={e => e.stopPropagation()}
      >
        <h3 className="text-base font-semibold text-[#f9fafa] mb-3">
          {isRunning ? (action === 'enable' ? 'Enabling' : 'Disabling') + ' Syslog Logging' : verb + ' Syslog Logging'}
        </h3>

        {!isRunning ? (
          <>
            <div className="text-sm text-[#cbced2] space-y-2 mb-4">
              {count >= 10 && (
                <p className="text-sm text-[#cbced2]">
                  {count >= 50
                    ? 'The UniFi Network API processes each rule individually. Large batches may take several minutes.'
                    : 'The UniFi Network API processes each rule individually. This may take up to a minute.'}
                </p>
              )}
              <p className="text-sm text-[#cbced2]">
                Changes are applied immediately on the UniFi Gateway but may take up to 5 minutes to reflect in the Log Stream.
              </p>
              {action === 'disable' && !srcZone && (
                <div className="px-3 py-2 rounded border border-[#f0383b]/40 bg-[#f0383b]/10 text-[#f0383b] text-xs">
                  Disabling syslog on all policies will prevent firewall logs from being received. No new log entries will appear until logging is re-enabled.
                </div>
              )}
              {action === 'disable' && srcZone && (
                <p className="text-sm text-[#676f79]">
                  Firewall events for this zone pair will no longer be logged.
                </p>
              )}
              {action === 'enable' && count > 50 && (
                <div className="px-3 py-2 rounded border border-[#f0383b]/40 bg-[#f0383b]/10 text-[#f0383b] text-xs">
                  Only enable logging on policies that add value. Performance of both the UniFi Controller and this app may be impacted when more than 200 policies have logging enabled.
                </div>
              )}
              <p>
                {verb} logging for <span className="font-semibold text-[#f9fafa]">{count}</span> eligible
                {count === 1 ? ' rule' : ' rules'}
                {srcZone && dstZone ? (
                  <> in zone pair <span className="font-semibold text-[#f9fafa]">{srcZone}</span> → <span className="font-semibold text-[#f9fafa]">{dstZone}</span>?</>
                ) : (
                  <> across <span className="font-semibold text-[#f9fafa]">All Policies</span>?</>
                )}
              </p>
            </div>
            <div className="flex items-center justify-end gap-2 mt-2">
              <button
                onClick={onCancel}
                className="disable-logging-btn px-3.5 py-1.5 rounded text-[12px] font-medium text-[#cbced2] hover:text-[#f9fafa] border border-white/[0.07] hover:border-white/[0.15] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={onConfirm}
                className={`px-3.5 py-1.5 rounded text-[12px] font-medium text-white transition-colors ${
                  action === 'enable'
                    ? 'bg-teal-600 hover:bg-teal-500'
                    : 'bg-red-600 hover:bg-red-500'
                }`}
              >
                {verb} Logging
              </button>
            </div>
          </>
        ) : (
          <div className="space-y-3">
            <div>
              <div className="flex items-center justify-between text-[11px] text-[#cbced2] mb-1.5">
                <span>
                  {progress.phase === 'verifying' ? 'Verifying changes...' : (
                    <>{progress.completed} <span className="text-[#676f79]">of</span> {progress.total} rules</>
                  )}
                </span>
                <span className="text-[#676f79]">{pct}%</span>
              </div>
              <div className="w-full h-1.5 bg-white/[0.07] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    action === 'enable' ? 'bg-teal-500' : 'bg-red-500'
                  }`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
            {progress.failed > 0 && (
              <div className="text-[11px] text-[#f36267]">{progress.failed} failed</div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function FirewallRules() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [toggling, setToggling] = useState(false)
  const [bulkAction, setBulkAction] = useState(null)
  const [pendingBulk, setPendingBulk] = useState(null) // { enableAll, eligible }
  const [bulkProgress, setBulkProgress] = useState(null) // { completed, total, success, failed, phase, eta }
  const [selectedCell, setSelectedCell] = useState(null)
  const [filters, setFilters] = useState({
    ipv4: true, ipv6: true, builtIn: true, custom: true, inUse: true, paused: true,
  })
  const [expandedGroups, setExpandedGroups] = useState(new Set())

  function toggleGroup(name) {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      next.has(name) ? next.delete(name) : next.add(name)
      return next
    })
  }

  useEffect(() => setExpandedGroups(new Set()), [selectedCell, filters])

  useEffect(() => { loadPolicies() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function loadPolicies() {
    setLoading(true)
    setError(null)
    try {
      setData(await fetchFirewallPolicies())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const sortedZones = useMemo(() => {
    if (!data?.zones) return []
    return sortZones(data.zones)
  }, [data])

  const zoneMap = useMemo(() => {
    if (!data?.zones) return {}
    return buildZoneMap(data.zones)
  }, [data])

  const matrixCells = useMemo(() => {
    if (!data?.policies || !sortedZones.length) return {}
    return buildMatrixData(data.policies, sortedZones)
  }, [data, sortedZones])

  const filteredPolicies = useMemo(() => {
    if (!data?.policies) return []
    let result = data.policies

    if (selectedCell) {
      result = result.filter(p =>
        p.source?.zoneId === selectedCell.srcZoneId &&
        p.destination?.zoneId === selectedCell.dstZoneId
      )
    }

    result = result.filter(p => {
      const origin = p.metadata?.origin
      const isBuiltIn = origin === 'SYSTEM_DEFINED' || origin === 'DERIVED'
      const isEnabled = p.enabled !== false
      const ipv = (p.ipProtocolScope?.ipVersion || p.ipVersion || 'IPv4').toLowerCase()
      const isV4 = ipv.includes('ipv4') || ipv.includes('v4')
      const isV6 = ipv.includes('ipv6') || ipv.includes('v6')
      const isBoth = isV4 && isV6

      if (!filters.builtIn && isBuiltIn) return false
      if (!filters.custom && !isBuiltIn) return false
      if (!filters.inUse && isEnabled) return false
      if (!filters.paused && !isEnabled) return false
      if (!filters.ipv4 && !filters.ipv6) return false
      if (!filters.ipv4 && isV4 && !isBoth) return false
      if (!filters.ipv6 && isV6 && !isBoth) return false

      return true
    })

    const originRank = { USER_DEFINED: 0, SYSTEM_DEFINED: 1, DERIVED: 2 }
    return result.sort((a, b) => {
      const ao = originRank[a.metadata?.origin] ?? 1
      const bo = originRank[b.metadata?.origin] ?? 1
      if (ao !== bo) return ao - bo
      return (a.name || '').localeCompare(b.name || '')
    })
  }, [data, selectedCell, filters])

  const groupedPolicies = useMemo(() => {
    const groupMap = new Map()
    for (const p of filteredPolicies) {
      const key = p.name || '(unnamed)'
      if (!groupMap.has(key)) groupMap.set(key, { name: key, policies: [] })
      groupMap.get(key).policies.push(p)
    }
    return Array.from(groupMap.values())
  }, [filteredPolicies])

  const { controllableTotal, controllableLoggingEnabled } = useMemo(() => {
    if (!data?.policies) return { controllableTotal: 0, controllableLoggingEnabled: 0 }
    const controllable = data.policies.filter(p =>
      p.metadata?.origin !== 'DERIVED' && p.enabled !== false
    )
    return {
      controllableTotal: controllable.length,
      controllableLoggingEnabled: controllable.filter(p => p.loggingEnabled).length,
    }
  }, [data])

  const { allEnabled, allDisabled } = useMemo(() => {
    const controllable = filteredPolicies.filter(p =>
      p.metadata?.origin !== 'DERIVED' && p.enabled !== false
    )
    // No controllable policies → both true so both buttons are disabled
    if (!controllable.length) return { allEnabled: true, allDisabled: true }
    return {
      allEnabled: controllable.every(p => p.loggingEnabled),
      allDisabled: controllable.every(p => !p.loggingEnabled),
    }
  }, [filteredPolicies])

  async function handleToggle(policyId, loggingEnabled, origin) {
    setToggling(true)
    try {
      await patchFirewallPolicy(policyId, loggingEnabled, origin)
      setData(prev => ({
        ...prev,
        policies: prev.policies.map(p =>
          p.id === policyId ? { ...p, loggingEnabled } : p
        ),
      }))
    } catch (err) {
      setError(err.message)
      setTimeout(() => setError(null), 5000)
    } finally {
      setToggling(false)
    }
  }

  function makeProgressCallback() {
    return (prog) => setBulkProgress(prog)
  }

  function handleBulkResult(result) {
    if (result?.failed > 0) {
      const msg = result.retried
        ? `${result.success} updated, ${result.failed} failed (${result.retried} retried)`
        : `${result.success} updated, ${result.failed} failed`
      setError(msg)
    }
  }

  async function handleGroupToggle(group, enableAll) {
    const eligible = group.policies.filter(p =>
      p.metadata?.origin !== 'DERIVED' &&
      p.enabled !== false &&
      p.loggingEnabled !== enableAll
    )
    if (!eligible.length) return

    setToggling(true)
    try {
      const policies = eligible.map(p => ({ id: p.id, loggingEnabled: enableAll }))
      const result = await bulkUpdateFirewallLoggingStream(policies, makeProgressCallback())
      setBulkProgress(null)
      await loadPolicies()
      handleBulkResult(result)
    } catch (err) {
      setBulkProgress(null)
      setError(err.message)
    } finally {
      setToggling(false)
    }
  }

  function handleBulkAction(enableAll) {
    const eligible = filteredPolicies.filter(p =>
      p.metadata?.origin !== 'DERIVED' &&
      p.enabled !== false &&
      p.loggingEnabled !== enableAll
    )
    if (!eligible.length) return
    setPendingBulk({ enableAll, eligible })
  }

  async function confirmBulkAction() {
    if (!pendingBulk) return
    const { enableAll, eligible } = pendingBulk

    setBulkAction(enableAll ? 'enable' : 'disable')
    setBulkProgress({ completed: 0, total: eligible.length, success: 0, failed: 0, phase: 'patching' })
    try {
      const policies = eligible.map(p => ({ id: p.id, loggingEnabled: enableAll }))
      const result = await bulkUpdateFirewallLoggingStream(policies, makeProgressCallback())
      setBulkProgress(null)
      setPendingBulk(null)
      await loadPolicies()
      handleBulkResult(result)
    } catch (err) {
      setBulkProgress(null)
      setPendingBulk(null)
      setError(err.message)
    } finally {
      setBulkAction(null)
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="animate-pulse space-y-4">
        <div className="grid grid-cols-4 gap-2">
          {[...Array(16)].map((_, i) => <div key={i} className="h-8 bg-gray-800 rounded" />)}
        </div>
        <div className="space-y-2">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-3 border border-gray-800 rounded">
              <div className="h-4 w-4 bg-gray-800 rounded" />
              <div className="h-3 bg-gray-800 rounded flex-1" />
              <div className="h-3 bg-gray-800 rounded w-20" />
              <div className="h-3 bg-gray-800 rounded w-16" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (error && !data) {
    return (
      <div className="text-center py-8">
        <p className="text-[#f36267] text-sm mb-3">{error}</p>
        <button onClick={loadPolicies} className="text-xs text-teal-400 hover:text-teal-300">Retry</button>
      </div>
    )
  }

  if (!data || !data.policies?.length) {
    return <div className="text-center py-8 text-[#676f79] text-sm">No firewall policies found.</div>
  }

  return (
    <div>
      {/* Bulk confirm modal */}
      {(pendingBulk || bulkProgress) && (
        <BulkConfirmModal
          action={bulkAction || (pendingBulk?.enableAll ? 'enable' : 'disable')}
          count={pendingBulk?.eligible.length ?? bulkProgress?.total ?? 0}
          srcZone={selectedCell ? zoneMap[selectedCell.srcZoneId] : null}
          dstZone={selectedCell ? zoneMap[selectedCell.dstZoneId] : null}
          onConfirm={confirmBulkAction}
          onCancel={() => setPendingBulk(null)}
          progress={bulkProgress}
        />
      )}

      {/* Zone Matrix */}
      <ZoneMatrix
        zones={sortedZones}
        cells={matrixCells}
        selectedCell={selectedCell}
        onSelectCell={setSelectedCell}
        totalPolicyCount={data.totalCount}
        syslogLabel={`${controllableLoggingEnabled} of ${controllableTotal} with syslog enabled`}
        onRefresh={loadPolicies}
        refreshDisabled={loading || !!bulkAction}
      />

      {/* Error banner */}
      {error && data && (
        <div className="mb-3 px-3 py-2 rounded bg-[#f0383b]/10 border border-[#f0383b]/30 text-xs text-[#f36267]">
          {error}
        </div>
      )}

      {/* Filters + bulk actions */}
      <FilterBar
        filters={filters}
        onFilterChange={setFilters}
        onBulk={handleBulkAction}
        bulkAction={bulkAction}
        zoneScopeLabel={selectedCell ? `${zoneMap[selectedCell.srcZoneId]} → ${zoneMap[selectedCell.dstZoneId]}` : null}
        allEnabled={allEnabled}
        allDisabled={allDisabled}
      />

      {/* Policy table */}
      <div className="scroll-fade border-b border-white/[0.07]">
        <table className="w-full table-fixed border-collapse">
          <colgroup>
            <col className="w-[50%] sm:w-[40%]" />
            <col className="w-[14%] sm:w-[9%]" />
            <col className="w-[12%] sm:w-[8%]" />
            <col className="hidden sm:table-column sm:w-[13%]" />
            <col className="hidden sm:table-column sm:w-[13%]" />
            <col className="w-[12%] sm:w-[7%]" />
            <col className="w-[12%] sm:w-[10%]" />
          </colgroup>
          <thead>
            <tr className="border-b border-white/[0.07]">
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Name</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Action</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Proto</th>
              <th className="hidden sm:table-cell px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Src Zone</th>
              <th className="hidden sm:table-cell px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Dst Zone</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">ID</th>
              <th className="px-2 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Syslog</th>
            </tr>
          </thead>
          <tbody>
            {groupedPolicies.map(group => {
              if (group.policies.length === 1) {
                const p = group.policies[0]
                return (
                  <PolicyRow
                    key={p.id}
                    policy={p}
                    zoneMap={zoneMap}
                    onToggle={handleToggle}
                    toggling={toggling}
                  />
                )
              }
              const expanded = expandedGroups.has(group.name)
              return (
                <React.Fragment key={`group-${group.name}`}>
                  <GroupHeaderRow
                    group={group}
                    expanded={expanded}
                    onToggle={handleGroupToggle}
                    onToggleExpand={toggleGroup}
                    toggling={toggling}
                  />
                  {expanded && group.policies.map(p => (
                    <PolicyRow
                      key={p.id}
                      policy={p}
                      zoneMap={zoneMap}
                      onToggle={handleToggle}
                      toggling={toggling}
                      isSubRow
                    />
                  ))}
                </React.Fragment>
              )
            })}
            {groupedPolicies.length === 0 && (
              <tr>
                <td colSpan={7} className="px-2 py-10 text-center text-sm text-[#676f79]">
                  No policies match the current filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="mt-2.5 text-[11px] text-[#676f79] px-0.5">
        Showing {filteredPolicies.length} of {data.totalCount} rules
      </div>
    </div>
  )
}
