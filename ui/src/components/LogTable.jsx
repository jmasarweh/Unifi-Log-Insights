import React from 'react'
import {
  formatTime, FlagIcon, countryName, getInterfaceName, formatServiceName, resolveIpSublines,
  normalizeRuleDesc, LOG_TYPE_STYLES, ACTION_STYLES,
  DIRECTION_ICONS, DIRECTION_COLORS, decodeThreatCategories,
} from '../utils'
import { getThreatLevel } from '../lib/threatPresentation'
import LogDetail from './LogDetail'
import IPCell from './IPCell'

// UniFi firewall icon (brick-wall pattern, fill-based)
const UNIFI_FIREWALL_ICON = (
  <path fillRule="evenodd" clipRule="evenodd" d="M8 5h4v2H8V5Zm5 2V5h4v2h-4Zm5 0h2V5h-2v2ZM7 5H4v2h3V5ZM4 8h1v2H4V8Zm2 2V8h4v2H6Zm5 0h4V8h-4v2Zm5 0V8h4v2h-4ZM3 7v12a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v2Zm5 6v-2h4v2H8Zm5 0v-2h4v2h-4Zm5 0v-2h2v2h-2ZM7 11H4v2h3v-2Zm-3 8v-2h3v2H4Zm4 0v-2h4v2H8Zm10 0h2v-2h-2v2Zm-1 0v-2h-4v2h4Zm3-5v2h-4v-2h4Zm-5 0v2h-4v-2h4Zm-5 0v2H6v-2h4Zm-5 0v2H4v-2h1Z" fill="currentColor" />
)

// Firewall action color
const FIREWALL_ACTION_COLORS = {
  block:    'text-red-400',
  allow:    'text-emerald-400',
  redirect: 'text-amber-400',
}

// Non-firewall mobile type icons (Lucide SVG paths, stroke-based)
const LOG_TYPE_ICON_PATHS = {
  dns:      <><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></>,
  dhcp:     <><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></>,
  wifi:     <><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1"/></>,
  ids:      <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></>,
  system:   <><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></>,
}

const LOG_TYPE_ICON_COLORS = {
  dns:      'text-violet-400',
  dhcp:     'text-cyan-400',
  wifi:     'text-gray-400',
  ids:      'text-red-400',
  system:   'text-gray-300',
}

// Mobile action abbreviations for non-firewall logs
const MOBILE_ACTION_LABELS = {
  DHCPACK:       'ACK',
  DHCPDISCOVER:  'DISC',
  DHCPREQUEST:   'REQ',
  DHCPOFFER:     'OFR',
  associated:    'ASSOC',
  disassociated: 'DISSOC',
}

function ThreatBadge({ score, categories }) {
  const level = getThreatLevel(score)
  if (!level) return <span className="text-gray-700">—</span>

  const catText = decodeThreatCategories(categories)

  return (
    <span className="inline-flex items-center gap-1" title={catText || `Threat score: ${score}%`}>
      <span className={`w-1.5 h-1.5 rounded-full ${level.dot}`} />
      <span className="text-gray-300">{score}</span>
    </span>
  )
}

function NetworkPath({ ifaceIn, ifaceOut }) {
  if (!ifaceIn && !ifaceOut) return <span className="text-gray-700">—</span>

  if (!ifaceOut) {
    return <span className="text-gray-200">{getInterfaceName(ifaceIn)}</span>
  }

  return (
    <span className="inline-flex items-center gap-1">
      <span className={ifaceIn ? 'text-gray-200' : 'text-gray-400 italic'}>{ifaceIn ? getInterfaceName(ifaceIn) : 'Gateway'}</span>
      <span className="text-gray-500">→</span>
      <span className="text-gray-200">{getInterfaceName(ifaceOut)}</span>
    </span>
  )
}

function LogRow({ log, isExpanded, detailedLog, onToggle, hiddenColumns, colCount, uiSettings }) {
  const actionStyle = ACTION_STYLES[log.rule_action || log.dhcp_event || log.wifi_event] || ''
  const typeStyle = LOG_TYPE_STYLES[log.log_type] || LOG_TYPE_STYLES.system
  const dirIcon = DIRECTION_ICONS[log.direction] || ''
  const dirColor = DIRECTION_COLORS[log.direction] || 'text-gray-500'

  const infoText = log.log_type === 'firewall'
    ? (normalizeRuleDesc(log.rule_desc) || log.rule_name || '—')
    : (log.dns_query || log.hostname || log.wifi_event || '—')

  const infoTitle = log.log_type === 'firewall'
    ? (normalizeRuleDesc(log.rule_desc) || log.rule_name || '')
    : infoText

  const show = (key) => !hiddenColumns.has(key)
  const countryDisplay = uiSettings?.ui_country_display || 'flag_name'
  const ipSubline = uiSettings?.ui_ip_subline === 'asn_or_abuse'
  const { srcSubline, dstSubline } = ipSubline ? resolveIpSublines(log) : { srcSubline: null, dstSubline: null }

  const highlightBlock = uiSettings?.ui_block_highlight !== 'off'
    && log.rule_action === 'block'
    && (log.threat_score ?? 0) >= (uiSettings?.ui_block_highlight_threshold ?? 0)

  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer transition-colors hover:bg-gray-800/30 ${
          isExpanded ? 'expanded-row' : 'border-b border-gray-800/50'
        } ${highlightBlock ? 'bg-red-950/10' : ''}`}
      >
        {/* Time */}
        <td className="px-3 py-1.5 text-[13px] text-gray-400 whitespace-nowrap font-light">
          {formatTime(log.timestamp)}
        </td>

        {/* Type — desktop only */}
        <td className="hidden sm:table-cell px-2 py-1.5">
          <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${typeStyle}`}>
            {log.log_type}
          </span>
        </td>

        {/* Action (combined Type + Action on mobile) */}
        <td className="px-1 sm:px-2 py-1.5 text-center sm:text-left">
          {/* Desktop: action badge */}
          {(log.rule_action || log.dhcp_event || log.wifi_event) ? (
            <span className={`hidden sm:inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${actionStyle}`}>
              {log.rule_action || log.dhcp_event || log.wifi_event}
            </span>
          ) : (
            <span className="hidden sm:inline-block text-gray-700 text-[12px]">—</span>
          )}
          {/* Mobile: combined type + action icon */}
          <span className="sm:hidden inline-flex items-center justify-center gap-1">
            {log.log_type === 'firewall' ? (
              log.rule_action === 'block' || log.rule_action === 'allow' ? (
                <>
                  <svg className={`w-5 h-5 ${FIREWALL_ACTION_COLORS[log.rule_action]}`}
                       viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                    {UNIFI_FIREWALL_ICON}
                  </svg>
                  <span className="sr-only">Firewall {log.rule_action}</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <polyline points="15 10 20 15 15 20"/>
                    <path d="M4 4v7a4 4 0 0 0 4 4h12"/>
                  </svg>
                  <span className="sr-only">Firewall {log.rule_action || 'redirect'}</span>
                </>
              )
            ) : (
              <>
                {LOG_TYPE_ICON_PATHS[log.log_type] && (
                  <svg className={`w-3.5 h-3.5 ${LOG_TYPE_ICON_COLORS[log.log_type] || 'text-gray-400'}`}
                       viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    {LOG_TYPE_ICON_PATHS[log.log_type]}
                  </svg>
                )}
                {(log.dhcp_event || log.wifi_event) && (
                  <span className="text-[9px] font-semibold text-gray-400 uppercase">
                    {MOBILE_ACTION_LABELS[log.dhcp_event || log.wifi_event] || log.dhcp_event || log.wifi_event}
                  </span>
                )}
                {!log.dhcp_event && !log.wifi_event && (
                  <span className="sr-only">{log.log_type}</span>
                )}
              </>
            )}
          </span>
        </td>

        {/* Source */}
        <td className="px-2 py-1.5 text-[13px] whitespace-nowrap max-w-[120px] sm:max-w-[180px] truncate">
          <IPCell ip={log.src_ip} port={log.src_port} deviceName={log.src_device_name} vlan={log.src_device_vlan} networkLabel={log.src_device_network} subline={srcSubline} />
        </td>

        {/* Direction */}
        <td className={`px-1.5 py-1.5 text-center text-sm ${dirColor}`} title={log.direction}>
          {dirIcon}
        </td>

        {/* Destination */}
        <td className="px-2 py-1.5 text-[13px] whitespace-nowrap max-w-[120px] sm:max-w-[180px] truncate">
          <IPCell ip={log.dst_ip} port={log.dst_port} deviceName={log.dst_device_name} vlan={log.dst_device_vlan} networkLabel={log.dst_device_network} subline={dstSubline} />
        </td>

        {/* Country */}
        {show('country') && (
          <td className="px-1 sm:px-2 py-1.5 text-[13px] whitespace-nowrap text-center" title={countryName(log.geo_country)}>
            {log.geo_country ? (
              <span className="inline-flex items-center justify-center gap-1">
                {countryDisplay !== 'name_only' && <FlagIcon code={log.geo_country} />}
                {countryDisplay !== 'flag_only' && (
                  <span className="text-gray-400">{log.geo_country}</span>
                )}
              </span>
            ) : (
              <span className="text-gray-700">—</span>
            )}
          </td>
        )}

        {/* ASN */}
        {show('asn') && (
          <td className="px-2 py-1.5 text-[12px] text-gray-400 whitespace-nowrap sm:max-w-[150px] sm:truncate" title={log.asn_name || ''}>
            {log.asn_name || '—'}
          </td>
        )}

        {/* Network Path */}
        <td className="px-2 py-1.5 text-[12px] whitespace-nowrap">
          <NetworkPath ifaceIn={log.interface_in} ifaceOut={log.interface_out} />
        </td>

        {/* Protocol */}
        {show('proto') && (
          <td className="hidden sm:table-cell px-2 py-1.5 text-[13px] text-gray-400 uppercase">
            {log.protocol || '—'}
          </td>
        )}

        {/* Service */}
        <td className="hidden sm:table-cell px-2 py-1.5 text-[12px] text-gray-400">
          {formatServiceName(log.service_name)}
        </td>

        {/* Rule / Info */}
        {show('rule') && (
          <td className="px-2 py-1.5 text-[12px] text-gray-400 whitespace-nowrap sm:max-w-[180px] sm:truncate" title={infoTitle}>
            {infoText}
          </td>
        )}

        {/* AbuseIPDB */}
        {show('threat') && (
          <td className="px-2 py-1.5 text-[13px] text-center">
            <ThreatBadge score={log.threat_score} categories={log.threat_categories} />
          </td>
        )}

        {/* Threat Categories */}
        {show('categories') && (
          <td className="px-2 py-1.5 text-[11px] text-purple-400/70 whitespace-nowrap sm:max-w-[180px] sm:truncate" title={decodeThreatCategories(log.threat_categories) || ''}>
            {decodeThreatCategories(log.threat_categories) || <span className="text-gray-700">—</span>}
          </td>
        )}
      </tr>

      {isExpanded && (
        <tr className="expanded-detail">
          <td colSpan={colCount}>
            <LogDetail log={detailedLog || log} hiddenColumns={hiddenColumns} />
          </td>
        </tr>
      )}
    </>
  )
}

export default function LogTable({ logs, loading, expandedId, detailedLog, onToggleExpand, hiddenColumns = new Set(), uiSettings }) {

  // Auto-hide ASN column when IP subline is enabled
  const effectiveHidden = uiSettings?.ui_ip_subline === 'asn_or_abuse'
    ? new Set([...hiddenColumns, 'asn'])
    : hiddenColumns

  const allColumns = [
    { key: 'timestamp', label: 'Time', className: 'w-20' },
    { key: 'log_type', label: 'Type', className: 'hidden sm:table-cell sm:w-20' },
    { key: 'action', label: 'Action', className: 'w-10 sm:w-20' },
    { key: 'src', label: 'Source', className: 'w-32 sm:w-40' },
    { key: 'dir', label: '', className: 'w-6' },
    { key: 'dst', label: 'Destination', className: 'w-32 sm:w-40' },
    { key: 'country', label: 'Country', className: 'w-16 text-center' },
    { key: 'asn', label: 'ASN', className: 'w-36' },
    { key: 'network', label: 'Network', className: 'w-28' },
    { key: 'proto', label: 'Proto', className: 'hidden sm:table-cell sm:w-12' },
    { key: 'service', label: 'Service', className: 'hidden sm:table-cell sm:w-28' },
    { key: 'rule', label: 'Rule / Info', className: 'w-48' },
    { key: 'threat', label: 'AbuseIPDB', className: 'w-20' },
    { key: 'categories', label: 'Categories', className: 'w-40' },
  ]

  const visibleColumns = allColumns.filter(col => !effectiveHidden.has(col.key))
  const colCount = visibleColumns.length

  return (
    <div>
      <table className="w-full text-left">
        <thead className="sticky top-0 z-10">
          <tr className="bg-gray-950">
            {visibleColumns.map(col => (
              <th
                key={col.key}
                className={`px-2 py-2 text-[12px] text-gray-400 font-medium uppercase tracking-wider ${col.className}`}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            [...Array(12)].map((_, i) => (
              <tr key={i} className="animate-pulse border-b border-gray-800/50">
                {visibleColumns.map(col => (
                  <td key={col.key} className="px-2 py-2.5">
                    <div className="h-3 bg-gray-800 rounded w-3/4" />
                  </td>
                ))}
              </tr>
            ))
          ) : logs.length === 0 ? (
            <tr>
              <td colSpan={colCount} className="text-center py-12 text-gray-500 text-sm">
                No logs match current filters
              </td>
            </tr>
          ) : (
            logs.map(log => (
              <LogRow
                key={log.id}
                log={log}
                isExpanded={expandedId === log.id}
                detailedLog={expandedId === log.id ? detailedLog : null}
                onToggle={() => onToggleExpand(log.id)}
                hiddenColumns={effectiveHidden}
                colCount={colCount}
                uiSettings={uiSettings}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
