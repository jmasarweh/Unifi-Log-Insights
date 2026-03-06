import { useState, useEffect } from 'react'
import { fetchIPPairs } from '../api'
import { formatNumber, formatServiceName, resolveIpSublines } from '../utils'
import IPCell from './IPCell'
import InfoTooltip from './InfoTooltip'
import KebabMenu, { SaveLoadMenuItems } from './KebabMenu'
import { exportCsv } from '../lib/exportCsv'

// Sankey node type → API param name mapping
const SANKEY_PARAM_MAP = {
  src_ip: 'src_ip',
  dst_ip: 'dst_ip',
  dst_port: 'dst_port',
  protocol: 'protocol',
  service_name: 'service',
  direction: 'direction',
  interface_in: 'interface_in',
  interface_out: 'interface_out',
}

const FILTER_LABELS = {
  src_ip: 'Source IP',
  dst_ip: 'Dest IP',
  dst_port: 'Dest Port',
  protocol: 'Protocol',
  service_name: 'Service',
  direction: 'Direction',
  interface_in: 'Interface In',
  interface_out: 'Interface Out',
}

function TopIPPairsMenuItems({ onSaveView, onLoadView, savedViews, onDeleteView, onExportCsv, close }) {
  return (
    <>
      <SaveLoadMenuItems
        onSaveView={onSaveView}
        onLoadView={onLoadView}
        savedViews={savedViews}
        onDeleteView={onDeleteView}
        close={close}
      />
      {/* Export CSV */}
      <button
        type="button"
        onClick={onExportCsv}
        className="w-full text-left px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 transition-colors"
      >
        Export CSV
      </button>
    </>
  )
}

// onIpClick(ip, rowIndex) — rowIndex is used by FlowView's toggle logic:
// clicking the same IP in the same row closes the panel, different row keeps it open.
export default function TopIPPairs({ filters, refreshKey, sankeyFilter, onClearSankeyFilter, zoneFilter, onClearZoneFilter, onIpClick, onSaveView, onLoadView, savedViews, onDeleteView, onRefreshViews }) {
  const [pairs, setPairs] = useState([])
  const [loading, setLoading] = useState(true)
  const [limit, setLimit] = useState(25)

  // Build stable dependency key for cross-filters
  const sankeyKey = sankeyFilter ? `${sankeyFilter.type}:${sankeyFilter.value}` : ''
  const zoneKey = zoneFilter ? `${zoneFilter.interface_in}:${zoneFilter.interface_out}` : ''

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const params = { ...filters, limit }
    if (sankeyFilter) {
      const paramKey = SANKEY_PARAM_MAP[sankeyFilter.type] || sankeyFilter.type
      params[paramKey] = sankeyFilter.value
    }
    if (zoneFilter) {
      params.interface_in = zoneFilter.interface_in
      params.interface_out = zoneFilter.interface_out
    }
    fetchIPPairs(params)
      .then(data => {
        if (!cancelled) setPairs(data.pairs || [])
      })
      .catch(err => console.error('IP pairs fetch failed:', err))
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [filters.time_range, filters.time_from, filters.time_to, filters.rule_action, filters.direction, sankeyKey, zoneKey, limit, refreshKey])

  const drillToLogs = (pair) => {
    window.dispatchEvent(new CustomEvent('drillToLogs', {
      detail: {
        src_ip: pair.src_ip,
        dst_ip: pair.dst_ip,
        dst_port: pair.dst_port,
        service: pair.service_name,
        time_range: filters.time_range,
        time_from: filters.time_from || undefined,
        time_to: filters.time_to || undefined,
      }
    }))
  }

  return (
    <div className="border border-gray-800 rounded-lg flex flex-col h-full">
      <div className="flex h-11 items-center justify-between px-4 border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-1.5">
          <h3 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">Top IP Pairs</h3>
          <InfoTooltip>
            <p>Click an IP address to open the host details panel.</p>
            <p>Click anywhere else on a row to drill down into the raw logs for that flow.</p>
          </InfoTooltip>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">Show</label>
          <select
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
            className="bg-gray-800 text-gray-300 text-xs rounded px-1.5 py-0.5 border border-gray-700"
          >
            {[10, 25, 50, 100].map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <KebabMenu onOpen={onRefreshViews}>
            {({ close }) => (
              <TopIPPairsMenuItems
                onSaveView={onSaveView}
                onLoadView={onLoadView}
                savedViews={savedViews}
                onDeleteView={onDeleteView}
                onExportCsv={() => { exportCsv(filters, sankeyFilter, zoneFilter); close() }}
                close={close}
              />
            )}
          </KebabMenu>
        </div>
      </div>

      {/* Cross-filter banner */}
      {(sankeyFilter || zoneFilter) && (
        <div className="flex items-center gap-2 px-4 py-1.5 bg-blue-500/10 border-b border-blue-500/20 text-xs text-blue-300 shrink-0">
          <span>Filtered by</span>
          {sankeyFilter && (
            <>
              <span className="font-medium">{FILTER_LABELS[sankeyFilter.type] || sankeyFilter.type}: {sankeyFilter.value}</span>
              <button onClick={onClearSankeyFilter} className="ml-1 text-blue-400 hover:text-blue-200">&times;</button>
            </>
          )}
          {zoneFilter && (
            <>
              <span className="font-medium">{zoneFilter.in_label || zoneFilter.interface_in} &rarr; {zoneFilter.out_label || zoneFilter.interface_out}</span>
              <button onClick={onClearZoneFilter} className="ml-1 text-blue-400 hover:text-blue-200">&times;</button>
            </>
          )}
        </div>
      )}

      {loading ? (
        <div className="overflow-y-auto overflow-x-hidden min-h-0 flex-1 animate-pulse">
          <table className="w-full table-fixed">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wider">
                <th className="text-left px-2 py-2 font-medium w-[30%] sm:w-[25%]">Source</th>
                <th className="text-left px-2 py-2 font-medium w-[30%] sm:w-[25%]">Destination</th>
                <th className="text-left px-3 py-2 font-medium w-[20%] sm:w-[16%]">Port/Proto</th>
                <th className="text-left px-3 py-2 font-medium hidden sm:table-cell sm:w-[14%]">Service</th>
                <th className="text-left px-3 py-2 font-medium w-[20%] sm:w-[20%]">Action</th>
              </tr>
            </thead>
            <tbody>
              {[...Array(8)].map((_, i) => (
                <tr key={i} className="border-t border-gray-800/50">
                  <td className="px-2 py-2.5"><div className="h-3 bg-gray-800 rounded w-3/4" /></td>
                  <td className="px-2 py-2.5"><div className="h-3 bg-gray-800 rounded w-3/4" /></td>
                  <td className="px-3 py-2.5"><div className="h-3 bg-gray-800 rounded w-1/2" /></td>
                  <td className="px-3 py-2.5 hidden sm:table-cell"><div className="h-3 bg-gray-800 rounded w-2/3" /></td>
                  <td className="px-3 py-2.5"><div className="h-3 bg-gray-800 rounded w-1/2" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : pairs.length === 0 ? (
        <div className="p-4 text-center text-xs text-gray-500">No flow data for this time range</div>
      ) : (
        <div className="overflow-y-auto overflow-x-hidden min-h-0 flex-1 text-xs">
          <table className="w-full table-fixed">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wider">
                <th className="text-left px-2 py-2 font-medium whitespace-nowrap w-[30%] sm:w-[25%]">Source</th>
                <th className="text-left px-2 py-2 font-medium whitespace-nowrap w-[30%] sm:w-[25%]">Destination</th>
                <th className="text-left px-3 py-2 font-medium whitespace-nowrap w-[20%] sm:w-[16%]">Port/Proto</th>
                <th className="text-left px-3 py-2 font-medium whitespace-nowrap hidden sm:table-cell sm:w-[14%]">Service</th>
                <th className="text-left px-3 py-2 font-medium whitespace-nowrap w-[20%] sm:w-[20%]">Action</th>
              </tr>
            </thead>
            <tbody>
              {pairs.map((p, i) => {
                const { srcSubline, dstSubline } = resolveIpSublines(p)
                return (
                <tr
                  key={i}
                  onClick={() => drillToLogs(p)}
                  className="border-t border-gray-800/50 hover:bg-gray-800/30 cursor-pointer transition-colors"
                >
                  <td className="px-2 py-1.5 align-middle min-w-0">
                    <div onClick={onIpClick ? (e) => { e.stopPropagation(); onIpClick(p.src_ip, i) } : undefined}
                         className={onIpClick ? 'cursor-pointer ip-clickable' : ''}>
                      <IPCell ip={p.src_ip} deviceName={p.src_device_name} subline={srcSubline} />
                    </div>
                  </td>
                  <td className="px-2 py-1.5 align-middle min-w-0">
                    <div className="flex items-start gap-1.5 min-w-0">
                      <span className="text-gray-600 pt-0.5 shrink-0">&rarr;</span>
                      <div onClick={onIpClick ? (e) => { e.stopPropagation(); onIpClick(p.dst_ip, i) } : undefined}
                           className={`min-w-0 ${onIpClick ? 'cursor-pointer ip-clickable' : ''}`}>
                        <IPCell ip={p.dst_ip} deviceName={p.dst_device_name} subline={dstSubline} />
                      </div>
                    </div>
                  </td>
                  <td className="px-3 py-1.5 text-gray-300 font-mono text-[11px] whitespace-nowrap">
                    {p.dst_port}/{(p.protocol || '').toUpperCase()}
                  </td>
                  <td className="px-3 py-1.5 text-gray-400 hidden sm:table-cell">
                    <div className="truncate" title={formatServiceName(p.service_name)}>
                      {formatServiceName(p.service_name)}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 whitespace-nowrap">
                    <div className="flex items-center flex-nowrap gap-1">
                      {p.allow_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                          {formatNumber(p.allow_count)}
                        </span>
                      )}
                      {p.block_count > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/40">
                          {formatNumber(p.block_count)}
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
