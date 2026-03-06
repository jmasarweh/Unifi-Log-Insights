import { useState, useEffect, useRef } from 'react'
import { fetchHostDetail } from '../api'
import { formatNumber, formatServiceName, ACTION_STYLES } from '../utils'

export default function HostSlidePanel({ ip, filters, onClose, onPeerClick }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [visible, setVisible] = useState(false)
  const closeTimeoutRef = useRef(null)

  // Trigger slide-in animation after mount
  useEffect(() => {
    const frame = requestAnimationFrame(() => setVisible(true))
    return () => cancelAnimationFrame(frame)
  }, [])

  // Clear close timeout on unmount
  useEffect(() => {
    return () => { if (closeTimeoutRef.current) clearTimeout(closeTimeoutRef.current) }
  }, [])

  useEffect(() => {
    if (!ip) return
    let cancelled = false
    setLoading(true)
    setError(null)
    fetchHostDetail({ ip, ...filters })
      .then(d => { if (!cancelled) setData(d) })
      .catch(err => { if (!cancelled) setError(err.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [ip, filters.time_range, filters.rule_action, filters.direction])

  const handleClose = () => {
    setVisible(false)
    closeTimeoutRef.current = setTimeout(onClose, 300) // wait for slide-out animation
  }

  return (
    <div
      className={`absolute inset-0 z-10 bg-black border border-gray-800 rounded-lg flex flex-col transition-transform duration-300 ease-out ${
        visible ? 'translate-x-0' : 'translate-x-full'
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          {loading ? (
            <span className="text-xs text-gray-500">Loading...</span>
          ) : error ? (
            <span className="text-xs text-red-400">{error}</span>
          ) : data ? (
            <>
              <span className="text-sm font-semibold text-gray-100 font-mono truncate">{data.device_name || data.ip}</span>
              {data.device_name && <span className="text-xs text-gray-500 font-mono">{data.ip}</span>}
              {data.network && (
                <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0">
                  {data.network}{data.vlan != null ? ` (VLAN ${data.vlan})` : ''}
                </span>
              )}
            </>
          ) : null}
        </div>
        <button onClick={handleClose} className="text-gray-500 hover:text-gray-300 text-lg leading-none ml-2 shrink-0" aria-label="Close panel" type="button">&times;</button>
      </div>

      {loading || error || !data ? null : (
        <div className="overflow-y-auto min-h-0 flex-1">
          {/* Summary stats */}
          <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800/50 text-xs shrink-0">
            <span className={`px-1.5 py-0.5 rounded font-medium border ${ACTION_STYLES.allow}`}>{formatNumber(data.summary?.allow_count ?? 0)} Allow</span>
            <span className={`px-1.5 py-0.5 rounded font-medium border ${ACTION_STYLES.block}`}>{formatNumber(data.summary?.block_count ?? 0)} Block</span>
            <span className="text-gray-400">{formatNumber(data.summary?.total_events ?? 0)} Events</span>
            <span className="text-gray-400">{formatNumber(data.summary?.unique_peers ?? 0)} Peers</span>
          </div>

          {/* Peers — side by side */}
          <div className="grid grid-cols-2">
            {/* Outbound peers */}
            <div className="border-r border-gray-800/50">
              <div className="px-4 py-2 text-xs text-gray-500 uppercase tracking-wider font-bold">Outbound Peers</div>
              {(data.peers_as_source ?? []).length === 0 ? (
                <div className="px-4 py-2 text-xs text-gray-600">No outbound traffic</div>
              ) : (
                <table className="w-full text-xs">
                  <tbody>
                    {(data.peers_as_source ?? []).map((peer, i) => (
                      <tr
                        key={i}
                        className="border-t border-gray-800/30 hover:bg-gray-800/30 cursor-pointer transition-colors"
                        onClick={() => onPeerClick?.(peer.peer_ip)}
                      >
                        <td className="px-4 py-1.5">
                          <span className="text-gray-200 font-mono hover:text-blue-400">{peer.peer_ip}</span>
                          {peer.device_name && (
                            <span className="ml-2 text-xs text-gray-500">{peer.device_name}</span>
                          )}
                        </td>
                        <td className="px-2 py-1.5 text-right text-gray-300 tabular-nums">{formatNumber(peer.count)}</td>
                        <td className="px-2 py-1.5 text-right">
                          {peer.block_count > 0 && <span className="text-red-400 text-xs">{formatNumber(peer.block_count)} blk</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            {/* Inbound peers */}
            <div>
              <div className="px-4 py-2 text-xs text-gray-500 uppercase tracking-wider font-bold">Inbound Peers</div>
              {(data.peers_as_destination ?? []).length === 0 ? (
                <div className="px-4 py-2 text-xs text-gray-600">No inbound traffic</div>
              ) : (
                <table className="w-full text-xs">
                  <tbody>
                    {(data.peers_as_destination ?? []).map((peer, i) => (
                      <tr
                        key={i}
                        className="border-t border-gray-800/30 hover:bg-gray-800/30 cursor-pointer transition-colors"
                        onClick={() => onPeerClick?.(peer.peer_ip)}
                      >
                        <td className="px-4 py-1.5">
                          <span className="text-gray-200 font-mono hover:text-blue-400">{peer.peer_ip}</span>
                          {peer.device_name && (
                            <span className="ml-2 text-xs text-gray-500">{peer.device_name}</span>
                          )}
                        </td>
                        <td className="px-2 py-1.5 text-right text-gray-300 tabular-nums">{formatNumber(peer.count)}</td>
                        <td className="px-2 py-1.5 text-right">
                          {peer.block_count > 0 && <span className="text-red-400 text-xs">{formatNumber(peer.block_count)} blk</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Top Ports */}
          {data.ports?.length > 0 && (
            <div className="border-t border-gray-800/50">
              <div className="px-4 py-2 text-xs text-gray-500 uppercase tracking-wider font-bold">Top Ports</div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-xs text-gray-500 uppercase tracking-wider">
                    <th className="text-left px-4 py-1 font-bold">Port</th>
                    <th className="text-left px-2 py-1 font-bold">Service</th>
                    <th className="text-left px-2 py-1 font-bold">Proto</th>
                    <th className="text-right px-4 py-1 font-bold">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.ports ?? []).map((port, i) => (
                    <tr key={i} className="border-t border-gray-800/30">
                      <td className="px-4 py-1.5 text-gray-200 font-mono">{port.dst_port}</td>
                      <td className="px-2 py-1.5 text-gray-400">{formatServiceName(port.service_name)}</td>
                      <td className="px-2 py-1.5 text-gray-400 uppercase">{port.protocol}</td>
                      <td className="px-4 py-1.5 text-right text-gray-300 tabular-nums">{formatNumber(port.count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
