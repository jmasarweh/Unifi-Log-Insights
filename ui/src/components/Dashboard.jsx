import { useState, useEffect } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { fetchStats } from '../api'
import { formatNumber, FlagIcon, countryName, decodeThreatCategories, LOG_TYPE_STYLES, ACTION_STYLES, formatServiceName, DIRECTION_ICONS, DIRECTION_COLORS } from '../utils'
import { getThreatLevel } from '../lib/threatPresentation'
import NetworkBadge from './NetworkBadge'
import useTimeRange from '../hooks/useTimeRange'

export function DashboardSkeleton() {
  return (
    <div className="p-4 space-y-4 overflow-auto max-h-full animate-pulse">
      {/* Time range selector */}
      <div className="flex gap-1">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-7 w-10 bg-gray-800 rounded" />
        ))}
      </div>
      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="h-2.5 w-24 bg-gray-800 rounded" />
          <div className="h-7 w-16 bg-gray-800 rounded" />
          <div className="flex gap-2">
            {[...Array(3)].map((_, i) => <div key={i} className="h-6 w-20 bg-gray-800 rounded" />)}
          </div>
          <div className="flex gap-2 pt-3 border-t border-gray-800/50">
            {[...Array(4)].map((_, i) => <div key={i} className="h-6 w-24 bg-gray-800 rounded" />)}
          </div>
        </div>
        <div className="border border-gray-800 rounded-lg p-4 space-y-3">
          <div className="h-2.5 w-16 bg-gray-800 rounded" />
          <div className="flex flex-wrap gap-2">
            {[...Array(4)].map((_, i) => <div key={i} className="h-6 w-24 bg-gray-800 rounded" />)}
          </div>
        </div>
      </div>
      {/* Charts */}
      <div className="border border-gray-800 rounded-lg p-4 h-40" />
      <div className="border border-gray-800 rounded-lg p-4 h-52" />
      {/* Section header */}
      <div className="h-3 w-24 bg-gray-800 rounded mt-2" />
      {/* Panel grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="border border-gray-800 rounded-lg p-4 h-48" />
        ))}
      </div>
      {/* Section header */}
      <div className="h-3 w-24 bg-gray-800 rounded mt-2" />
      {/* Allowed panel grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="border border-gray-800 rounded-lg p-4 h-48" />
        ))}
      </div>
    </div>
  )
}


function MiniBar({ data, maxVal, color = 'bg-blue-500' }) {
  if (!maxVal) return null
  const pct = (data / maxVal) * 100
  return (
    <div className="w-full bg-gray-800 rounded-full h-1.5">
      <div className={`${color} h-1.5 rounded-full transition-all`} style={{ width: `${pct}%` }} />
    </div>
  )
}

function formatXAxis(iso, timeRange) {
  const d = new Date(iso)
  if (['1h', '6h', '24h'].includes(timeRange)) {
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  }
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
}

function ChartTooltip({ active, payload, timeRange }) {
  if (!active || !payload?.length) return null
  const d = new Date(payload[0].payload.period)
  const label = ['1h', '6h', '24h'].includes(timeRange)
    ? d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
  return (
    <div className="bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-xs shadow-lg">
      <div className="text-gray-400 mb-1">{label}</div>
      <div className="text-gray-200 font-medium">{formatNumber(payload[0].value)} logs</div>
    </div>
  )
}

function ActionTooltip({ active, payload, timeRange }) {
  if (!active || !payload?.length) return null
  const row = payload[0].payload
  const d = new Date(row.period)
  const label = ['1h', '6h', '24h'].includes(timeRange)
    ? d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
  const keys = { Redirect: 'redirect', Blocked: 'block', Allowed: 'allow' }
  const total = (row.allow || 0) + (row.block || 0) + (row.redirect || 0)
  return (
    <div className="bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-xs shadow-lg">
      <div className="text-gray-400 mb-1.5">{label}</div>
      {[...payload].reverse().map((p, i) => {
        const raw = row[keys[p.name]] || 0
        const pct = total > 0 ? Math.round((raw / total) * 100) : 0
        return (
          <div key={i} className="flex items-center justify-between gap-4">
            <span style={{ color: p.color }}>{p.name}</span>
            <span className="text-gray-200 font-medium">{formatNumber(raw)} <span className="text-gray-500">({pct}%)</span></span>
          </div>
        )
      })}
      <div className="border-t border-gray-700 mt-1.5 pt-1.5 flex justify-between text-gray-300">
        <span>Total</span>
        <span className="font-medium">{formatNumber(total)}</span>
      </div>
    </div>
  )
}

const RANGE_MS = {
  '1h': 3600e3, '6h': 21600e3, '24h': 86400e3, '7d': 604800e3,
  '30d': 2592e6, '60d': 5184e6, '90d': 7776e6, '180d': 15552e6, '365d': 31536e6,
}

function isSparseData(data, timeRange) {
  if (!data || data.length < 2) return true
  const first = new Date(data[0].period).getTime()
  const last = new Date(data[data.length - 1].period).getTime()
  const span = last - first
  const rangeMs = RANGE_MS[timeRange] || 3600e3
  return span < rangeMs * 0.15
}

function LogsOverTimeChart({ data, timeRange, loading }) {
  if (!data || data.length === 0) {
    return <div className="text-gray-400 text-xs text-center py-8">{loading ? 'Loading...' : 'No data yet'}</div>
  }
  if (isSparseData(data, timeRange)) {
    if (loading) return <div className="text-gray-400 text-xs text-center py-8">Loading...</div>
    return <div className="text-gray-500 text-xs text-center py-8">Not enough data to display a chart. Try selecting a shorter time range.</div>
  }
  return (
    <ResponsiveContainer width="100%" height={140}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="logsGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.05} />
          </linearGradient>
        </defs>
        <XAxis dataKey="period" tickFormatter={(v) => formatXAxis(v, timeRange)}
               tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false}
               interval="preserveStartEnd" />
        <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} axisLine={false} tickLine={false} width={40}
               tickFormatter={v => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v} />
        <Tooltip content={<ChartTooltip timeRange={timeRange} />} />
        <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2}
              fill="url(#logsGrad)" dot={false} activeDot={{ r: 4, fill: '#3b82f6' }} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function TrafficByActionChart({ data, timeRange, loading }) {
  if (!data || data.length === 0) {
    return <div className="text-gray-400 text-xs text-center py-8">{loading ? 'Loading...' : 'No data yet'}</div>
  }
  if (isSparseData(data, timeRange)) {
    if (loading) return <div className="text-gray-400 text-xs text-center py-8">Loading...</div>
    return <div className="text-gray-500 text-xs text-center py-8">Not enough data to display a chart. Try selecting a shorter time range.</div>
  }
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="allowGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22c55e" stopOpacity={0.5} />
            <stop offset="100%" stopColor="#22c55e" stopOpacity={0.15} />
          </linearGradient>
          <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ef4444" stopOpacity={0.5} />
            <stop offset="100%" stopColor="#ef4444" stopOpacity={0.15} />
          </linearGradient>
          <linearGradient id="redirectGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.5} />
            <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.15} />
          </linearGradient>
        </defs>
        <XAxis dataKey="period" tickFormatter={(v) => formatXAxis(v, timeRange)}
               tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false}
               interval="preserveStartEnd" />
        <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} axisLine={false} tickLine={false} width={40}
               tickFormatter={v => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v} />
        <Tooltip content={<ActionTooltip timeRange={timeRange} />} />
        <Area type="monotone" dataKey="redirect" name="Redirect" stackId="1" stroke="#f59e0b" strokeWidth={1.5}
              fill="url(#redirectGrad)" dot={false} />
        <Area type="monotone" dataKey="block" name="Blocked" stackId="1" stroke="#ef4444" strokeWidth={1.5}
              fill="url(#blockGrad)" dot={false} />
        <Area type="monotone" dataKey="allow" name="Allowed" stackId="1" stroke="#22c55e" strokeWidth={1.5}
              fill="url(#allowGrad)" dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function formatTimeAgo(isoStr) {
  if (!isoStr) return null
  const diff = Date.now() - new Date(isoStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function TopList({ title, items, renderItem }) {
  return (
    <div className="border border-gray-800 rounded-lg p-4">
      <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">{title}</div>
      {items.length === 0 ? (
        <div className="text-gray-400 text-xs py-4 text-center">No data</div>
      ) : (
        <div className="space-y-2">
          {items.map((item, i) => renderItem(item, i))}
        </div>
      )}
    </div>
  )
}

export default function Dashboard({ maxFilterDays }) {
  const [timeRange, setTimeRange, visibleRanges] = useTimeRange(maxFilterDays)
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    setLoading(true)
    fetchStats(timeRange)
      .then(data => { if (mounted) setStats(data) })
      .catch(err => console.error('Failed to fetch stats:', err))
      .finally(() => { if (mounted) setLoading(false) })
    return () => { mounted = false }
  }, [timeRange])

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(() => {
      fetchStats(timeRange)
        .then(setStats)
        .catch(() => {})
    }, 30000)
    return () => clearInterval(interval)
  }, [timeRange])

  if (loading && !stats) {
    return <DashboardSkeleton />
  }

  if (!stats) return null

  const maxBlocked = stats.top_blocked_ips.length > 0
    ? Math.max(...stats.top_blocked_ips.map(i => i.count))
    : 0
  const maxBlockedInternal = (stats.top_blocked_internal_ips || []).length > 0
    ? Math.max(...stats.top_blocked_internal_ips.map(i => i.count))
    : 0
  const maxAllowedDest = (stats.top_allowed_destinations || []).length > 0
    ? Math.max(...stats.top_allowed_destinations.map(i => i.count))
    : 0
  const maxActiveInternal = (stats.top_active_internal_ips || []).length > 0
    ? Math.max(...stats.top_active_internal_ips.map(i => i.count))
    : 0

  return (
    <div className="pt-2.5 px-4 pb-4 space-y-4 overflow-auto max-h-full">
      {/* Time range selector */}
      <div className="flex items-center gap-1 flex-wrap">
        {visibleRanges.map(tr => (
          <button
            key={tr}
            onClick={() => setTimeRange(tr)}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
              timeRange === tr ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            {tr}
          </button>
        ))}
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Traffic Overview */}
        <div className="border border-gray-800 rounded-lg p-4">
          <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">Traffic Overview</div>
          <div className="flex items-baseline gap-2 mb-3">
            <span className="text-2xl font-semibold text-white">{formatNumber(stats.total)}</span>
            <span className="text-xs text-gray-500">total logs</span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 mb-3">
            <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold uppercase border ${ACTION_STYLES.allow}`}>
              Allowed {formatNumber(stats.allowed || 0)}
            </span>
            <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold uppercase border ${ACTION_STYLES.block}`}>
              Blocked {formatNumber(stats.blocked)}
            </span>
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold uppercase border bg-orange-500/15 text-orange-400 border-orange-500/30">
              Threats {formatNumber(stats.threats)}
            </span>
          </div>
          {Object.keys(stats.by_direction).length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 pt-3 border-t border-gray-800/50">
              {Object.entries(stats.by_direction).map(([dir, count]) => (
                <span key={dir} className={`inline-flex items-center gap-1 px-2 py-1 rounded bg-gray-800/50 text-xs font-medium ${DIRECTION_COLORS[dir] || 'text-gray-300'}`}>
                  <span>{DIRECTION_ICONS[dir]}</span>
                  <span className="uppercase">{dir === 'inter_vlan' ? 'VLAN' : dir}</span>
                  <span className="text-gray-400 font-semibold">{formatNumber(count)}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Log Types */}
        <div className="border border-gray-800 rounded-lg p-4">
          <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">Log Types</div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(stats.by_type).map(([t, c]) => (
              <span key={t} className={`inline-block px-2 py-1 rounded text-xs font-semibold uppercase border ${LOG_TYPE_STYLES[t] || LOG_TYPE_STYLES.system}`}>
                {t} {formatNumber(c)}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Logs over time chart */}
      <div className="border border-gray-800 rounded-lg p-4">
        <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">Traffic Over Time</div>
        <LogsOverTimeChart data={stats.logs_over_time || stats.logs_per_hour} timeRange={timeRange} loading={loading} />
      </div>

      {/* Traffic by action chart */}
      <div className="border border-gray-800 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-xs text-gray-400 uppercase tracking-wider">Traffic by Action</div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="flex items-center gap-1 text-xs text-green-400">
              <span className="w-2 h-2 rounded-full bg-green-500" /> Allowed
            </span>
            <span className="flex items-center gap-1 text-xs text-red-400">
              <span className="w-2 h-2 rounded-full bg-red-500" /> Blocked
            </span>
            <span className="flex items-center gap-1 text-xs text-amber-400">
              <span className="w-2 h-2 rounded-full bg-amber-500" /> Redirect
            </span>
          </div>
        </div>
        <TrafficByActionChart data={stats.traffic_by_action} timeRange={timeRange} loading={loading} />
      </div>

      {/* Top lists grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <TopList
          title="Top Threat IPs"
          items={stats.top_threat_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">
                  {item.ip}
                  {item.country && <span className="ml-1.5">{<FlagIcon code={item.country} />}</span>}
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 text-xs">{formatNumber(item.count)}×</span>
                  <span className={`font-medium ${getThreatLevel(item.threat_score)?.color ?? 'text-yellow-400'}`}>
                    {item.threat_score}%
                  </span>
                </div>
              </div>
              {(item.asn || item.city) && (
                <div className="text-xs text-gray-400 truncate">
                  {[item.asn, item.city].filter(Boolean).join(' · ')}
                </div>
              )}
              {item.rdns && (
                <div className="text-xs text-gray-400 truncate">{item.rdns}</div>
              )}
              <div className="flex items-center justify-between">
                {decodeThreatCategories(item.threat_categories) ? (
                  <div className="text-xs text-purple-400/70 truncate">
                    {decodeThreatCategories(item.threat_categories)}
                  </div>
                ) : <div />}
                {item.last_seen && (
                  <div className="text-xs text-gray-400 shrink-0">{formatTimeAgo(item.last_seen)}</div>
                )}
              </div>
            </div>
          )}
        />

        <TopList
          title="Top Blocked External IPs"
          items={stats.top_blocked_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">
                  {item.ip}
                  {item.country && <span className="ml-1.5">{<FlagIcon code={item.country} />}</span>}
                </span>
                <span className="text-gray-400">{formatNumber(item.count)}</span>
              </div>
              {item.asn && <div className="text-xs text-gray-400">{item.asn}</div>}
              <MiniBar data={item.count} maxVal={maxBlocked} color="bg-red-500/60" />
            </div>
          )}
        />

        <TopList
          title="Top Blocked Internal IPs"
          items={stats.top_blocked_internal_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <div className="min-w-0">
                  {item.device_name && (
                    <div className="flex items-center gap-1">
                      <span className="text-gray-200 text-[12px] truncate" title={item.device_name}>{item.device_name}</span>
                      <NetworkBadge vlan={item.vlan} size="sm" />
                    </div>
                  )}
                  <span className={item.device_name ? 'text-gray-500 text-[11px]' : 'text-gray-300'}>{item.ip}</span>
                </div>
                <span className="text-gray-400 shrink-0 ml-2">{formatNumber(item.count)}</span>
              </div>
              <MiniBar data={item.count} maxVal={maxBlockedInternal} color="bg-red-500/60" />
            </div>
          )}
        />

        <TopList
          title="Top Active Internal IPs"
          items={stats.top_active_internal_ips || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <div className="min-w-0">
                  {item.device_name && (
                    <div className="flex items-center gap-1">
                      <span className="text-gray-200 text-[12px] truncate" title={item.device_name}>{item.device_name}</span>
                      <NetworkBadge vlan={item.vlan} size="sm" />
                    </div>
                  )}
                  <span className={item.device_name ? 'text-gray-500 text-[11px]' : 'text-gray-300'}>{item.ip}</span>
                </div>
                <span className="text-gray-400 shrink-0 ml-2">{formatNumber(item.count)}</span>
              </div>
              <MiniBar data={item.count} maxVal={maxActiveInternal} color="bg-emerald-500/60" />
            </div>
          )}
        />

        <TopList
          title="Top Allowed Destinations"
          items={stats.top_allowed_destinations || []}
          renderItem={(item, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-300">
                  {item.ip}
                  {item.country && <span className="ml-1.5">{<FlagIcon code={item.country} />}</span>}
                </span>
                <span className="text-gray-400">{formatNumber(item.count)}</span>
              </div>
              {item.asn && <div className="text-xs text-gray-400">{item.asn}</div>}
              <MiniBar data={item.count} maxVal={maxAllowedDest} color="bg-green-500/60" />
            </div>
          )}
        />

        <div className="border border-gray-800 rounded-lg p-4">
          <div className="text-xs text-gray-400 uppercase tracking-wider mb-3">Top Countries</div>
          {(() => {
            const blocked = stats.top_blocked_countries || []
            const allowed = stats.top_allowed_countries || []
            if (blocked.length === 0 && allowed.length === 0) return <div className="text-gray-400 text-xs py-4 text-center">No data</div>
            return (
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/40">Blocked</span>
                  {blocked.slice(0, 10).map((item, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-gray-300 truncate mr-2 flex items-center gap-1.5">
                        <FlagIcon code={item.country} size={18} />
                        <span className="hidden sm:inline">{countryName(item.country)}</span>
                        <span className="sm:hidden">{item.country}</span>
                      </span>
                      <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/40 shrink-0">{formatNumber(item.count)}</span>
                    </div>
                  ))}
                  {blocked.length === 0 && <div className="text-gray-500 text-xs">—</div>}
                </div>
                <div className="space-y-2">
                  <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">Allowed</span>
                  {allowed.slice(0, 10).map((item, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-gray-300 truncate mr-2 flex items-center gap-1.5">
                        <FlagIcon code={item.country} size={18} />
                        <span className="hidden sm:inline">{countryName(item.country)}</span>
                        <span className="sm:hidden">{item.country}</span>
                      </span>
                      <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">{formatNumber(item.count)}</span>
                    </div>
                  ))}
                  {allowed.length === 0 && <div className="text-gray-500 text-xs">—</div>}
                </div>
              </div>
            )
          })()}
        </div>

        <TopList
          title="Top Blocked Services"
          items={stats.top_blocked_services || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300 truncate mr-2">{formatServiceName(item.service_name)}</span>
              <span className="text-gray-400 shrink-0">{formatNumber(item.count)}</span>
            </div>
          )}
        />

        <TopList
          title="Top Allowed Services"
          items={stats.top_allowed_services || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300 truncate mr-2">{formatServiceName(item.service_name)}</span>
              <span className="text-gray-400 shrink-0">{formatNumber(item.count)}</span>
            </div>
          )}
        />

        <TopList
          title="Top DNS Queries"
          items={stats.top_dns || []}
          renderItem={(item, i) => (
            <div key={i} className="flex items-center justify-between text-xs">
              <span className="text-gray-300 truncate mr-2">{item.dns_query}</span>
              <span className="text-gray-400 shrink-0">{formatNumber(item.count)}</span>
            </div>
          )}
        />
      </div>
    </div>
  )
}
