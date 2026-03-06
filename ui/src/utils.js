// Country flag SVG icon (works on all platforms including Windows)
import React from 'react'

const _regionNames = new Intl.DisplayNames(['en'], { type: 'region' })
export function countryName(code) {
  if (!code) return ''
  try { return _regionNames.of(code.toUpperCase()) || code } catch { return code }
}

export function FlagIcon({ code, size = 14 }) {
  if (!code) return null
  return React.createElement('span', {
    className: `fi fi-${code.toLowerCase()}`,
    style: { fontSize: `${size}px`, lineHeight: 1 },
    title: countryName(code),
  })
}

export function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatDateTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' +
    d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatNumber(n) {
  if (n === null || n === undefined) return '—'
  return n.toLocaleString()
}

export function formatServiceName(name) {
  if (!name) return '—'
  if (name === 'Unknown' || name === 'unknown') return 'Unknown'
  return name.toUpperCase()
}

export function normalizeRuleDesc(desc) {
  if (!desc) return null
  return desc.replace(/\](?!\s)/g, '] ')
}

export function isPrivateIP(ip) {
  if (!ip) return true
  // IPv6 private/reserved ranges
  if (ip.includes(':')) {
    const lower = ip.toLowerCase()
    if (lower === '::1' || lower === '::') return true          // loopback / unspecified
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true  // ULA (fc00::/7)
    if (lower.startsWith('fe80')) return true                   // link-local
    if (lower.startsWith('ff')) return true                     // multicast
    return false
  }
  // IPv4 private ranges
  if (ip.startsWith('10.') || ip.startsWith('192.168.') ||
      ip.startsWith('127.') || ip.startsWith('169.254.')) return true
  // RFC1918 172.16.0.0/12 = 172.16.x.x – 172.31.x.x
  const m = ip.match(/^172\.(\d+)\./)
  if (m) {
    const second = Number.parseInt(m[1], 10)
    if (second >= 16 && second <= 31) return true
  }
  return false
}

/**
 * Resolve ASN/abuse subline for source and destination IPs.
 * ASN belongs to the enriched (remote) IP: inbound → source, otherwise → destination.
 * Returns { srcSubline, dstSubline }.
 */
export function resolveIpSublines({ asn_name, abuse_hostnames, direction, src_ip, dst_ip }) {
  const text = asn_name || abuse_hostnames || null
  if (!text) return { srcSubline: null, dstSubline: null }
  return {
    srcSubline: direction === 'inbound' && !isPrivateIP(src_ip) ? text : null,
    dstSubline: direction !== 'inbound' && dst_ip && !isPrivateIP(dst_ip) ? text : null,
  }
}

export const LOG_TYPE_STYLES = {
  firewall: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  dns: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  dhcp: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  wifi: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  ids: 'bg-red-500/15 text-red-400 border-red-500/30',
  system: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
}

export const ACTION_STYLES = {
  block: 'bg-red-500/20 text-red-400 border-red-500/40',
  allow: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  redirect: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  DHCPACK: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  DHCPDISCOVER: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  DHCPREQUEST: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  DHCPOFFER: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  associated: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  disassociated: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
}

export const DIRECTION_ICONS = {
  inbound: '↓',
  outbound: '↑',
  inter_vlan: '⇔',
  nat: '⤴\uFE0E',
  local: '⟳',
  vpn: '⛨',
}

// Interface name validation: letters then digits, with optional + for sfp+0 and optional .N VLAN tag (e.g., ppp0, eth4, eth4.10, sfp+0, enp3s0)
const IFACE_REGEX = /^[a-z][a-z0-9+]*\d+(\.\d+)?$/

// Returns an error string if the interface name is invalid, or null if valid.
export function validateInterfaceName(iface) {
  if (!IFACE_REGEX.test(iface))
    return 'Interface name must start with letters followed by a number, with optional VLAN tag (e.g., ppp0, eth4, eth4.10, sfp+0).'
  const dot = iface.indexOf('.')
  if (dot !== -1) {
    const id = Number.parseInt(iface.slice(dot + 1), 10)
    if (id < 1 || id > 4094) return 'VLAN ID must be between 1 and 4094.'
  }
  return null
}

// Module-level variables (populated on app load via loadInterfaceLabels)
let INTERFACE_LABELS = {}
let WAN_INTERFACES = new Set()

// Deterministic color palette keyed by raw interface name, not label.
// WAN interfaces always get red; bridge interfaces use a fixed map.
const BRIDGE_COLOR_MAP = {
  0:  'text-blue-400',
  10: 'text-blue-400',
  20: 'text-amber-400',
  30: 'text-purple-400',
  40: 'text-teal-400',
  50: 'text-pink-400',
  60: 'text-orange-400',
  70: 'text-lime-400',
  80: 'text-cyan-400',
  90: 'text-indigo-400',
  100: 'text-rose-400',
}

export async function loadInterfaceLabels(prefetchedConfig) {
  try {
    const config = prefetchedConfig || await (await fetch('/api/config')).json()
    INTERFACE_LABELS = config.interface_labels || {}
    WAN_INTERFACES = new Set(config.wan_interfaces || [])
  } catch (err) {
    console.warn('Failed to load interface labels, using raw names:', err)
    INTERFACE_LABELS = {}
    WAN_INTERFACES = new Set()
  }
}

export function getInterfaceName(iface) {
  if (!iface) return '—'
  return INTERFACE_LABELS[iface] || iface
}

export function getInterfaceColor(iface) {
  if (!iface) return 'text-gray-300'

  // WAN interfaces → always red
  if (WAN_INTERFACES.has(iface)) return 'text-red-400'

  // Bridge interfaces → fixed color per VLAN number
  if (iface.startsWith('br')) {
    const num = parseInt(iface.slice(2), 10)
    if (isNaN(num)) return 'text-gray-300'
    return BRIDGE_COLOR_MAP[num] || 'text-gray-300'
  }

  // VLAN interfaces
  if (iface.startsWith('vlan')) return 'text-indigo-400'

  // Ethernet interfaces
  if (iface.startsWith('eth')) return 'text-gray-300'

  return 'text-gray-300'
}

export const DIRECTION_COLORS = {
  inbound: 'text-red-400',
  outbound: 'text-blue-400',
  inter_vlan: 'text-gray-300',
  nat: 'text-yellow-400',
  local: 'text-gray-400',
  vpn: 'text-teal-400',
}

// sessionStorage key for persisting time range across views
export const TR_KEY = 'unifi-log-insight:time-range'

// Convert time range string (e.g. '7d', '24h') to days
export function timeRangeToDays(value) {
  if (!value) return 0
  const match = value.match(/^(\d+)([hd])$/)
  if (!match) return 0
  const num = parseInt(match[1], 10)
  return match[2] === 'h' ? num / 24 : num
}

// Filter time ranges to those within maxFilterDays (progressive unlock).
// Always includes one "ceiling" range beyond the data span so users can
// view their full dataset even when it falls between two range steps.
export function filterVisibleRanges(ranges, maxFilterDays, getValue = v => v) {
  if (!maxFilterDays) return ranges
  let ceilingIncluded = false
  return ranges.filter((tr) => {
    const days = timeRangeToDays(getValue(tr))
    if (days < 1 || days <= maxFilterDays) return true
    if (!ceilingIncluded) { ceilingIncluded = true; return true }
    return false
  })
}

// AbuseIPDB category code → human-readable label
const ABUSE_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
}

export function decodeThreatCategories(cats) {
  if (!cats || cats.length === 0) return null
  return cats.map(c => {
    if (c === 'blacklist') return 'Blacklist'
    return ABUSE_CATEGORIES[parseInt(c)] || `Cat ${c}`
  }).join(', ')
}
