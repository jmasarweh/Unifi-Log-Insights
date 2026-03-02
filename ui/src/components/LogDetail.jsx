import React, { useState, useEffect } from 'react'
import { FlagIcon, getInterfaceName, decodeThreatCategories, isPrivateIP, formatServiceName } from '../utils'
import { fetchAbuseIPDBStatus, enrichIP } from '../api'
import CopyButton from './CopyButton'

const TEAL = 'text-teal-500 hover:text-teal-400'

function parseRuleName(ruleName) {
  if (!ruleName) return null
  // Format: CHAIN-ACTION_CODE-PRIORITY e.g. "WAN_LOCAL-D-2147483647"
  const m = ruleName.match(/^(.+?)-(A|D|R)-(\d+)$/)
  if (!m) return null
  const actionMap = { 'A': 'Allow', 'D': 'Drop', 'R': 'Redirect' }
  return {
    chain: m[1],
    action: actionMap[m[2]] || m[2],
    priority: m[3],
  }
}

export default function LogDetail({ log, hiddenColumns = new Set() }) {
  const [enriching, setEnriching] = useState(false)
  const [enrichError, setEnrichError] = useState(null)
  const [enrichedData, setEnrichedData] = useState(null)
  const [budget, setBudget] = useState(null)

  // Determine which IP to enrich — the remote party, not our infrastructure
  function getEnrichableIP() {
    if (!log) return null
    const srcPublic = log.src_ip && !isPrivateIP(log.src_ip)
    const dstPublic = log.dst_ip && !isPrivateIP(log.dst_ip)
    // For outbound/local traffic, the remote party is the destination
    if (log.direction === 'outbound' || log.direction === 'local') {
      return dstPublic ? log.dst_ip : srcPublic ? log.src_ip : null
    }
    return srcPublic ? log.src_ip : dstPublic ? log.dst_ip : null
  }
  const enrichableIP = getEnrichableIP()

  const canEnrich = log
    && log.log_type === 'firewall'
    && log.rule_action === 'block'
    && !log.abuse_usage_type
    && enrichableIP

  // Fetch budget status when enrich button would be shown
  useEffect(() => {
    if (!canEnrich) return
    fetchAbuseIPDBStatus()
      .then(s => setBudget(s.remaining))
      .catch(() => setBudget(null))
  }, [canEnrich])

  if (!log) return null

  // Merge enriched data into display log
  const displayLog = enrichedData ? { ...log, ...enrichedData } : log

  const handleEnrich = async () => {
    setEnriching(true)
    setEnrichError(null)
    try {
      const result = await enrichIP(enrichableIP)
      setEnrichedData({
        threat_score: result.threat_score,
        threat_categories: result.threat_categories,
        abuse_usage_type: result.abuse_usage_type,
        abuse_hostnames: result.abuse_hostnames,
        abuse_total_reports: result.abuse_total_reports,
        abuse_last_reported: result.abuse_last_reported,
        abuse_is_whitelisted: result.abuse_is_whitelisted,
        abuse_is_tor: result.abuse_is_tor,
      })
      setBudget(result.remaining_budget)
    } catch (err) {
      setEnrichError(err.message)
    } finally {
      setEnriching(false)
    }
  }

  const sections = []

  // Source IP / Destination IP (always shown for copyability)
  if (displayLog.src_ip) {
    sections.push(
      <div key="src_ip">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">Source IP</span>
        <div className="text-gray-300 text-sm mt-0.5 flex items-center">
          {displayLog.src_ip}
          {displayLog.src_port && <span className="text-gray-500">:{displayLog.src_port}</span>}
          <CopyButton text={displayLog.src_ip} color={TEAL} />
        </div>
        {displayLog.src_device_name && (
          <div className="text-gray-500 text-[12px] mt-0.5">{displayLog.src_device_name}</div>
        )}
      </div>
    )
  }
  if (displayLog.dst_ip) {
    sections.push(
      <div key="dst_ip">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">Destination IP</span>
        <div className="text-gray-300 text-sm mt-0.5 flex items-center">
          {displayLog.dst_ip}
          {displayLog.dst_port && <span className="text-gray-500">:{displayLog.dst_port}</span>}
          <CopyButton text={displayLog.dst_ip} color={TEAL} />
        </div>
        {displayLog.dst_device_name && (
          <div className="text-gray-500 text-[12px] mt-0.5">{displayLog.dst_device_name}</div>
        )}
      </div>
    )
  }

  // rDNS (prominent)
  if (displayLog.rdns) {
    sections.push(
      <div key="rdns" className="col-span-full">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">Reverse DNS</span>
        <div className="text-gray-200 text-sm mt-0.5">{displayLog.rdns}</div>
      </div>
    )
  }

  // GeoIP (hidden when country column is hidden)
  if (displayLog.geo_country && !hiddenColumns.has('country')) {
    const geoText = [displayLog.geo_country, displayLog.geo_city].filter(Boolean).join(' · ')

    sections.push(
      <div key="geo">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">GeoIP</span>
        <div className="text-gray-300 text-sm mt-0.5 flex items-center gap-1.5">
          <FlagIcon code={displayLog.geo_country} />
          {geoText}
        </div>
        {displayLog.geo_lat != null && displayLog.geo_lon != null && (
          <div className="text-gray-500 text-[12px] mt-0.5 flex items-center gap-2">
            <span>{displayLog.geo_lat.toFixed(4)}, {displayLog.geo_lon.toFixed(4)}</span>
            <button
              onClick={() => window.dispatchEvent(new CustomEvent('viewOnMap', {
                detail: {
                  lat: displayLog.geo_lat,
                  lon: displayLog.geo_lon,
                  src_ip: displayLog.src_ip,
                  dst_ip: displayLog.dst_ip,
                  src_port: displayLog.src_port,
                  dst_port: displayLog.dst_port,
                  src_device: displayLog.src_device_name,
                  dst_device: displayLog.dst_device_name,
                  direction: displayLog.direction,
                  timestamp: displayLog.timestamp,
                  threat_score: displayLog.threat_score,
                  country: displayLog.geo_country,
                  city: displayLog.geo_city,
                  service: displayLog.service_name,
                }
              }))}
              className="text-teal-500 hover:text-teal-400 text-[11px] underline"
            >
              View on map
            </button>
          </div>
        )}
      </div>
    )
  }

  // ASN (hidden when ASN column is hidden)
  if (displayLog.asn_name && !hiddenColumns.has('asn')) {
    sections.push(
      <div key="asn">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">ASN</span>
        <div className="text-gray-300 text-sm mt-0.5">
          {displayLog.asn_name}
          {displayLog.asn_number && <span className="text-gray-500 ml-1.5">AS{displayLog.asn_number}</span>}
        </div>
      </div>
    )
  }

  // Protocol (always shown when available)
  if (displayLog.protocol) {
    sections.push(
      <div key="proto">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">Protocol</span>
        <div className="text-gray-300 text-sm mt-0.5 uppercase">{displayLog.protocol}</div>
      </div>
    )
  }

  // Service (shown for non-firewall; firewall has its own detailed service section below)
  if (displayLog.service_name && displayLog.log_type !== 'firewall') {
    sections.push(
      <div key="service_general">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">Service</span>
        <div className="text-gray-300 text-sm mt-0.5">{formatServiceName(displayLog.service_name)}</div>
      </div>
    )
  }

  // Firewall details
  if (displayLog.log_type === 'firewall') {
    // Parsed rule breakdown (hidden when rule column is hidden)
    if (!hiddenColumns.has('rule')) {
      const parsed = parseRuleName(displayLog.rule_name)
      if (parsed) {
        sections.push(
          <div key="rule_parsed">
            <span className="text-gray-400 text-[12px] uppercase tracking-wider">Rule Details</span>
            <div className="text-gray-300 text-sm mt-0.5">
              <span className="text-gray-300">Chain:</span> {parsed.chain}
              <span className="text-gray-500 mx-2">·</span>
              <span className="text-gray-300">Action:</span> {parsed.action}
              <span className="text-gray-500 mx-2">·</span>
              <span className="text-gray-300">Priority:</span> {parsed.priority}
            </div>
          </div>
        )
      }

      // Rule description
      if (displayLog.rule_desc) {
        const desc = displayLog.rule_desc.replace(/\](?!\s)/, '] ')
        sections.push(
          <div key="rule_desc">
            <span className="text-gray-400 text-[12px] uppercase tracking-wider">Rule Description</span>
            <div className="text-gray-300 text-sm mt-0.5">{desc}</div>
          </div>
        )
      }
    }

    // Service name + description
    if (displayLog.service_name) {
      sections.push(
        <div key="service">
          <span className="text-gray-400 text-[12px] uppercase tracking-wider">Service</span>
          <div className="text-gray-300 text-sm mt-0.5">
            {formatServiceName(displayLog.service_name)}
            {displayLog.dst_port && (
              <span className="text-gray-400"> (port {displayLog.dst_port})</span>
            )}
          </div>
          {displayLog.service_description && (
            <div className="text-gray-400 text-xs mt-0.5">{displayLog.service_description}</div>
          )}
        </div>
      )
    }

    const netDetails = [
      displayLog.interface_in && `IN: ${getInterfaceName(displayLog.interface_in)}`,
      displayLog.interface_out && `OUT: ${getInterfaceName(displayLog.interface_out)}`,
      displayLog.mac_address && `MAC: ${displayLog.mac_address}`,
    ].filter(Boolean)
    if (netDetails.length) {
      sections.push(
        <div key="net">
          <span className="text-gray-400 text-[12px] uppercase tracking-wider">Network</span>
          <div className="text-gray-300 text-sm mt-0.5">{netDetails.join(' · ')}</div>
        </div>
      )
    }
  }

  // DHCP details
  if (displayLog.log_type === 'dhcp') {
    const dhcpDetails = [
      displayLog.hostname && `Host: ${displayLog.hostname}`,
      displayLog.mac_address && `MAC: ${displayLog.mac_address}`,
    ].filter(Boolean)
    if (dhcpDetails.length) {
      sections.push(
        <div key="dhcp">
          <span className="text-gray-400 text-[12px] uppercase tracking-wider">DHCP</span>
          <div className="text-gray-300 text-sm mt-0.5">{dhcpDetails.join(' · ')}</div>
        </div>
      )
    }
  }

  // WiFi details
  if (displayLog.log_type === 'wifi') {
    const wifiDetails = [
      displayLog.wifi_event && `Event: ${displayLog.wifi_event}`,
      displayLog.mac_address && `MAC: ${displayLog.mac_address}`,
    ].filter(Boolean)
    if (wifiDetails.length) {
      sections.push(
        <div key="wifi">
          <span className="text-gray-400 text-[12px] uppercase tracking-wider">WiFi</span>
          <div className="text-gray-300 text-sm mt-0.5">{wifiDetails.join(' · ')}</div>
        </div>
      )
    }
  }

  // AbuseIPDB Detail Fields (hidden when both threat and categories columns are hidden)
  const showAbuse = !hiddenColumns.has('threat') || !hiddenColumns.has('categories')
  const abuseDetails = []

  if (showAbuse && displayLog.threat_score !== null && displayLog.threat_score !== undefined) {
    const score = displayLog.threat_score
    let color = 'text-emerald-400'
    let label = 'Clean'
    if (score >= 75) { color = 'text-red-400'; label = 'Critical' }
    else if (score >= 50) { color = 'text-orange-400'; label = 'High' }
    else if (score >= 25) { color = 'text-yellow-400'; label = 'Medium' }
    else if (score > 0) { color = 'text-blue-400'; label = 'Low' }

    abuseDetails.push(
      <div key="abuse_score">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Score</span>
        <div className={`text-sm mt-0.5 ${color} font-medium`}>
          {score}% · {label}
        </div>
        {!hiddenColumns.has('categories') && decodeThreatCategories(displayLog.threat_categories) && (
          <div className="text-[11px] text-purple-400/70 mt-0.5">
            {decodeThreatCategories(displayLog.threat_categories)}
          </div>
        )}
      </div>
    )
  }

  if (showAbuse && displayLog.abuse_usage_type) {
    abuseDetails.push(
      <div key="abuse_usage">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Usage Type</span>
        <div className="text-gray-300 text-sm mt-0.5">{displayLog.abuse_usage_type}</div>
      </div>
    )
  }

  if (showAbuse && displayLog.abuse_hostnames) {
    abuseDetails.push(
      <div key="abuse_hosts">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Host Names</span>
        <div className="text-gray-300 text-sm mt-0.5 flex items-center">
          {displayLog.abuse_hostnames}
          <CopyButton text={displayLog.abuse_hostnames} color={TEAL} />
        </div>
      </div>
    )
  }

  if (showAbuse && displayLog.abuse_total_reports != null && displayLog.abuse_total_reports > 0) {
    abuseDetails.push(
      <div key="abuse_reports">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Reports #</span>
        <div className="text-gray-300 text-sm mt-0.5">{displayLog.abuse_total_reports.toLocaleString()}</div>
      </div>
    )
  }

  if (showAbuse && displayLog.abuse_last_reported) {
    const d = new Date(displayLog.abuse_last_reported)
    const formatted = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
    abuseDetails.push(
      <div key="abuse_last">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Last Reported</span>
        <div className="text-gray-300 text-sm mt-0.5">{formatted}</div>
      </div>
    )
  }

  if (showAbuse && displayLog.abuse_is_whitelisted) {
    abuseDetails.push(
      <div key="abuse_wl">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Whitelisted</span>
        <div className="text-emerald-400 text-sm mt-0.5">✓</div>
      </div>
    )
  }

  if (showAbuse && displayLog.abuse_is_tor) {
    abuseDetails.push(
      <div key="abuse_tor">
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB Tor</span>
        <div className="text-orange-400 text-sm mt-0.5">✓</div>
      </div>
    )
  }

  // Enrich button — shown when abuse data is missing for a blocked firewall log
  const showEnrichButton = showAbuse && canEnrich && !enrichedData

  return (
    <div className="bg-gray-950/80 px-4 py-3 max-h-[60vh] sm:max-h-none overflow-y-auto">
      {sections.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 mb-3">
          {sections}
        </div>
      )}
      {(abuseDetails.length > 0 || showEnrichButton) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 mb-3 pt-2 border-t border-gray-800/50">
          {abuseDetails}
          {showEnrichButton && (
            <div key="enrich_btn">
              <span className="text-gray-400 text-[12px] uppercase tracking-wider">AbuseIPDB</span>
              <div className="mt-1">
                <button
                  onClick={handleEnrich}
                  disabled={enriching || budget === 0}
                  className="px-2.5 py-1 text-[12px] rounded border border-gray-700 text-gray-300 hover:text-gray-200 hover:border-gray-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  title={budget === 0 ? 'No API budget' : `Look up ${enrichableIP} on AbuseIPDB`}
                >
                  {enriching ? 'Looking up...' : `Enrich ${enrichableIP}`}
                </button>
                {budget !== null && (
                  <span className="text-gray-500 text-[11px] ml-2">{budget} remaining</span>
                )}
                {enrichError && (
                  <div className="text-red-400 text-[11px] mt-1">{enrichError}</div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
      {/* Raw log */}
      <div>
        <span className="text-gray-400 text-[12px] uppercase tracking-wider">Raw Log</span>
        <pre className="text-[12px] text-gray-100 mt-1 whitespace-pre-wrap break-all leading-relaxed bg-gray-950 rounded p-2 border border-gray-800">
          {displayLog.raw_log}
        </pre>
      </div>
      {/* Log ID */}
      {displayLog.id != null && (
        <div className="flex items-center justify-end gap-1 mt-2">
          <span className="text-gray-500 text-[11px] font-mono font-bold">LOG ID: {displayLog.id}</span>
          <CopyButton text={String(displayLog.id)} color={TEAL} />
        </div>
      )}
    </div>
  )
}
