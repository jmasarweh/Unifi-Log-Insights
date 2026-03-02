/**
 * Build query params matching TopIPPairs' filter logic and trigger
 * a CSV download from /api/stats/ip-pairs/csv.
 *
 * @param {object} filters - Base FlowView filters (time_range, rule_action, direction, etc.)
 * @param {object|null} sankeyFilter - Cross-filter from Sankey node click
 * @param {object|null} zoneFilter - Cross-filter from Zone Matrix cell click
 */

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

export async function exportCsv(filters, sankeyFilter, zoneFilter) {
  const params = new URLSearchParams()

  for (const [k, v] of Object.entries(filters)) {
    if (v !== null && v !== undefined && v !== '') params.set(k, v)
  }

  if (sankeyFilter) {
    const paramKey = SANKEY_PARAM_MAP[sankeyFilter.type] || sankeyFilter.type
    params.set(paramKey, sankeyFilter.value)
  }
  if (zoneFilter) {
    params.set('interface_in', zoneFilter.interface_in)
    params.set('interface_out', zoneFilter.interface_out)
  }

  const url = `/api/stats/ip-pairs/csv?${params.toString()}`

  try {
    const resp = await fetch(url)
    if (!resp.ok) throw new Error(`CSV export failed: ${resp.status}`)
    const blob = await resp.blob()
    const blobUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = blobUrl
    a.download = `ip_pairs_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(blobUrl)
  } catch (err) {
    console.error('CSV export failed:', err)
    throw err
  }
}
