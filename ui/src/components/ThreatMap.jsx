import { useState, useEffect, useRef, useCallback } from 'react'
import maplibregl from 'maplibre-gl'
import maplibreWorkerUrl from 'maplibre-gl/dist/maplibre-gl-csp-worker?url'
import 'maplibre-gl/dist/maplibre-gl.css'
import { fetchThreatGeo } from '../api'
import { formatNumber } from '../utils'
import { THREAT_LEVELS } from '../lib/threatPresentation'
import useTimeRange from '../hooks/useTimeRange'
import ThreatSidebar from './ThreatSidebar'

maplibregl.setWorkerUrl(maplibreWorkerUrl)

const MODES = [
  { id: 'threats', label: 'Threats' },
  { id: 'blocked_outbound', label: 'Blocked Outbound' },
]

const VIEWS = [
  { id: 'heatmap', label: 'Heatmap' },
  { id: 'clusters', label: 'Clusters' },
]

// CARTO dark/light basemaps (free, no API key)
const TILE_DARK = 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json'
const TILE_LIGHT = 'https://basemaps.cartocdn.com/gl/positron-gl-style/style.json'

const ALL_LAYERS = ['threat-heat', 'heat-points', 'threat-clusters', 'cluster-count', 'unclustered-point']

// Build MapLibre 'step' expression from THREAT_LEVELS for score-based coloring.
// Produces: ['step', expr, color0, min1, color1, min2, color2, ...]
// THREAT_LEVELS is sorted descending by min; 'step' needs ascending thresholds.
const SCORE_STEP = (() => {
  const asc = [...THREAT_LEVELS].reverse()
  const expr = ['step', ['get', 'max_score'], asc[0].hex]
  for (let i = 1; i < asc.length; i++) expr.push(asc[i].min, asc[i].hex)
  return expr
})()

// Same but using 'interpolate' for smooth gradient (heatmap points)
const SCORE_INTERPOLATE = (() => {
  const asc = [...THREAT_LEVELS].reverse()
  const expr = ['interpolate', ['linear'], ['get', 'max_score']]
  for (const t of asc) expr.push(t.min, t.hex)
  return expr
})()

function getTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark'
}

/** Create a DOM element with className and textContent */
function el(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text != null) node.textContent = text
  return node
}

/** Remove all threat layers + source from the map.
 *  Hides layers before removal to flush the GPU heatmap framebuffer,
 *  preventing the heat texture from lingering during view switches. */
function cleanupLayers(map) {
  ALL_LAYERS.forEach(id => {
    try {
      if (map.getLayer(id)) {
        map.setLayoutProperty(id, 'visibility', 'none')
        map.removeLayer(id)
      }
    } catch (_) { /* noop */ }
  })
  try { if (map.getSource('threats')) map.removeSource('threats') } catch (_) { /* noop */ }
  map.triggerRepaint()
}

/** Apply heatmap or cluster layers to the map (with auto-retry on failure) */
function applyLayers(map, geoData, view, _retry) {
  try {
    cleanupLayers(map)

    if (!geoData?.features?.length) return

    if (view === 'heatmap') {
      map.addSource('threats', { type: 'geojson', data: geoData })

      // Native heatmap layer (official MapLibre approach)
      map.addLayer({
        id: 'threat-heat',
        type: 'heatmap',
        source: 'threats',
        paint: {
          'heatmap-weight': ['interpolate', ['linear'], ['get', 'count'],
            1, 0.3, 10, 0.6, 50, 0.9, 200, 1,
          ],
          'heatmap-intensity': ['interpolate', ['linear'], ['zoom'],
            0, 1, 4, 1.5, 9, 2.5,
          ],
          // Warm-only ramp — avoids blue which conflicts with threat score legend
          'heatmap-color': [
            'interpolate', ['linear'], ['heatmap-density'],
            0,   'rgba(0,0,0,0)',
            0.05, 'rgba(250,204,21,0.2)',
            0.2, 'rgb(250,204,21)',
            0.4, 'rgb(245,158,11)',
            0.6, 'rgb(239,68,68)',
            0.8, 'rgb(220,38,38)',
            1,   'rgb(153,27,27)',
          ],
          'heatmap-radius': ['interpolate', ['linear'], ['zoom'],
            0, 15, 3, 25, 6, 35, 9, 45,
          ],
          // Stay visible at all zoom levels
          'heatmap-opacity': ['interpolate', ['linear'], ['zoom'],
            0, 0.9, 9, 0.7,
          ],
        },
      })

      // Individual points visible at higher zoom
      map.addLayer({
        id: 'heat-points',
        type: 'circle',
        source: 'threats',
        minzoom: 6,
        paint: {
          'circle-radius': ['interpolate', ['linear'], ['get', 'count'],
            1, 4, 10, 7, 50, 11, 200, 16,
          ],
          'circle-color': SCORE_INTERPOLATE,
          'circle-opacity': ['interpolate', ['linear'], ['zoom'],
            6, 0, 8, 0.8,
          ],
          'circle-stroke-width': 1,
          'circle-stroke-color': 'rgba(255,255,255,0.3)',
        },
      })
    } else {
      map.addSource('threats', {
        type: 'geojson',
        data: geoData,
        cluster: true,
        clusterMaxZoom: 14,
        clusterRadius: 50,
        clusterProperties: {
          sum_count: ['+', ['get', 'count']],
          max_score: ['max', ['get', 'max_score']],
        },
      })

      // Cluster circles
      map.addLayer({
        id: 'threat-clusters',
        type: 'circle',
        source: 'threats',
        filter: ['has', 'point_count'],
        paint: {
          'circle-color': SCORE_STEP,
          'circle-radius': ['step', ['get', 'sum_count'], 18, 10, 24, 50, 32, 200, 42],
          'circle-opacity': 0.85,
          'circle-stroke-width': 2,
          'circle-stroke-color': 'rgba(255,255,255,0.3)',
        },
      })

      // Cluster count labels
      map.addLayer({
        id: 'cluster-count',
        type: 'symbol',
        source: 'threats',
        filter: ['has', 'point_count'],
        layout: {
          'text-field': ['number-format', ['get', 'sum_count'], { 'min-fraction-digits': 0 }],
          'text-size': 12,
          'text-font': ['Open Sans Bold'],
        },
        paint: { 'text-color': '#ffffff' },
      })

      // Unclustered points
      map.addLayer({
        id: 'unclustered-point',
        type: 'circle',
        source: 'threats',
        filter: ['!', ['has', 'point_count']],
        paint: {
          'circle-color': SCORE_STEP,
          'circle-radius': ['interpolate', ['linear'], ['get', 'count'], 1, 6, 50, 12, 200, 18],
          'circle-opacity': 0.85,
          'circle-stroke-width': 1,
          'circle-stroke-color': 'rgba(255,255,255,0.4)',
        },
      })

    }
  } catch (_err) {
    if (!_retry) {
      map.once('idle', () => applyLayers(map, geoData, view, true))
    }
  }
}

export function ThreatMapSkeleton() {
  return (
    <div className="h-full flex flex-col animate-pulse">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800">
        <div className="h-7 w-10 bg-gray-800 rounded" />
        <div className="h-7 w-10 bg-gray-800 rounded" />
        <div className="h-7 w-10 bg-gray-800 rounded" />
      </div>
      <div className="flex-1 bg-black" />
    </div>
  )
}

export default function ThreatMap({ maxFilterDays, flyTo, onFlyToDone }) {
  const mapContainer = useRef(null)
  const mapRef = useRef(null)
  const flyToMarkerRef = useRef(null)
  const [timeRange, setTimeRange, visibleRanges] = useTimeRange(maxFilterDays)
  const [mode, setMode] = useState('threats')
  const [view, setView] = useState('heatmap')
  const [filtersExpanded, setFiltersExpanded] = useState(false)
  const [geoData, setGeoData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [sidebarLocation, setSidebarLocation] = useState(null)
  const [hasFlyToMarker, setHasFlyToMarker] = useState(false)

  const closeSidebar = useCallback(() => setSidebarLocation(null), [])

  // Keep refs in sync so applyLayers always has latest values
  const viewRef = useRef(view)
  const geoDataRef = useRef(geoData)
  viewRef.current = view
  geoDataRef.current = geoData

  // Fetch geo data
  useEffect(() => {
    let mounted = true
    setLoading(true)
    setSidebarLocation(null)
    fetchThreatGeo({ time_range: timeRange, mode })
      .then(data => { if (mounted) setGeoData(data) })
      .catch(() => {})
      .finally(() => { if (mounted) setLoading(false) })
    return () => { mounted = false }
  }, [timeRange, mode])

  // Auto-refresh every 60s
  useEffect(() => {
    let mounted = true
    const interval = setInterval(() => {
      fetchThreatGeo({ time_range: timeRange, mode })
        .then(data => { if (mounted) setGeoData(data) })
        .catch(() => {})
    }, 60000)
    return () => { mounted = false; clearInterval(interval) }
  }, [timeRange, mode])

  // Initialize map
  useEffect(() => {
    if (!mapContainer.current || mapRef.current) return

    const map = new maplibregl.Map({
      container: mapContainer.current,
      style: getTheme() === 'dark' ? TILE_DARK : TILE_LIGHT,
      center: [20, 20],
      zoom: 1.5,
      attributionControl: false,
    })

    map.addControl(new maplibregl.NavigationControl(), 'top-right')
    map.addControl(new maplibregl.AttributionControl({ compact: true }), 'bottom-right')

    // Register interaction handlers once (layers are added/removed but names stay stable)
    const clusterPopup = new maplibregl.Popup({ closeButton: false, closeOnClick: false, className: 'threat-popup' })

    map.on('click', 'threat-clusters', (e) => {
      const features = map.queryRenderedFeatures(e.point, { layers: ['threat-clusters'] })
      if (!features.length) return
      const source = map.getSource('threats')
      if (!source) return
      const clusterId = features[0].properties.cluster_id
      source.getClusterExpansionZoom(clusterId, (err, zoom) => {
        if (err || !map.getSource('threats')) return
        map.easeTo({ center: features[0].geometry.coordinates, zoom })
      })
    })

    map.on('click', 'unclustered-point', (e) => {
      if (!e.features?.length) return
      clusterPopup.remove()
      const f = e.features[0]
      const p = f.properties
      let logIds = p.log_ids || []
      if (typeof logIds === 'string') {
        try { logIds = JSON.parse(logIds) } catch (_) { logIds = [] }
      }
      setSidebarLocation({
        city: p.city || '',
        country: p.country || '',
        count: p.count,
        uniqueIps: p.unique_ips,
        maxScore: p.max_score,
        logIds,
      })
    })

    map.on('mouseenter', 'unclustered-point', (e) => {
      if (!e.features?.length) return
      map.getCanvas().style.cursor = 'pointer'
      const f = e.features[0]
      const p = f.properties
      const coords = f.geometry.coordinates.slice()
      const container = el('div', 'text-xs')
      const header = el('div', 'flex items-center justify-between gap-2')
      header.appendChild(el('span', 'font-medium', [p.city, p.country].filter(Boolean).join(', ')))
      // Small "open details" icon hint
      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
      icon.setAttribute('viewBox', '0 0 20 20')
      icon.setAttribute('fill', 'currentColor')
      icon.setAttribute('class', 'w-3 h-3 opacity-40 shrink-0')
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
      path.setAttribute('fill-rule', 'evenodd')
      path.setAttribute('d', 'M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v5.69a.75.75 0 001.5 0v-7.5a.75.75 0 00-.75-.75h-7.5a.75.75 0 000 1.5h5.69l-7.22 7.22a.75.75 0 000 1.06z')
      path.setAttribute('clip-rule', 'evenodd')
      icon.appendChild(path)
      header.appendChild(icon)
      container.appendChild(header)
      container.appendChild(el('div', null, `${p.count} events · Score: ${p.max_score}`))
      container.appendChild(el('div', null, `${p.unique_ips} unique IPs`))
      container.appendChild(el('div', 'opacity-40 mt-0.5', 'Click for details'))
      clusterPopup.setLngLat(coords).setDOMContent(container).addTo(map)
    })

    map.on('mouseleave', 'unclustered-point', () => {
      map.getCanvas().style.cursor = ''
      clusterPopup.remove()
    })

    map.on('mouseenter', 'threat-clusters', () => { map.getCanvas().style.cursor = 'pointer' })
    map.on('mouseleave', 'threat-clusters', () => { map.getCanvas().style.cursor = '' })

    // Apply layers once map is fully loaded, and re-apply after theme changes
    map.on('load', () => {
      const data = geoDataRef.current
      const v = viewRef.current
      if (data) applyLayers(map, data, v)
    })

    map.on('style.load', () => {
      const data = geoDataRef.current
      const v = viewRef.current
      if (data) applyLayers(map, data, v)
    })

    mapRef.current = map

    return () => {
      mapRef.current = null
      map.remove()
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Re-apply layers when geoData or view changes
  useEffect(() => {
    const map = mapRef.current
    if (!map || !geoData) return

    // If style isn't ready yet, wait for idle then apply
    if (!map.isStyleLoaded()) {
      const handler = () => applyLayers(map, geoDataRef.current, viewRef.current)
      map.once('idle', handler)
      return () => map.off('idle', handler)
    }

    applyLayers(map, geoData, view)
  }, [geoData, view])

  // Fly to coordinates when triggered from LogDetail — with a marker pin
  useEffect(() => {
    if (!flyTo || !mapRef.current) return
    const map = mapRef.current

    // Switch to clusters so the marker isn't obscured by the heatmap
    if (viewRef.current === 'heatmap') setView('clusters')

    // Remove previous flyTo marker
    if (flyToMarkerRef.current) {
      flyToMarkerRef.current.remove()
      flyToMarkerRef.current = null
      setHasFlyToMarker(false)
    }

    // Create pulsing marker element
    const markerEl = document.createElement('div')
    markerEl.className = 'flyto-marker'

    // Build popup DOM from log details (safe — no innerHTML)
    const loc = [flyTo.city, flyTo.country].filter(Boolean).join(', ') || `${flyTo.lat.toFixed(4)}, ${flyTo.lon.toFixed(4)}`
    const ts = flyTo.timestamp ? new Date(flyTo.timestamp).toLocaleString() : ''
    const src = [flyTo.src_ip, flyTo.src_port].filter(Boolean).join(':')
    const dst = [flyTo.dst_ip, flyTo.dst_port].filter(Boolean).join(':')
    const srcLabel = flyTo.src_device || src
    const dstLabel = flyTo.dst_device || dst
    const dir = flyTo.direction || ''
    const score = flyTo.threat_score

    const popupRoot = el('div', 'text-xs')
    popupRoot.style.minWidth = '180px'
    popupRoot.appendChild(el('div', 'font-semibold text-sm mb-1', loc))
    if (ts) popupRoot.appendChild(el('div', 'opacity-60 mb-1.5', ts))

    const addRow = (label, value) => {
      const row = el('div', 'flex items-center gap-1 mb-0.5')
      row.appendChild(el('span', 'opacity-50 w-10', label))
      row.appendChild(el('span', 'font-mono', value))
      popupRoot.appendChild(row)
    }
    if (src || dst) {
      addRow('Src', srcLabel)
      addRow('Dst', dstLabel)
    }
    if (dir) addRow('Dir', dir + (flyTo.service ? ' · ' + flyTo.service : ''))
    if (score != null) {
      const row = el('div', 'flex items-center gap-1')
      row.appendChild(el('span', 'opacity-50 w-10', 'Score'))
      const scoreEl = el('span', 'font-semibold', String(score))
      scoreEl.style.color = (THREAT_LEVELS.find(t => score >= t.min) ?? THREAT_LEVELS[THREAT_LEVELS.length - 1]).hex
      row.appendChild(scoreEl)
      popupRoot.appendChild(row)
    }

    const marker = new maplibregl.Marker({ element: markerEl })
      .setLngLat([flyTo.lon, flyTo.lat])
      .setPopup(
        new maplibregl.Popup({ offset: 16, closeButton: false, maxWidth: '260px' }).setDOMContent(popupRoot)
      )
      .addTo(map)

    flyToMarkerRef.current = marker
    setHasFlyToMarker(true)

    map.flyTo({ center: [flyTo.lon, flyTo.lat], zoom: 8, duration: 1500 })

    // Show popup after fly animation
    const popupTimeout = setTimeout(() => marker.togglePopup(), 1600)

    // Reset flyTo prop immediately to prevent re-triggering; the flyTo
    // animation (1500ms) and popup open (1600ms setTimeout) complete async.
    if (onFlyToDone) onFlyToDone()

    return () => clearTimeout(popupTimeout)
  }, [flyTo, onFlyToDone])

  // Watch for theme changes
  useEffect(() => {
    const observer = new MutationObserver(() => {
      const map = mapRef.current
      if (!map) return
      const theme = getTheme()
      map.setStyle(theme === 'dark' ? TILE_DARK : TILE_LIGHT)
      // style.load handler will re-apply layers automatically
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => observer.disconnect()
  }, [])

  const summary = geoData?.summary

  // Count active non-default filters for mobile badge
  const activeFilterCount = [
    timeRange !== '24h',
    mode !== 'threats',
    view !== 'heatmap',
  ].filter(Boolean).length

  return (
    <div className="h-full flex flex-col">
      {/* Controls bar */}
      <div className="border-b border-gray-800 shrink-0">
        {/* Mobile filter toggle */}
        <button
          type="button"
          onClick={() => setFiltersExpanded(v => !v)}
          className="lg:hidden flex items-center gap-2 px-4 py-2.5 text-xs font-medium text-gray-300 hover:bg-gray-800/30 transition-colors w-full justify-between"
          aria-expanded={filtersExpanded}
          aria-controls="threat-filters-panel"
        >
          <span className="flex items-center gap-2">
            <span>Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}</span>
            {loading && <span className="text-blue-400 text-[10px]">Loading...</span>}
            {!loading && summary && (
              <span className="text-[10px] text-gray-500">{formatNumber(summary.total_events)} events</span>
            )}
          </span>
          <svg className={`w-3.5 h-3.5 transition-transform ${filtersExpanded ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" focusable="false">
            <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
          </svg>
        </button>

        {/* Filter content — always visible on desktop, collapsible on mobile */}
        <div id="threat-filters-panel" className={`${filtersExpanded ? 'flex' : 'hidden'} lg:flex items-center gap-3 px-4 py-2.5 flex-wrap`}>
          {/* Mode toggle */}
          <div className="flex items-center gap-0.5">
            {MODES.map(m => (
              <button
                type="button"
                key={m.id}
                onClick={() => setMode(m.id)}
                aria-pressed={mode === m.id}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                  mode === m.id ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-300'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>

          <span className="text-gray-700">|</span>

          {/* View toggle */}
          <div className="flex items-center gap-0.5">
            {VIEWS.map(v => (
              <button
                type="button"
                key={v.id}
                onClick={() => setView(v.id)}
                aria-pressed={view === v.id}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                  view === v.id ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-300'
                }`}
              >
                {v.label}
              </button>
            ))}
          </div>

          <span className="text-gray-700">|</span>

          {/* Time range */}
          <div className="flex items-center gap-0.5">
            {visibleRanges.map(tr => (
              <button
                type="button"
                key={tr}
                onClick={() => setTimeRange(tr)}
                aria-pressed={timeRange === tr}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                  timeRange === tr ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-gray-300'
                }`}
              >
                {tr}
              </button>
            ))}
          </div>

          {/* Summary stats */}
          <div className="ml-auto flex items-center gap-3 text-[10px] text-gray-400">
            {loading && <span className="text-blue-400">Loading...</span>}
            {summary && (
              <>
                <span>{formatNumber(summary.total_points)} locations</span>
                <span className="text-gray-700">|</span>
                <span>{formatNumber(summary.total_events)} events</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Map + sidebar row */}
      <div className="flex-1 flex min-h-0">
        {/* Map container */}
        <div className="flex-1 relative">
          <div ref={mapContainer} className="absolute inset-0" />

          {/* Empty state */}
          {!loading && geoData?.features?.length === 0 && !hasFlyToMarker && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
              <div className="bg-gray-950/80 border border-gray-800 rounded-lg px-6 py-4 text-center">
                <div className="text-gray-400 text-sm">No geo data available</div>
                <div className="text-gray-500 text-xs mt-1">
                  {mode === 'threats'
                    ? 'No threats with score > 70 and geo coordinates found'
                    : 'No blocked outbound traffic with geo coordinates found'}
                </div>
              </div>
            </div>
          )}

          {/* Legend — context-aware for heatmap vs clusters */}
          {geoData?.features?.length > 0 && (
            <div className="absolute bottom-6 left-4 z-10 bg-gray-950/90 border border-gray-800 rounded-lg px-3 py-2">
              {view === 'heatmap' ? (
                <>
                  <div className="text-[10px] text-white/70 uppercase tracking-wider mb-1.5">Event Density</div>
                  <div className="flex items-center gap-1.5">
                    <div className="h-2 w-28 rounded-full" style={{
                      background: 'linear-gradient(to right, rgba(250,204,21,0.3), #facc15, #f59e0b, #ef4444, #991b1b)',
                    }} />
                  </div>
                  <div className="flex justify-between text-[9px] text-white/50 mt-0.5 w-28">
                    <span>Fewer</span><span>More</span>
                  </div>
                </>
              ) : (
                <>
                  <div className="text-[10px] text-white/70 uppercase tracking-wider mb-1.5">Threat Score</div>
                  <div className="flex items-center gap-2 text-[10px] text-white/90 flex-wrap">
                    {[...THREAT_LEVELS].reverse().map(t => (
                      <span key={t.label} className="flex items-center gap-1">
                        <span className={`w-2.5 h-2.5 rounded-full ${t.dot} inline-block`} />
                        {t.label}
                      </span>
                    ))}
                  </div>
                  <div className="text-[10px] text-white/50 mt-1">Circle size = event count</div>
                </>
              )}
            </div>
          )}
        </div>

        {/* Sidebar */}
        {sidebarLocation && (
          <ThreatSidebar location={sidebarLocation} onClose={closeSidebar} />
        )}
      </div>
    </div>
  )
}
