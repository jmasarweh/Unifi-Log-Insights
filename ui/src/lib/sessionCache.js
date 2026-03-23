/**
 * sessionStorage cache with TTL — shared across Dashboard, FlowView, etc.
 *
 * Keys are namespaced by prefix + version + a caller-supplied discriminator
 * (e.g. serialized filters). Data expires after CACHE_TTL_MS.
 */

const CACHE_VERSION = 'v1'
const CACHE_TTL_MS = 10 * 60 * 1000 // 10 minutes

export { CACHE_TTL_MS }

export function cacheKey(prefix, discriminator) {
  return `${prefix}:${CACHE_VERSION}:${discriminator}`
}

export function readCache(prefix, discriminator) {
  try {
    const raw = sessionStorage.getItem(cacheKey(prefix, discriminator))
    if (!raw) return null
    const { fetchedAt, data } = JSON.parse(raw)
    if (Date.now() - fetchedAt > CACHE_TTL_MS) return null
    return data
  } catch (e) { console.warn('Cache read failed:', e); return null }
}

export function writeCache(prefix, discriminator, data) {
  try {
    sessionStorage.setItem(cacheKey(prefix, discriminator), JSON.stringify({ fetchedAt: Date.now(), data }))
  } catch (e) { console.warn('Cache write failed:', e) }
}
