import { useState, useCallback } from 'react'
import { fetchApiTokens, createApiToken, revokeApiToken } from '../api'

/**
 * Shared hook for token CRUD operations.
 * @param {string} [clientType] - Optional client_type filter for fetchApiTokens.
 *
 * No auto-reload on mount: consumer-driven loading by design. Consumers call
 * reload() in their own useEffect to control timing.
 *
 * Returns { tokens, loading, saving, error, reload, create, revoke }.
 * - loading: true during initial/explicit reload
 * - saving: true during create/revoke mutations
 * - reload({ silent }): silent=true skips loading flag (used after mutations)
 * - reload returns null on success, error message string on failure
 */
export default function useApiTokens(clientType) {
  const [tokens, setTokens] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const reload = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const resp = await fetchApiTokens(clientType)
      setTokens(resp.tokens || [])
      return null
    } catch (err) {
      setTokens([])
      const msg = err.message || 'Failed to load tokens'
      setError(msg)
      return msg
    } finally {
      if (!silent) setLoading(false)
    }
  }, [clientType])

  const create = useCallback(async (payload) => {
    setSaving(true)
    setError(null)
    try {
      const resp = await createApiToken(payload)
      await reload({ silent: true })
      return resp
    } catch (err) {
      setError(err.message || 'Failed to create token')
      throw err
    } finally {
      setSaving(false)
    }
  }, [reload])

  const revoke = useCallback(async (id) => {
    setSaving(true)
    setError(null)
    try {
      await revokeApiToken(id)
      await reload({ silent: true })
    } catch (err) {
      setError(err.message || 'Failed to revoke token')
      throw err
    } finally {
      setSaving(false)
    }
  }, [reload])

  return { tokens, loading, saving, error, reload, create, revoke }
}
