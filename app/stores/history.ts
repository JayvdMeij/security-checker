import { defineStore } from 'pinia'
import type { CheckReport } from '#shared/types'

export const HISTORY_STORAGE_KEY = 'site-check:history:v1'
export const HISTORY_LIMIT = 50

/**
 * History of previous checks, persisted in localStorage.
 *
 * localStorage is per browser and per origin, so no accounts or database are needed,
 * and other sites cannot read it. Data read back is still treated as untrusted input:
 * it is shape-checked (it may be corrupt or from an older version) and only ever
 * rendered via escaped text interpolation.
 */
export const useHistoryStore = defineStore('history', {
  state: () => ({
    items: [] as CheckReport[],
    loaded: false,
  }),

  getters: {
    byId: (state) => (id: string) => state.items.find((item) => item.id === id),
  },

  actions: {
    /** Load from localStorage. Client-only: there is no localStorage during SSR. */
    load() {
      if (this.loaded || !import.meta.client) return
      this.items = readStorage()
      this.loaded = true
    },

    add(report: CheckReport) {
      this.load()
      this.items = [report, ...this.items.filter((item) => item.id !== report.id)].slice(0, HISTORY_LIMIT)
      this.persist()
    },

    remove(id: string) {
      this.items = this.items.filter((item) => item.id !== id)
      this.persist()
    },

    clear() {
      this.items = []
      this.persist()
    },

    persist() {
      if (!import.meta.client) return
      try {
        localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(this.items))
      } catch {
        // Storage full or disabled (e.g. private mode): keep the in-memory history only.
      }
    },
  },
})

function readStorage(): CheckReport[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter(isReport).slice(0, HISTORY_LIMIT) : []
  } catch {
    return []
  }
}

function isReport(value: unknown): value is CheckReport {
  if (!value || typeof value !== 'object') return false
  const r = value as Record<string, unknown>
  return (
    typeof r.id === 'string' &&
    typeof r.finalUrl === 'string' &&
    typeof r.checkedAt === 'string' &&
    typeof r.grade === 'string' &&
    typeof r.score === 'number' &&
    Array.isArray(r.checks) &&
    Array.isArray(r.redirects) &&
    Array.isArray(r.warnings) &&
    typeof r.info === 'object' &&
    r.info !== null
  )
}
