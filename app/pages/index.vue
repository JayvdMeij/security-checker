<script setup lang="ts">
import type { CheckReport } from '#shared/types'
import { useHistoryStore } from '~/stores/history'

const route = useRoute()
const history = useHistoryStore()

const report = ref<CheckReport | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

// "Check again" links prefill the form; a check is never started just by opening a link.
const initialUrl = computed(() => (typeof route.query.url === 'string' ? route.query.url.slice(0, 2048) : ''))

async function runCheck(url: string) {
  loading.value = true
  error.value = null
  try {
    report.value = await $fetch<CheckReport>('/api/check', { method: 'POST', body: { url } })
    history.add(report.value)
  } catch (e: unknown) {
    report.value = null
    const data = (e as { data?: { message?: string } }).data
    error.value = data?.message ?? 'Something went wrong. Please try again.'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="space-y-8">
    <section class="space-y-3">
      <h1 class="text-3xl font-bold tracking-tight">Check a website’s security headers</h1>
      <p class="text-slate-600">
        Enter a URL to see how well it uses HTTPS and security headers like CSP and HSTS, with a score and an explanation per header.
      </p>
      <UrlForm :loading="loading" :initial-url="initialUrl" @submit="runCheck" />
    </section>

    <p v-if="error" class="rounded-lg border border-red-300 bg-red-50 p-4 text-red-800" role="alert" data-testid="error">
      {{ error }}
    </p>

    <p v-if="loading" class="text-slate-600" data-testid="loading">Fetching the site and analysing its headers…</p>

    <ReportView v-if="report && !loading" :report="report" />
  </div>
</template>
