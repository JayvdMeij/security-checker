<script setup lang="ts">
import type { CheckReport } from '#shared/types'

const props = defineProps<{ report: CheckReport }>()

const checkedAt = computed(() =>
  new Date(props.report.checkedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }),
)

const facts = computed(() => {
  const r = props.report
  return [
    { label: 'HTTP status', value: String(r.status) },
    { label: 'Response time', value: `${r.durationMs} ms` },
    { label: 'IP address', value: r.remoteAddress ?? 'unknown' },
    { label: 'Server', value: r.info.server ?? '—' },
    { label: 'Content type', value: r.info.contentType ?? '—' },
    { label: 'Checked', value: checkedAt.value },
  ]
})
</script>

<template>
  <section class="space-y-6" data-testid="report" aria-live="polite">
    <div class="flex flex-col gap-5 rounded-lg border border-slate-200 bg-white p-5 shadow-sm sm:flex-row sm:items-center">
      <ScoreBadge :grade="report.grade" :score="report.score" :max-score="report.maxScore" />
      <div class="min-w-0 flex-1">
        <h2 class="truncate text-xl font-semibold" data-testid="report-title">{{ report.info.title ?? report.finalUrl }}</h2>
        <p class="mt-1 truncate font-mono text-sm text-slate-600" data-testid="report-url">{{ report.finalUrl }}</p>
        <p v-if="report.info.description" class="mt-2 line-clamp-2 text-sm text-slate-700">{{ report.info.description }}</p>
      </div>
    </div>

    <dl class="grid grid-cols-2 gap-3 sm:grid-cols-3">
      <div v-for="fact in facts" :key="fact.label" class="rounded-lg border border-slate-200 bg-white p-3">
        <dt class="text-xs uppercase tracking-wide text-slate-500">{{ fact.label }}</dt>
        <dd class="mt-1 truncate text-sm font-medium" :title="fact.value">{{ fact.value }}</dd>
      </div>
    </dl>

    <div v-if="report.redirects.length" class="rounded-lg border border-slate-200 bg-white p-4 text-sm">
      <h3 class="font-semibold">Redirects</h3>
      <ol class="mt-2 space-y-1 font-mono text-xs text-slate-700">
        <li v-for="(hop, i) in report.redirects" :key="i" class="[overflow-wrap:anywhere]">
          {{ hop.url }} <span class="text-slate-500">→ {{ hop.status }} →</span> {{ hop.location }}
        </li>
      </ol>
    </div>

    <div v-if="report.warnings.length" class="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900" data-testid="warnings">
      <h3 class="font-semibold">Information disclosure</h3>
      <ul class="mt-2 list-disc space-y-1 pl-5">
        <li v-for="(warning, i) in report.warnings" :key="i">{{ warning }}</li>
      </ul>
    </div>

    <div class="space-y-4">
      <h2 class="text-lg font-semibold">Checks</h2>
      <CheckCard v-for="check in report.checks" :key="check.id" :check="check" />
    </div>
  </section>
</template>
