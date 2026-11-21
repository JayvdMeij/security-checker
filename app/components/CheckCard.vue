<script setup lang="ts">
import type { CheckResult, CheckStatus } from '#shared/types'

defineProps<{ check: CheckResult }>()

const STATUS: Record<CheckStatus, { label: string; classes: string; border: string }> = {
  pass: { label: 'Good', classes: 'bg-emerald-100 text-emerald-800', border: 'border-l-emerald-500' },
  warn: { label: 'Could be better', classes: 'bg-amber-100 text-amber-800', border: 'border-l-amber-500' },
  fail: { label: 'Weak', classes: 'bg-red-100 text-red-800', border: 'border-l-red-500' },
  missing: { label: 'Missing', classes: 'bg-slate-200 text-slate-700', border: 'border-l-red-400' },
}
</script>

<template>
  <article
    class="rounded-lg border border-l-4 border-slate-200 bg-white p-5 shadow-sm"
    :class="STATUS[check.status].border"
    :data-testid="`check-${check.id}`"
  >
    <header class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="font-semibold">{{ check.name }}</h3>
      <div class="flex items-center gap-2 text-sm">
        <span class="rounded-full px-2.5 py-0.5 font-medium" :class="STATUS[check.status].classes" data-testid="check-status">
          {{ STATUS[check.status].label }}
        </span>
        <span class="tabular-nums text-slate-600">{{ check.score }}/{{ check.maxScore }}</span>
      </div>
    </header>

    <p v-if="check.value" class="mt-3 max-h-40 overflow-auto rounded bg-slate-100 px-3 py-2 font-mono text-xs text-slate-800 [overflow-wrap:anywhere]">
      {{ check.value }}
    </p>

    <ul class="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-700">
      <li v-for="(finding, i) in check.findings" :key="i">{{ finding }}</li>
    </ul>

    <p v-if="check.recommendation" class="mt-3 text-sm">
      <span class="font-medium">Recommendation:</span> {{ check.recommendation }}
    </p>

    <details class="mt-3 text-sm text-slate-600">
      <summary class="cursor-pointer select-none font-medium text-indigo-700 hover:underline">What does this do?</summary>
      <p class="mt-2">{{ check.explanation }}</p>
      <p class="mt-2">
        Example:
        <code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs [overflow-wrap:anywhere]">{{ check.example }}</code>
      </p>
    </details>
  </article>
</template>
