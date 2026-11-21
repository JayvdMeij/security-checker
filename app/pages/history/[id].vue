<script setup lang="ts">
import { useHistoryStore } from '~/stores/history'

const route = useRoute()
const history = useHistoryStore()
onMounted(() => history.load())

const report = computed(() => history.byId(String(route.params.id)))
useHead({ title: () => (report.value ? `${report.value.finalUrl} · Site Check` : 'Check · Site Check') })
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <NuxtLink to="/history" class="text-sm text-indigo-700 hover:underline">← Back to history</NuxtLink>
      <NuxtLink
        v-if="report"
        :to="{ path: '/', query: { url: report.requestedUrl } }"
        class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
      >
        Check again
      </NuxtLink>
    </div>

    <ReportView v-if="report" :report="report" />
    <p v-else-if="history.loaded" class="rounded-lg border border-dashed border-slate-300 p-8 text-center text-slate-600">
      This check is not in your history (anymore).
    </p>
  </div>
</template>
