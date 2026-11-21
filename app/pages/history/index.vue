<script setup lang="ts">
import { HISTORY_LIMIT, useHistoryStore } from '~/stores/history'

useHead({ title: 'History · Site Check' })

const history = useHistoryStore()
onMounted(() => history.load())

const formatDate = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

const confirmingClear = ref(false)
function clearAll() {
  history.clear()
  confirmingClear.value = false
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h1 class="text-3xl font-bold tracking-tight">History</h1>
      <div v-if="history.items.length" class="flex items-center gap-2 text-sm">
        <template v-if="confirmingClear">
          <span class="text-slate-600">Delete all {{ history.items.length }} checks?</span>
          <button type="button" class="rounded-md bg-red-600 px-3 py-1.5 font-medium text-white hover:bg-red-700" data-testid="confirm-clear" @click="clearAll">
            Delete all
          </button>
          <button type="button" class="rounded-md px-3 py-1.5 hover:bg-slate-200" @click="confirmingClear = false">Cancel</button>
        </template>
        <button v-else type="button" class="rounded-md px-3 py-1.5 text-red-700 hover:bg-red-50" data-testid="clear-history" @click="confirmingClear = true">
          Clear history
        </button>
      </div>
    </div>

    <p class="text-sm text-slate-600">Checks are stored in this browser only (localStorage). The latest {{ HISTORY_LIMIT }} are kept.</p>

    <p v-if="history.loaded && !history.items.length" class="rounded-lg border border-dashed border-slate-300 p-8 text-center text-slate-600" data-testid="history-empty">
      No checks yet. <NuxtLink to="/" class="font-medium text-indigo-700 hover:underline">Check a site</NuxtLink>
    </p>

    <ul class="space-y-3" data-testid="history-list">
      <li
        v-for="item in history.items"
        :key="item.id"
        class="flex items-center gap-4 rounded-lg border border-slate-200 bg-white p-4 shadow-sm"
        data-testid="history-item"
      >
        <ScoreBadge :grade="item.grade" :score="item.score" size="sm" />
        <NuxtLink :to="`/history/${item.id}`" class="min-w-0 flex-1 hover:underline">
          <span class="block truncate font-medium">{{ item.info.title ?? item.finalUrl }}</span>
          <span class="block truncate font-mono text-xs text-slate-600">{{ item.finalUrl }}</span>
          <span class="block text-xs text-slate-500">{{ formatDate(item.checkedAt) }} · {{ item.score }}/{{ item.maxScore }}</span>
        </NuxtLink>
        <button
          type="button"
          class="rounded-md px-2 py-1 text-sm text-slate-500 hover:bg-red-50 hover:text-red-700"
          :aria-label="`Delete check of ${item.finalUrl}`"
          @click="history.remove(item.id)"
        >
          Delete
        </button>
      </li>
    </ul>
  </div>
</template>

