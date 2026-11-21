<script setup lang="ts">
const props = defineProps<{ loading: boolean; initialUrl?: string }>()
const emit = defineEmits<{ submit: [url: string] }>()

const url = ref(props.initialUrl ?? '')
watch(
  () => props.initialUrl,
  (value) => {
    if (value) url.value = value
  },
)

function onSubmit() {
  const value = url.value.trim()
  if (value && !props.loading) emit('submit', value)
}
</script>

<template>
  <form class="flex flex-col gap-3 sm:flex-row" novalidate @submit.prevent="onSubmit">
    <label for="url" class="sr-only">Website URL</label>
    <input
      id="url"
      v-model="url"
      data-testid="url-input"
      type="text"
      inputmode="url"
      autocomplete="url"
      spellcheck="false"
      maxlength="2048"
      placeholder="example.com"
      class="min-w-0 flex-1 rounded-lg border border-slate-300 bg-white px-4 py-3 text-base shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-200"
      :disabled="loading"
    />
    <button
      type="submit"
      data-testid="check-button"
      class="rounded-lg bg-indigo-600 px-6 py-3 font-medium text-white shadow-sm transition hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-300 disabled:cursor-not-allowed disabled:opacity-60"
      :disabled="loading || !url.trim()"
    >
      {{ loading ? 'Checking…' : 'Check site' }}
    </button>
  </form>
</template>
