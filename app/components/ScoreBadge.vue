<script setup lang="ts">
import type { Grade } from '#shared/types'

const props = withDefaults(defineProps<{ grade: Grade; score: number; maxScore?: number; size?: 'sm' | 'lg' }>(), {
  maxScore: 100,
  size: 'lg',
})

const color = computed(() => {
  switch (props.grade) {
    case 'A+':
    case 'A':
      return 'bg-emerald-600'
    case 'B':
      return 'bg-lime-600'
    case 'C':
      return 'bg-amber-500'
    case 'D':
      return 'bg-orange-600'
    default:
      return 'bg-red-600'
  }
})
</script>

<template>
  <div
    class="flex shrink-0 flex-col items-center justify-center rounded-2xl font-bold text-white"
    :class="[color, size === 'lg' ? 'h-24 w-24' : 'h-12 w-12 rounded-xl']"
    :aria-label="`Grade ${grade}, ${score} out of ${maxScore} points`"
    data-testid="grade"
  >
    <span :class="size === 'lg' ? 'text-4xl' : 'text-lg'">{{ grade }}</span>
    <span v-if="size === 'lg'" class="text-xs font-medium opacity-90">{{ score }}/{{ maxScore }}</span>
  </div>
</template>
