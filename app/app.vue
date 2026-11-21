<template>
  <div class="min-h-screen bg-slate-50 text-slate-900">
    <header class="border-b border-slate-200 bg-white">
      <nav class="mx-auto flex max-w-4xl items-center justify-between px-4 py-4">
        <NuxtLink to="/" class="text-lg font-semibold">Site Check</NuxtLink>
        <div class="flex gap-4 text-sm">
          <NuxtLink to="/" class="hover:underline" active-class="font-semibold">Check</NuxtLink>
          <NuxtLink to="/history" class="hover:underline" active-class="font-semibold">History</NuxtLink>
        </div>
      </nav>
    </header>
    <main class="mx-auto max-w-4xl px-4 py-8">
      <NuxtPage />
    </main>
  </div>
</template>
