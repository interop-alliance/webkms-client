import { defineConfig } from 'vitest/config'
import { fileURLToPath } from 'node:url'

export default defineConfig(({ mode }) => ({
  // In the browser (the playwright dev server, mode 'development') resolve the
  // isomorphic crypto module to its browser implementation so the bundle loads
  // without `node:crypto`. The vitest node run (mode 'test') keeps the
  // node:crypto-backed module. This mirrors the package.json `browser` field
  // for first-party source served directly by vite; for consumers the swap is
  // made permanent via the `browser` export condition.
  resolve:
    mode === 'test'
      ? undefined
      : {
          alias: {
            './crypto.js': fileURLToPath(
              new URL('./src/crypto-browser.ts', import.meta.url)
            )
          }
        },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
}))
