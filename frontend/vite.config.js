import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const backend = 'http://127.0.0.1:8000'

// Dev-server proxy: API + WebSocket go to FastAPI. In production the built
// dist/ is served by FastAPI itself, so everything is same-origin.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/auth': backend,
      '/portal': backend,
      '/soc': backend,
      '/audit': backend,
      '/demo': backend,
      '/vault': backend,
      '/pqc': backend,
      '/health': backend,
      '/ws': { target: 'ws://127.0.0.1:8000', ws: true },
    },
  },
})
