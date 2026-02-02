import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Proxy API requests to the backend during local dev
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      },
      '/auth': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true
      },
      '/instances': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true
      },
       '/emails': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true
      },
       '/regions': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true
      }
    }
  }
})