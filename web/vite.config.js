import { defineConfig } from 'vite';
export default defineConfig({ base: './', build: { target: 'es2022', outDir: 'dist', assetsInlineLimit: 0 }, esbuild: { target: 'es2022' } });
