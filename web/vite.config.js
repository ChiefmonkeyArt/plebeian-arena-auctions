import { defineConfig } from 'vite';
// worker.format 'es': the wallet worker (v0.4.2) is a module worker that loads Coco on demand.
export default defineConfig({ base: './', build: { target: 'es2022', outDir: 'dist', assetsInlineLimit: 0 }, esbuild: { target: 'es2022' }, worker: { format: 'es' } });
