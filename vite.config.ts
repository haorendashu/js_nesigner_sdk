import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'jsNesignerSdk',
      fileName: (format) => `index.${format}.js`,
      formats: ['es', 'cjs']
    },
    rollupOptions: {
      external: [
        '@noble/ciphers',
        '@noble/curves',
        '@noble/hashes',
        '@scure/base',
        'ts-md5'
      ],
      output: {
        globals: {
          '@noble/ciphers': 'nobleCiphers',
          '@noble/curves': 'nobleCurves',
          '@noble/hashes': 'nobleHashes',
          '@scure/base': 'scureBase',
          'ts-md5': 'tsMd5'
        }
      }
    }
  },
  // 添加TypeScript解析配置
  resolve: {
    extensions: ['.ts', '.js']
  }
});