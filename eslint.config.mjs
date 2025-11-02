import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import prettierConfig from 'eslint-config-prettier'; // <-- ADD THIS IMPORT

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    // Base config: applies to all files
    ignores: ['dist/', 'node_modules/', '.env'],
  },
  {
    // Config for TypeScript files
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        project: './tsconfig.json',
      },
      globals: {
        node: true, // Make Node.js globals available
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      // Start with recommended rules
      ...tsPlugin.configs['eslint-recommended'].rules,
      ...tsPlugin.configs['recommended'].rules,
      
      // --- Add any custom rules here ---
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-floating-promises': 'error',
    },
  },

  prettierConfig,
];