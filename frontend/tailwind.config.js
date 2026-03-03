/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Deep backgrounds (using CSS variables for theming)
        'bg-deep': 'var(--bg-deep)',
        'bg-surface': 'var(--bg-surface)',
        'bg-elevated': 'var(--bg-elevated)',
        'bg-card': 'var(--bg-card)',
        // Text colors
        'text-bright': 'var(--text-bright)',
        'text-normal': 'var(--text-normal)',
        'text-dim': 'var(--text-dim)',
        'text-muted': 'var(--text-muted)',
        // Accent colors
        'amber': {
          DEFAULT: '#f59e0b',
          bright: '#fbbf24',
          light: '#fcd34d',
          dim: 'rgba(245, 158, 11, 0.12)',
          glow: 'rgba(245, 158, 11, 0.25)',
          hover: '#d97706',
        },
        // Border colors
        'border-dim': 'var(--border-dim)',
        'border-visible': 'var(--border-visible)',
      },
      fontFamily: {
        'display': ['Syne', 'sans-serif'],
        'mono': ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(34, 197, 94, 0.5)' },
          '50%': { boxShadow: '0 0 0 6px rgba(34, 197, 94, 0)' },
        },
        'blink': {
          '50%': { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
}
