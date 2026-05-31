/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        "logo": ["Orbitron", "sans-serif"],
        "sans": ["Inter", "system-ui", "-apple-system", "sans-serif"],
        "mono": ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        // Aegis brand palette
        'bg': {
          'primary': '#030307',
          'secondary': '#0a0a14',
          'tertiary': '#141424',
        },
        'text': {
          'primary': '#f8fafc',
          'secondary': '#d1d5e8',
          'tertiary': '#94a3b8',
        },
        'border': {
          'primary': 'rgba(0, 212, 255, 0.2)',
          'secondary': 'rgba(0, 212, 255, 0.4)',
        },
        // Security severity colors
        'severity': {
          'critical': '#f7768e',
          'critical-bg': 'rgba(247, 118, 142, 0.15)',
          'high': '#e0af68',
          'high-bg': 'rgba(224, 175, 104, 0.15)',
          'medium': '#a855f7',
          'medium-bg': 'rgba(168, 85, 247, 0.15)',
          'low': '#9ece6a',
          'low-bg': 'rgba(158, 206, 106, 0.15)',
        },
        // Aegis accent colors
        'accent': {
          'blue': '#38bdf8',
          'cyan': '#00f2fe',
          'green': '#10b981',
          'magenta': '#d946ef',
          'purple': '#8b5cf6',
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
