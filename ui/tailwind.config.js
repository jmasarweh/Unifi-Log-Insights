/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['UI Sans', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'SF Mono', 'Cascadia Code', 'monospace'],
      },
      colors: {
        gray: {
          950: '#000000',
        },
      },
    },
  },
  plugins: [],
}
