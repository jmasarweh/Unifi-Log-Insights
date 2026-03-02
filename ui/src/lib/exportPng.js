import { toPng } from 'html-to-image'

/** CSS properties critical for foreignObject rendering in PNG export.
 *  html-to-image struggles to resolve CSS classes inside SVG foreignObject,
 *  so we inline computed styles before capture and restore afterwards. */
const INLINE_PROPS = [
  'color', 'fontSize', 'fontFamily', 'fontWeight',
  'display', 'flexDirection', 'alignItems', 'justifyContent', 'gap',
  'padding', 'backgroundColor', 'background',
  'borderWidth', 'borderStyle', 'borderColor', 'borderRadius',
  'whiteSpace', 'overflow', 'textOverflow', 'maxWidth',
  'lineHeight', 'letterSpacing', 'textTransform',
  'flexShrink', 'opacity',
]

/**
 * Export a DOM element as a PNG image and trigger download.
 *
 * @param {HTMLElement} element - The container element to capture
 * @param {string} [filename='flow-graph.png'] - Download filename
 */
export async function exportChartPng(element, filename = 'flow-graph.png') {
  if (!element) return

  const theme = document.documentElement.dataset.theme
  const backgroundColor = theme === 'light' ? '#ffffff' : '#111827'

  // Inline computed styles on foreignObject children so html-to-image captures them
  const saved = []
  for (const fo of element.querySelectorAll('foreignObject')) {
    for (const el of fo.querySelectorAll('*')) {
      const prev = el.getAttribute('style') || ''
      const cs = window.getComputedStyle(el)
      for (const p of INLINE_PROPS) el.style[p] = cs[p]
      saved.push({ el, prev })
    }
  }

  try {
    const dataUrl = await toPng(element, {
      pixelRatio: 2,
      backgroundColor,
    })

    const a = document.createElement('a')
    a.href = dataUrl
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  } catch (err) {
    console.error('PNG export failed:', err)
    throw err
  } finally {
    for (const { el, prev } of saved) {
      if (prev) el.setAttribute('style', prev)
      else el.removeAttribute('style')
    }
  }
}
