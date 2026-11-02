// Графики без библиотек: SVG. Цвета — через классы/currentColor, чтобы следовать теме.
import { h } from './ui.js';

const NS = 'http://www.w3.org/2000/svg';
const el = (name, attrs = {}) => { const e = document.createElementNS(NS, name); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };

/** Мини-график для плитки. */
export function sparkline(values, { violet = false } = {}) {
  const svg = el('svg', { viewBox: '0 0 100 34', preserveAspectRatio: 'none', class: 'spark' + (violet ? ' violet' : ''), 'aria-hidden': 'true' });
  const v = values.length > 1 ? values : [0, 0];
  const max = Math.max(1, ...v), n = v.length - 1;
  const pts = v.map((y, i) => [(i / n) * 100, 32 - (y / max) * 30]);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)} ${y.toFixed(2)}`).join('');
  svg.append(
    el('path', { d: `${line}L100 34L0 34Z`, fill: 'currentColor', opacity: '0.12' }),
    el('path', { d: line, fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'vector-effect': 'non-scaling-stroke', 'stroke-linejoin': 'round' }));
  return svg;
}

/**
 * Основной график: линия + заливка (`conns`) и столбики (`new`). Наведение показывает значения.
 * points: [{ts, conns, new}]
 */
export function activityChart(points) {
  const W = 640, H = 190, L = 34, B = 20, T = 8, R = 6;
  const host = h('div', { class: 'chart' });
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Соединения за последний час' });
  host.append(svg);
  if (points.length < 2) {
    const t = el('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', class: 'ytxt' });
    t.textContent = 'Данные копятся — график появится через несколько секунд';
    svg.append(t);
    return host;
  }
  const maxC = Math.max(3, ...points.map((p) => p.conns));
  const maxN = Math.max(1, ...points.map((p) => p.new));
  const x = (i) => L + (i / (points.length - 1)) * (W - L - R);
  const yC = (v) => H - B - (v / maxC) * (H - B - T);
  const yN = (v) => H - B - (v / maxN) * (H - B - T) * 0.35;

  for (const f of [0, 0.5, 1]) {
    const y = H - B - f * (H - B - T);
    svg.append(el('line', { x1: L, x2: W - R, y1: y, y2: y, class: 'axis' }));
    const t = el('text', { x: L - 6, y: y + 3, 'text-anchor': 'end', class: 'ytxt' });
    t.textContent = Math.round(maxC * f);
    svg.append(t);
  }
  const bw = Math.max(1, ((W - L - R) / points.length) * 0.7);
  points.forEach((p, i) => { if (p.new > 0) svg.append(el('rect', { x: x(i) - bw / 2, y: yN(p.new), width: bw, height: H - B - yN(p.new), class: 's2' })); });
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${yC(p.conns).toFixed(1)}`).join('');
  svg.append(el('path', { d: `${line}L${x(points.length - 1)} ${H - B}L${L} ${H - B}Z`, class: 's1a' }), el('path', { d: line, class: 's1', 'vector-effect': 'non-scaling-stroke', 'stroke-linejoin': 'round' }));
  const mins = Math.max(1, Math.round((points[points.length - 1].ts - points[0].ts) / 60));
  for (const [anchor, txt, xx] of [['start', `−${mins} мин`, L], ['end', 'сейчас', W - R]]) {
    const t = el('text', { x: xx, y: H - 4, 'text-anchor': anchor, class: 'xtxt' });
    t.textContent = txt;
    svg.append(t);
  }

  const cross = el('line', { y1: T, y2: H - B, class: 'cross', visibility: 'hidden' });
  const tip = h('div', { class: 'tip', hidden: true });
  svg.append(cross);
  host.append(tip);
  svg.addEventListener('pointermove', (e) => {
    const r = svg.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = Math.max(0, Math.min(points.length - 1, Math.round(((px - L) / (W - L - R)) * (points.length - 1))));
    cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('visibility', 'visible');
    const p = points[i];
    tip.hidden = false;
    tip.textContent = `${new Date(p.ts * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })} · соед. ${p.conns} · новых ${p.new}`;
    tip.style.left = `${Math.max(90, Math.min(r.width - 90, (x(i) / W) * r.width))}px`;
  });
  svg.addEventListener('pointerleave', () => { cross.setAttribute('visibility', 'hidden'); tip.hidden = true; });
  return host;
}
