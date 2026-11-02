import { h, btn, short } from './ui.js';

const COLORS = { relay: '#22d3ee', exit: '#4ade80', bridge: '#c084fc', legacy: '#94a3b8' };
const NS = 'http://www.w3.org/2000/svg';
let graphSerial = 0;

// Keep layout and camera math independent of the DOM for regression tests.
export function networkLayout(snapshot) {
  const unique = new Map();
  for (const node of snapshot.nodes || []) {
    if (typeof node.node_id === 'string' && node.node_id) unique.set(node.node_id, node);
  }
  const members = [...unique.values()].sort((a, b) => a.node_id.localeCompare(b.node_id)).slice(0, 512);
  const rings = Math.max(1, Math.ceil(members.length / 10));
  const width = 1400 + Math.max(0, rings - 1) * 380;
  const height = 900 + Math.max(0, rings - 1) * 300;
  const nodes = members.map((node, index) => {
    const ring = Math.floor(index / 10);
    const count = Math.min(10, members.length - ring * 10);
    const angle = -Math.PI / 2 + (index % 10) * Math.PI * 2 / count;
    return { ...node, x: width / 2 + (members.length === 1 ? 0 : Math.cos(angle) * (470 + ring * 190)), y: height / 2 + (members.length === 1 ? 0 : Math.sin(angle) * (290 + ring * 150)) };
  });
  const byId = new Map(nodes.map((node) => [node.node_id, node]));
  const links = new Map();
  for (const link of snapshot.links || []) {
    if (link.source === link.target || !byId.has(link.source) || !byId.has(link.target)) continue;
    if (!link.connected && !link.tcp_reachable) continue;
    if (link.valid_until != null && link.valid_until <= snapshot.generated_at) continue;
    if (link.observed_at != null && link.observed_at + 60 <= snapshot.generated_at) continue;
    const key = `${link.source}>${link.target}`;
    if (!links.has(key) || (links.get(key).reported_at || 0) < (link.reported_at || 0)) links.set(key, link);
    if (links.size >= 4096) break;
  }
  return { nodes, links: [...links.values()], byId, width, height };
}

export function zoomNetworkCamera(camera, requested, anchor) {
  const zoom = Math.max(0.35, Math.min(4, requested));
  const x = (anchor.x - camera.x) / camera.zoom;
  const y = (anchor.y - camera.y) / camera.zoom;
  camera.x = anchor.x - x * zoom;
  camera.y = anchor.y - y * zoom;
  camera.zoom = zoom;
}

function svgNode(tag, attrs = {}, text = null) {
  const el = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) if (value != null) el.setAttribute(key, String(value));
  if (text != null) el.textContent = String(text);
  return el;
}

function edgePoint(node, dx, dy) {
  const fraction = Math.min(118 / Math.max(1, Math.abs(dx)), 51 / Math.max(1, Math.abs(dy)));
  return { x: node.x + dx * fraction, y: node.y + dy * fraction };
}

export function networkGraph(snapshot, camera) {
  const graph = networkLayout(snapshot);
  if (camera.selected && !graph.byId.has(camera.selected)) camera.selected = null;
  const { width, height } = graph;
  const markerId = `network-arrow-${++graphSerial}`;
  const svg = svgNode('svg', { viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Сеть узлов и подписанные наблюдения о связях' });
  svg.style.cssText = 'display:block;width:100%;height:auto;touch-action:none;user-select:none';
  const defs = svgNode('defs');
  const marker = svgNode('marker', { id: markerId, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
  marker.append(svgNode('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: '#94a3b8' }));
  defs.append(marker);
  const world = svgNode('g');
  svg.append(defs, svgNode('rect', { width, height, fill: '#05060b' }), world);
  world.append(svgNode('ellipse', { cx: width / 2, cy: height / 2, rx: 470, ry: 290, fill: 'none', stroke: '#334155', 'stroke-opacity': 0.35 }));
  const drawnLinks = [];
  for (const link of graph.links) {
    const source = graph.byId.get(link.source), target = graph.byId.get(link.target);
    const dx = target.x - source.x, dy = target.y - source.y;
    const length = Math.max(1, Math.hypot(dx, dy));
    const start = edgePoint(source, dx, dy), end = edgePoint(target, -dx, -dy);
    const path = svgNode('path', {
      d: `M ${start.x} ${start.y} Q ${(start.x + end.x) / 2 - dy / length * 28} ${(start.y + end.y) / 2 + dx / length * 28} ${end.x} ${end.y}`,
      fill: 'none', stroke: link.connected ? '#22d3ee' : '#94a3b8', 'stroke-width': link.connected ? 2.4 : 1.5,
      'stroke-dasharray': link.connected ? null : '5 7', 'stroke-opacity': 0.7, 'marker-end': `url(#${markerId})`,
    });
    path.append(svgNode('title', {}, `${link.source} → ${link.target}\n${link.connected ? 'Получен ответ по аутентифицированному NRXP transport' : 'Успешная TCP-проба'}${link.rtt_ms == null ? '' : ` · ${link.rtt_ms} мс`}\n${link.local ? 'Наблюдение этого узла' : 'Подписанный отчёт удалённого узла'}${link.observed_at ? `\nЗамер: ${new Date(link.observed_at * 1000).toLocaleTimeString()}` : ''}`));
    world.append(path);
    drawnLinks.push({ path, link });
  }
  const drawnNodes = [];
  for (const node of graph.nodes) {
    const roles = node.roles || [];
    const role = roles.includes('bridge') ? 'bridge' : roles.includes('exit') ? 'exit' : roles.includes('relay') ? 'relay' : 'legacy';
    const color = COLORS[role];
    const group = svgNode('g', { transform: `translate(${node.x - 118} ${node.y - 51})`, 'data-network-node': node.node_id, tabindex: 0, role: 'button', 'aria-label': `Узел ${node.node_id}` });
    group.style.cursor = 'pointer';
    const border = svgNode('rect', { width: 236, height: 102, rx: 14, fill: '#090b13', stroke: color, 'stroke-width': node.is_self ? 3 : 1.8 });
    const address = node.endpoints?.[0]?.address || node.sni || 'адрес не объявлен';
    group.append(border, svgNode('title', {}, `${node.node_id}\n${address}\n${roles.join(' + ') || 'Legacy'}\n${node.is_self ? 'Этот узел' : node.state === 'reported' ? 'Есть свежий подписанный отчёт' : 'Известен по каталогу; свежего отчёта нет'}`));
    group.append(svgNode('circle', { cx: 220, cy: 15, r: 4, fill: node.is_self ? '#22c55e' : node.state === 'reported' ? '#60a5fa' : '#64748b' }));
    group.append(svgNode('text', { x: 118, y: 28, fill: '#f1f5f9', 'font-size': 13, 'text-anchor': 'middle', 'font-weight': 650 }, `${node.is_self ? 'ЭТОТ УЗЕЛ · ' : ''}${short(node.node_id, 8)}`));
    group.append(svgNode('text', { x: 118, y: 50, fill: '#94a3b8', 'font-size': 11, 'text-anchor': 'middle' }, address.length > 31 ? `${address.slice(0, 28)}…` : address));
    group.append(svgNode('text', { x: 118, y: 72, fill: color, 'font-size': 11, 'text-anchor': 'middle' }, roles.length ? roles.join(' + ').toUpperCase() : 'LEGACY'));
    group.append(svgNode('text', { x: 118, y: 90, fill: '#94a3b8', 'font-size': 10, 'text-anchor': 'middle' }, node.is_self ? 'локальное состояние' : node.state === 'reported' ? 'свежий отчёт' : 'связность неизвестна'));
    world.append(group);
    drawnNodes.push({ node, group, border, color });
    group.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); camera.selected = node.node_id; select(); }
    });
  }
  function select() {
    for (const { link, path } of drawnLinks) path.setAttribute('stroke-opacity', !camera.selected || [link.source, link.target].includes(camera.selected) ? '0.85' : '0.1');
    for (const { node, border, color } of drawnNodes) border.setAttribute('stroke', camera.selected === node.node_id ? '#fff' : color);
  }
  let drag = null;
  const label = h('span', { class: 'mono muted small', 'aria-live': 'polite' });
  function apply() { world.setAttribute('transform', `translate(${camera.x} ${camera.y}) scale(${camera.zoom})`); label.textContent = `${Math.round(camera.zoom * 100)}%`; svg.style.cursor = drag ? 'grabbing' : 'grab'; }
  function point(event) {
    const p = svg.createSVGPoint(); p.x = event.clientX; p.y = event.clientY;
    const matrix = svg.getScreenCTM();
    return matrix ? p.matrixTransform(matrix.inverse()) : { x: width / 2, y: height / 2 };
  }
  const center = { x: width / 2, y: height / 2 };
  function zoom(value, anchor = center) { zoomNetworkCamera(camera, value, anchor); apply(); }
  function reset() { camera.zoom = 1; camera.x = 0; camera.y = 0; camera.selected = null; select(); apply(); }
  const controls = h('div', { class: 'row', style: 'justify-content:flex-end;gap:6px' },
    btn({ label: '−', size: 'sm', aria: 'Уменьшить масштаб', onclick: () => zoom(camera.zoom / 1.2) }), label,
    btn({ label: '+', size: 'sm', aria: 'Увеличить масштаб', onclick: () => zoom(camera.zoom * 1.2) }),
    btn({ label: 'Вписать', size: 'sm', onclick: reset }));
  svg.addEventListener('wheel', (event) => { event.preventDefault(); zoom(camera.zoom * (event.deltaY < 0 ? 1.12 : 1 / 1.12), point(event)); }, { passive: false });
  svg.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    const node = event.target.closest?.('[data-network-node]');
    if (node) { camera.selected = node.getAttribute('data-network-node'); select(); return; }
    const p = point(event); drag = { x: camera.x, y: camera.y, point: p }; svg.setPointerCapture(event.pointerId); apply();
  });
  svg.addEventListener('pointermove', (event) => { if (!drag) return; const p = point(event); camera.x = drag.x + p.x - drag.point.x; camera.y = drag.y + p.y - drag.point.y; apply(); });
  function end(event) { drag = null; if (svg.hasPointerCapture(event.pointerId)) svg.releasePointerCapture(event.pointerId); apply(); }
  svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end);
  select(); apply();
  return h('div', { class: 'stack-sm' }, controls,
    h('div', { style: 'overflow:hidden;border:1px solid rgba(255,255,255,.12);border-radius:12px;background:#05060b' }, svg),
    h('p', { class: 'muted small' }, 'Сплошная линия — аутентифицированное соединение; пунктир — успешная TCP-проба. Стрелку подтверждает узел-отправитель. Синий индикатор — свежий подписанный отчёт, серый — известный узел без свежего отчёта.'));
}
