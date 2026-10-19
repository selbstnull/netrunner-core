// Обзор: состояние узла, «требует внимания», живые показатели, сети и последние действия.
import { api, nav, store } from './api.js';
import { h, icon, btn, badge, eyebrow, empty, skeleton, dur, rel, short, plural, act, put } from './ui.js';
import { sparkline, activityChart } from './charts.js';
import { openIssue } from './meshes.js';
import { actionLabel, detailText } from './tools.js';

const MODE = { swarm: 'режим роя', panel: 'под управлением панели', standalone: 'автономный узел' };

export function overviewView() {
  const hero = h('section', { class: 'card hero' }, skeleton(60));
  const attn = h('div', {});
  const tiles = h('div', { class: 'grid cols-4 keep-2' }, [0, 1, 2, 3].map(() => h('div', { class: 'card' }, skeleton(70))));
  const chart = h('section', { class: 'card' }, skeleton(190));
  const meshes = h('section', { class: 'card flush' }, skeleton(120));
  const audit = h('section', { class: 'card flush' }, skeleton(120));
  const el = h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, eyebrow('обзор'), h('h1', {}, 'Состояние узла и доступа'))),
    hero, attn, tiles, chart, h('div', { class: 'grid cols-2' }, meshes, audit));

  let tick = 0, timer, alive = true;
  let data = { node: null, live: null, items: [], meshList: [], entries: [] };

  const renderLive = () => {
    const { node, live } = data;
    if (!node) return;
    const warns = data.items.filter((i) => i.level !== 'info').length;
    put(hero, 
      h('div', { class: 'hero-status' },
        h('span', { class: `led ${node.healthy ? (warns ? 'warn' : 'ok') : 'bad'}`, style: 'width:14px;height:14px' }),
        h('div', { class: 'grow' },
          h('div', { class: 'big' }, !node.healthy ? 'Узел не отвечает' : warns ? 'Узел работает · есть что проверить' : 'Узел работает штатно'),
          h('div', { class: 'muted small mono' }, [MODE[node.mode], `аптайм ${dur(node.uptime)}`, node.node_id ? `id ${short(node.node_id, 6)}` : null].filter(Boolean).join('  ·  '))),
        h('div', { class: 'row' },
          store.status && data.meshList.length
            ? btn({ label: 'Выдать доступ', icon: 'key', variant: 'primary', onclick: () => openIssue({}) })
            : btn({ label: 'Создать сеть', icon: 'plus', variant: 'primary', onclick: () => nav('#/meshes') }),
          btn({ label: 'Клиентский конфиг', icon: 'terminal', onclick: () => nav('#/nodes') }))));

    const pts = live?.points ?? [];
    const sum = (k) => pts.reduce((a, p) => a + p[k], 0);
    const noMetrics = !live?.metrics;
    const bad = (p) => p.auth_fail + p.scanner;
    const meshN = node.mesh?.enabled ? node.mesh.peers : null;
    const tile = (label, value, unit, hintText, spark) => h('div', { class: 'card tile' }, h('span', { class: 'label' }, label), h('div', { class: 'value' }, value, unit ? h('small', {}, unit) : null), h('div', { class: 'hint' }, hintText), spark);
    put(tiles, 
      tile('Соединения', String(node.active_connections), null, 'активны сейчас', sparkline(pts.map((p) => p.conns))),
      tile('Подключений', noMetrics ? '—' : String(Math.round(sum('new'))), 'за час', noMetrics ? 'метрики недоступны' : 'новых физических соединений', sparkline(pts.map((p) => p.new))),
      tile('Mesh', meshN == null ? '—' : String(meshN), meshN == null ? null : plural(meshN, 'сосед', 'соседа', 'соседей'), node.mesh?.enabled ? `макс. хопов: ${node.config?.mesh_max_hops ?? '—'}` : 'mesh выключен', sparkline(pts.map((p) => p.mesh), { violet: true })),
      tile('Отбито', noMetrics ? '—' : String(Math.round(sum('auth_fail') + sum('scanner'))), 'за час', 'отказов авторизации и сканеров', sparkline(pts.map(bad), { violet: true })));
    put(chart, 
      h('div', { class: 'card-head' }, h('h2', {}, 'Активность за час'), h('div', { class: 'end legend' }, h('span', {}, h('i'), 'соединения'), h('span', {}, h('i', { class: 'v' }), 'новые'))),
      activityChart(pts));
  };

  const renderAttn = () => {
    const items = data.items.filter((i) => i.code !== 'no-meshes');
    if (!items.length) { put(attn, h('div', { class: 'notice info' }, icon('check'), h('div', {}, 'Всё в порядке: срочных задач нет.'))); return; }
    const actionFor = (i) => {
      const go = (to, label) => btn({ label, size: 'sm', onclick: () => nav(to) });
      if (i.code === 'no-meshes') return go('#/meshes', 'Создать сеть');
      if (i.code.includes('backup')) return go('#/tools/backup', 'Копия');
      if (i.code === 'node-stalled') return go('#/tools/config', 'Конфигурация');
      if (i.code === 'node-old-key') return go(`#/meshes/${i.mesh}/keys`, 'Ключи');
      if (i.code === 'node-key-unknown') return go('#/meshes', 'Сети');
      if (i.mesh) return go(`#/meshes/${i.mesh}${i.code.includes('root') || i.code === 'stale-grants' ? '/keys' : ''}`, 'Открыть');
      return null;
    };
    put(attn, h('section', { class: 'card flush' },
      h('div', { class: 'card-head' }, eyebrow('Требует внимания'), badge(String(items.length), items.some((i) => i.level === 'crit') ? 'bad' : 'warn')),
      h('div', { class: 'attn' }, items.map((i) => h('div', { class: `attn-row ${i.level}` }, h('span', { class: 'dot' }), h('span', { class: 'grow' }, i.text), actionFor(i))))));
  };

  const renderLists = () => {
    put(meshes, 
      h('div', { class: 'card-head' }, h('h2', {}, 'Сети'), h('div', { class: 'end' }, btn({ label: 'Все', size: 'sm', variant: 'ghost', onclick: () => nav('#/meshes') }))),
      data.meshList.length
        ? data.meshList.map((m) => h('a', { class: 'list-row', href: `#/meshes/${m.id}`, style: 'text-decoration:none;color:inherit;grid-template-columns:1fr auto' },
          h('div', { class: 'who-text' }, h('strong', {}, m.name), h('div', { class: 'muted small mono' }, `ключ #${m.swarm_epoch} · корень #${m.root_epoch}`)),
          h('div', { class: 'row' }, m.on_this_node === 'current' ? badge('этот узел', 'ok') : m.on_this_node === 'previous' ? badge('старый ключ', 'warn') : null, badge(`${m.counts.active} дейст.`, 'primary'), m.expiring ? badge(`${m.expiring} истекают`, 'warn') : null)))
        : empty('network', 'Сетей пока нет', 'Создайте сеть — для неё сгенерируются ключ роя и корень доверенностей.', btn({ label: 'Создать сеть', icon: 'plus', variant: 'primary', onclick: () => nav('#/meshes') })));
    put(audit, 
      h('div', { class: 'card-head' }, h('h2', {}, 'Последние действия'), h('div', { class: 'end' }, btn({ label: 'Журнал', size: 'sm', variant: 'ghost', onclick: () => nav('#/tools/audit') }))),
      data.entries.length
        ? data.entries.slice(0, 6).map((e) => h('div', { class: 'list-row', style: 'grid-template-columns:1fr auto' }, h('div', {}, h('strong', {}, actionLabel(e.action)), detailText(e) ? h('div', { class: 'muted small' }, detailText(e)) : null), h('span', { class: 'muted small nowrap' }, rel(e.ts))))
        : h('p', { class: 'muted pad-sm', style: 'padding:6px 18px 16px' }, 'Действий пока не было.'));
  };

  async function load(full) {
    const jobs = [api('GET', 'node').then((n) => { data.node = n; store.node = n; store.nodeError = false; }), api('GET', 'live').then((l) => { data.live = l; })];
    if (full) jobs.push(api('GET', 'attention').then((a) => { data.items = a.items; }), api('GET', 'meshes').then((m) => { data.meshList = m.meshes; }), api('GET', 'audit').then((a) => { data.entries = a.entries; }));
    await Promise.all(jobs);
    if (!alive) return;
    renderLive();
    if (full) { renderAttn(); renderLists(); }
  }
  act(() => load(true));
  timer = setInterval(() => { tick++; act(() => load(tick % 3 === 0)); }, 5000);
  return { el, dispose: () => { alive = false; clearInterval(timer); } };
}
