// Узлы: этот узел, клиентский конфиг, самоописание для соседей и список соседей с RTT.
import { api, nav } from './api.js';
import { h, icon, btn, badge, field, notice, empty, skeleton, secret, eyebrow, dialog, confirmDialog, toast, copy, download, act, fmtDate, rel, dur, short, plural, put } from './ui.js';

const MODE = { swarm: 'рой (без панели)', panel: 'под управлением панели', standalone: 'автономный' };
const ROLE = { relay: ['ретранслятор', 'primary'], exit: ['выход', 'violet'], bridge: ['мост', 'warn'] };

function rtt(ms) {
  if (ms == null) return h('span', { class: 'muted small' }, 'не замерен');
  const cls = ms < 80 ? '' : ms < 200 ? 'mid' : 'high';
  return h('span', { class: `rtt ${cls}`.trim(), title: 'Задержка до узла (TCP-проба)' }, `${ms} мс`, h('i', {}, h('b', { style: `width:${Math.min(100, ms / 3)}%` })));
}

export function nodesView() {
  const own = h('section', { class: 'card' }, skeleton(200));
  const cfg = h('section', { class: 'card' }, skeleton(200));
  const desc = h('div', {});
  const peersCard = h('section', { class: 'card flush' }, skeleton(160));
  const el = h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, eyebrow('узлы'), h('h1', {}, 'Этот узел и соседи'))),
    h('div', { class: 'grid cols-2' }, own, cfg), desc, peersCard);
  let alive = true, q = '';
  let node = null, peers = null;

  const renderOwn = () => {
    const n = node;
    put(own, 
      h('div', { class: 'card-head' }, h('h2', {}, 'Этот узел'), h('div', { class: 'end' }, badge(n.healthy ? 'в сети' : 'не отвечает', n.healthy ? 'ok' : 'bad'))),
      h('dl', { class: 'kv' },
        h('dt', {}, 'Режим'), h('dd', {}, MODE[n.mode]),
        n.node_id ? [h('dt', {}, 'node_id'), h('dd', {}, secret(n.node_id, 'node_id скопирован'))] : null,
        n.static_public ? [h('dt', {}, 'Публичный ключ'), h('dd', {}, secret(n.static_public, 'Публичный ключ скопирован'))] : null,
        h('dt', {}, 'Адрес для клиентов'), h('dd', {}, n.advertise ? h('code', { class: 'mono' }, n.advertise) : h('span', { class: 'muted' }, 'не задан (--advertise)')),
        h('dt', {}, 'Сайт-приманка'), h('dd', {}, n.decoy_host),
        h('dt', {}, 'Строгий режим'), h('dd', {}, n.strict ? badge('включён', 'ok') : badge('выключен', 'warn', 'PROXY_NRXP_STRICT=true — обязателен после раскатки')),
        h('dt', {}, 'Аптайм'), h('dd', {}, dur(n.uptime)),
        h('dt', {}, 'Соединения'), h('dd', {}, String(n.active_connections)),
        h('dt', {}, 'Mesh'), h('dd', {}, n.mesh.enabled ? `включён · макс. хопов ${n.config.mesh_max_hops} · пиров ${n.mesh.peers}` : 'выключен'),
        n.directory_records != null ? [h('dt', {}, 'Каталог'), h('dd', {}, `${n.directory_records} ${plural(n.directory_records, 'запись', 'записи', 'записей')}`)] : null));
  };

  const renderCfg = () => {
    const remote = h('input', { type: 'text', placeholder: node.advertise || 'IP_УЗЛА:443', 'aria-label': 'Адрес узла' });
    const sni = h('input', { type: 'text', placeholder: node.decoy_host, 'aria-label': 'SNI' });
    const out = h('div', {});
    let full = '', masked = true;
    const show = () => {
      const text = masked ? full.replace(/(node_secret\s*=\s*")[0-9a-f]+(")/, '$1••••••••••••••••$2') : full;
      const ta = h('textarea', { readOnly: true, rows: 6, 'aria-label': 'client.toml' }); ta.value = text;
      put(out, h('div', { class: 'stack-sm', style: 'margin-top:12px' }, ta,
        h('div', { class: 'row' },
          btn({ label: 'Копировать', icon: 'copy', size: 'sm', variant: 'primary', onclick: () => copy(full, 'client.toml скопирован') }),
          btn({ label: 'Скачать', icon: 'download', size: 'sm', onclick: () => download('client.toml', full, 'text/plain') }),
          btn({ label: masked ? 'Показать секрет' : 'Скрыть секрет', icon: masked ? 'eye' : 'eyeoff', size: 'sm', onclick: () => { masked = !masked; show(); } })),
        h('p', { class: 'muted small' }, 'Положите файл на клиента (chmod 600) и запустите: netrunner-client --config client.toml')));
    };
    const gen = () => act(async () => {
      const q = new URLSearchParams(); if (remote.value.trim()) q.set('remote', remote.value.trim()); if (sni.value.trim()) q.set('sni', sni.value.trim());
      full = (await api('GET', `node/client-config?${q}`)).toml; masked = true; show();
    });
    put(cfg, 
      h('div', { class: 'card-head' }, h('h2', {}, 'Конфиг для клиента')),
      h('p', { class: 'muted', style: 'margin-bottom:12px' }, 'Готовый client.toml для подключения к этому узлу. Содержит входной секрет узла — каждая выдача записывается в журнал.'),
      h('div', { class: 'stack-sm' }, field('Публичный адрес узла', remote), field('SNI', sni), h('div', { class: 'row' }, btn({ label: 'Сгенерировать', icon: 'terminal', variant: 'primary', onclick: gen }))), out);
  };

  const renderDesc = async () => {
    if (node.mode !== 'swarm') { put(desc, ); return; }
    const d = await act(() => api('GET', 'node/descriptor'));
    if (!d || !alive) return;
    const ta = h('textarea', { readOnly: true, rows: 3, 'aria-label': 'Самоописание' }); ta.value = d.descriptor;
    put(desc, h('section', { class: 'card stack-sm' },
      h('div', { class: 'card-head' }, h('h2', {}, 'Самоописание узла'), badge(`seq ${d.seq}`, 'mono'), h('span', { class: 'muted small' }, `действует до ${fmtDate(d.valid_until)}`)),
      h('p', { class: 'muted' }, 'Подписанная запись, по которой соседи находят этот узел. Передайте её оператору другого узла — он добавит её в «Соседей» или в --directory-seed.'),
      ta, h('div', { class: 'row' }, btn({ label: 'Копировать', icon: 'copy', size: 'sm', variant: 'primary', onclick: () => copy(d.descriptor, 'Самоописание скопировано') }))));
  };

  const addSeed = () => {
    const ta = h('textarea', { rows: 5, placeholder: 'hex самоописания соседа (его «descriptor»)' });
    dialog({ title: 'Добавить соседа', body: h('div', { class: 'stack-sm' }, h('p', { class: 'muted' }, 'Запись проверяется (подпись, срок, публичный адрес) перед добавлением. Дальше узел будет обмениваться записями с соседом сам.'), ta),
      actions: [{ label: 'Добавить', icon: 'plus', variant: 'primary', run: async () => { const r = await api('POST', 'node/seed', { descriptor: ta.value }); toast({ added: 'Сосед добавлен', updated: 'Запись обновлена', stale: 'Такая или более новая запись уже есть' }[r.result] || 'Готово'); load(); } }] });
  };

  const renderPeers = () => {
    const list = (peers.peers || []).filter((p) => !q || [p.node_id, p.sni, ...p.endpoints.map((e) => e.address)].join(' ').toLowerCase().includes(q));
    const isDir = peers.source === 'directory';
    const search = h('input', { type: 'search', 'data-search': '1', placeholder: 'Поиск по id, адресу…', 'aria-label': 'Поиск', value: q });
    search.addEventListener('input', () => { q = search.value.toLowerCase(); renderPeers(); const f = peersCard.querySelector('input[type=search]'); if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); } });
    put(peersCard, 
      h('div', { class: 'card-head' }, h('h2', {}, 'Соседи'), badge(String((peers.peers || []).length), 'primary'), h('div', { class: 'end' },
        node.mode === 'swarm' ? [btn({ label: 'Добавить соседа', icon: 'plus', size: 'sm', variant: 'primary', onclick: addSeed }),
          btn({ label: 'Очистить устаревшие', icon: 'trash', size: 'sm', onclick: () => act(async () => { const r = await api('POST', 'node/directory/gc'); toast(`Удалено записей: ${r.removed}`); load(); }) })] : null,
        btn({ label: 'Обновить', icon: 'refresh', size: 'sm', variant: 'ghost', onclick: load }))),
      (peers.peers || []).length > 6 ? h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search', 'sm'), search)) : null,
      list.length ? list.map((p) => h('div', { class: 'list-row' },
        h('div', { class: 'who-text' }, h('strong', { class: 'mono' }, short(p.node_id, 8)), p.is_self ? ' ' : null, p.is_self ? badge('это узел', 'ok') : null, h('div', { class: 'muted small' }, p.sni || '')),
        h('div', { class: 'small' }, p.endpoints.map((e) => h('div', { class: 'mono' }, e.address, h('span', { class: 'muted' }, ` ${e.kind}`)))),
        h('div', { class: 'stack-sm' }, h('div', { class: 'chips' }, (p.roles || []).map((r) => badge(...(ROLE[r] || [r, '']))), p.gossip ? badge('gossip', 'mono') : null), rtt(p.rtt_ms)),
        h('div', { class: 'small muted nowrap' }, p.valid_until ? [`до ${fmtDate(p.valid_until)}`, h('div', {}, `seq ${p.seq}`)] : '')))
        : empty('network', peers.source === 'none' ? 'Mesh не включён' : 'Соседей пока нет',
          peers.source === 'none' ? 'Запустите узел с --mesh-enabled или в режиме роя (--swarm-key), чтобы он находил другие узлы.'
            : isDir ? 'Добавьте соседа по его самоописанию — дальше узлы обмениваются записями сами.' : 'Каталог пиров приходит с control-plane; пока он пуст.',
          isDir ? btn({ label: 'Добавить соседа', icon: 'plus', variant: 'primary', onclick: addSeed }) : null));
  };

  async function load() {
    const [n, p] = await Promise.all([api('GET', 'node'), api('GET', 'node/peers')]);
    if (!alive) return;
    node = n; peers = p;
    renderOwn(); renderCfg(); renderPeers(); renderDesc();
  }
  act(load);
  return { el, dispose: () => { alive = false; } };
}
