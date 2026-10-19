// Сети и доступ: ключи mesh-сетей, доверенности (выдача, передоверие, продление, ротация, отзыв).
import { api, nav, store } from './api.js';
import { h, icon, btn, iconBtn, badge, field, notice, empty, skeleton, secret, eyebrow, dialog, confirmDialog, menu, toast, copy, download, act, closeDialog, fmtDate, fmtDay, rel, short, initials, plural, put } from './ui.js';

export const ROLE_HINT = {
  client: 'Клиент (лист): пользуется сетью', guard: 'Друг-сторож: вход по приглашению', relay: 'Ретранслятор: средний хоп',
  egress: 'Выход: выпускает трафик в интернет', operator: 'Оператор узлов',
};
const ALL_ROLES = ['client', 'guard', 'relay', 'egress', 'operator'];
const PRESETS = [
  { id: 'client', title: 'Клиент', desc: 'Устройство или человек, который пользуется сетью', roles: ['client'], ttl: 720, delegate: 0 },
  { id: 'guard', title: 'Друг-сторож', desc: 'Принимает клиентов и может приглашать', roles: ['client', 'guard'], ttl: 2160, delegate: 1 },
  { id: 'relay', title: 'Ретранслятор', desc: 'Узел-посредник в цепочке', roles: ['relay'], ttl: 2160, delegate: 0 },
  { id: 'egress', title: 'Выход', desc: 'Выпускает трафик в интернет', roles: ['egress'], ttl: 720, delegate: 0 },
  { id: 'operator', title: 'Оператор', desc: 'Полный доступ к сети', roles: ALL_ROLES, ttl: 8760, delegate: 2 },
  { id: 'custom', title: 'Своя', desc: 'Роли и срок вручную', roles: ['client'], ttl: 720, delegate: 0 },
];
const TTLS = [[24, '1 день'], [168, '7 дней'], [720, '30 дней'], [2160, '90 дней'], [8760, '1 год']];
const DAY = 86400;
const STATE = { active: ['действует', 'ok'], stale: ['старый корень', 'warn'], expired: ['истекла', ''], revoked: ['отозвана', 'bad'], invalid: ['ошибка проверки', 'bad'] };
const ui = { q: '', filter: 'all' };

const refresh = () => nav(location.hash || '#/meshes');

// ── токен ──────────────────────────────────────────────────────────────────

export function showToken(title, token, extra, fileLabel = 'token') {
  const ta = h('textarea', { readOnly: true, rows: 6, 'aria-label': 'Токен' });
  ta.value = token;
  dialog({
    title, wide: false,
    body: h('div', { class: 'stack-sm' }, extra || null, ta,
      notice('warn', 'Токен содержит ключ держателя и цепочку полномочий. Передавайте его по защищённому каналу: кто получил токен, тот действует в рамках этой доверенности.')),
    actions: [
      { label: 'Скачать', icon: 'download', run: async () => { download(`${fileLabel}.nrxp-cap.txt`, token + '\n', 'text/plain'); return false; } },
      { label: 'Копировать', icon: 'copy', variant: 'primary', run: async () => { await copy(token, 'Токен скопирован'); return false; } },
    ],
  });
  ta.select();
}

// ── выдача доступа ─────────────────────────────────────────────────────────

/** Диалог выдачи. `parent` — доверенность-родитель (передоверие), `meshId` — сеть. */
export async function openIssue({ meshId, parent, mesh, presetId } = {}) {
  const [list, peers] = await act(() => Promise.all([api('GET', 'meshes'), api('GET', 'node/peers').catch(() => ({ peers: [] }))])) || [];
  if (!list) return;
  if (!list.meshes.length) { toast('Сначала создайте сеть', 'bad'); nav('#/meshes'); return; }
  const meshSel = h('select', { 'aria-label': 'Сеть' }, list.meshes.map((m) => h('option', { value: m.id, selected: m.id === (meshId || list.meshes[0].id) }, m.name)));
  const label = h('input', { type: 'text', maxlength: 80, placeholder: parent ? `Под-доверенность от «${parent.label}»` : 'Имя, устройство или организация' });
  const note = h('input', { type: 'text', maxlength: 500, placeholder: 'Заметка (необязательно)' });

  const allowed = parent ? parent.roles : ALL_ROLES;
  const maxDelegate = parent ? parent.delegate - 1 : (store.status?.max_chain ?? 4) - 1;
  const parentHours = parent ? Math.floor((parent.exp - Date.now() / 1000) / 3600) : Infinity;
  const fits = (p) => p.id === 'custom' || p.roles.every((r) => allowed.includes(r));

  let preset = PRESETS.find((p) => p.id === presetId && fits(p)) || PRESETS.find((p) => fits(p) && p.id !== 'custom') || PRESETS.at(-1);
  let ttl = Math.min(preset.ttl, parentHours);
  const roleBoxes = ALL_ROLES.map((r) => ({ r, box: h('input', { type: 'checkbox', disabled: !allowed.includes(r) }) }));
  const delegate = h('input', { type: 'number', min: 0, max: Math.max(0, maxDelegate), value: 0, style: 'width:90px' });
  const ttlInput = h('input', { type: 'number', min: 1, max: 8760, style: 'width:110px', 'aria-label': 'Срок в часах' });
  const presetGrid = h('div', { class: 'preset-grid' });
  const ttlChips = h('div', { class: 'chips' });

  const apply = (p) => {
    preset = p;
    roleBoxes.forEach(({ r, box }) => (box.checked = p.roles.includes(r) && allowed.includes(r)));
    delegate.value = Math.min(p.delegate, Math.max(0, maxDelegate));
    ttl = Math.min(p.ttl, parentHours);
    draw();
  };
  const draw = () => {
    put(presetGrid, ...PRESETS.map((p) => h('button', { class: 'preset', type: 'button', 'aria-pressed': String(p.id === preset.id), disabled: !fits(p), onclick: () => apply(p) }, h('strong', {}, p.title), h('span', {}, p.desc))));
    put(ttlChips, ...TTLS.filter(([hrs]) => hrs <= parentHours).map(([hrs, t]) => h('button', { class: 'chip', type: 'button', 'aria-pressed': String(hrs === ttl), onclick: () => { ttl = hrs; draw(); } }, t)));
    ttlInput.value = ttl;
  };
  ttlInput.addEventListener('input', () => { ttl = Number(ttlInput.value) || 0; ttlChips.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-pressed', 'false')); });
  apply(preset);

  const known = (peers.peers || []).map((p) => p.node_id);
  const picks = known.map((id) => ({ id, box: h('input', { type: 'checkbox' }) }));
  const manual = h('textarea', { rows: 2, placeholder: 'или вручную: node_id (32 hex), по одному в строке' });
  const nodesBlock = h('div', { class: 'stack-sm' },
    picks.length ? h('div', { class: 'node-pick' }, picks.map(({ id, box }) => h('label', {}, box, h('span', { class: 'mono' }, id)))) : null, manual,
    parent?.nodes ? h('p', { class: 'muted small' }, `Родитель ограничен узлами: ${parent.nodes.length}. Потомок может получить только их подмножество.`) : null);

  dialog({
    title: parent ? `Передоверие от «${parent.label}»` : 'Выдать доступ', wide: true,
    body: h('div', { class: 'stack' },
      !parent && list.meshes.length > 1 ? field('Сеть', meshSel) : null,
      h('div', { class: 'grid cols-2' }, field('Кому', label), field('Заметка', note)),
      h('div', { class: 'stack-sm' }, h('span', { class: 'label-text' }, 'Что разрешено'), presetGrid),
      h('div', { class: 'stack-sm' }, h('span', { class: 'label-text' }, 'Срок действия'), ttlChips),
      h('details', { class: 'adv' }, h('summary', {}, icon('gear', 'sm'), 'Дополнительно: роли, узлы, передоверие'),
        h('div', { class: 'stack' },
          h('div', { class: 'stack-sm' }, h('span', { class: 'label-text' }, 'Роли'), h('div', { class: 'check-row' }, roleBoxes.map(({ r, box }) => h('label', { title: ROLE_HINT[r] }, box, r)))),
          h('div', { class: 'stack-sm' }, h('span', { class: 'label-text' }, 'Ограничить узлами (пусто — любые узлы сети)'), nodesBlock),
          h('div', { class: 'row' }, field(`Глубина передоверия (0–${Math.max(0, maxDelegate)})`, delegate), field('Срок, часов', ttlInput))))),
    actions: [{
      label: 'Выдать', icon: 'key', variant: 'primary',
      run: async () => {
        const nodes = [...picks.filter(({ box }) => box.checked).map(({ id }) => id), ...manual.value.split(/[\s,]+/).filter(Boolean)];
        const roles = roleBoxes.filter(({ box }) => box.checked).map(({ r }) => r);
        const id = parent ? mesh : meshSel.value;
        const r = await api('POST', `meshes/${id}/grants`, { label: label.value, note: note.value, parent: parent?.serial ?? null, roles, nodes: nodes.length ? nodes : null, ttl_hours: ttl, delegate: Number(delegate.value) || 0 });
        refresh();
        setTimeout(() => showToken(`Доступ выдан: ${label.value.trim()}`, r.token, null, label.value.trim() || 'grant'), 0);
      },
    }],
  });
}

// ── действия над доверенностью ─────────────────────────────────────────────

function revokeDialog(g) {
  const reason = h('input', { type: 'text', maxlength: 120, placeholder: 'Причина (необязательно, попадёт в список отзывов)' });
  dialog({
    title: `Отозвать «${g.label}»`,
    body: h('div', { class: 'stack-sm' }, h('p', {}, 'Доверенность и все выданные от неё передоверия перестанут проходить проверку. Это необратимо.'), reason),
    actions: [{ label: 'Отозвать', icon: 'x', variant: 'danger solid', run: async () => { await api('POST', `grants/${g.serial}/revoke`, { reason: reason.value }); toast('Отозвано'); refresh(); } }],
  });
}

async function rotateGrant(g) {
  if (!(await confirmDialog({ title: `Ротировать «${g.label}»`, text: 'Будет выпущен новый ключ и серийный номер, прежний токен отзовётся. Потомки останутся действующими, но их токены нужно будет выдать заново.', confirmLabel: 'Ротировать', danger: true }))) return;
  const r = await act(() => api('POST', `grants/${g.serial}/rotate`));
  if (!r) return;
  refresh();
  setTimeout(() => showToken(`Новый токен: ${g.label}`, r.token, r.children_to_redistribute ? notice('warn', `Потомков, которым нужно выдать токены заново: ${r.children_to_redistribute}.`) : null, g.label), 0);
}

function extendDialog(g, parentExp) {
  const maxH = parentExp ? Math.floor((parentExp - Date.now() / 1000) / 3600) : Infinity;
  let ttl = TTLS.filter(([hrs]) => hrs <= maxH).find(([hrs]) => hrs >= 720)?.[0] ?? TTLS.filter(([hrs]) => hrs <= maxH).at(-1)?.[0] ?? 24;
  const chips = h('div', { class: 'chips' });
  const warn = h('div', {});
  const draw = () => {
    put(chips, ...TTLS.filter(([hrs]) => hrs <= maxH).map(([hrs, t]) => h('button', { class: 'chip', type: 'button', 'aria-pressed': String(hrs === ttl), onclick: () => { ttl = hrs; draw(); } }, t)));
    const newExp = Date.now() / 1000 + ttl * 3600;
    put(warn, newExp < g.exp ? notice('warn', `Новый срок (${fmtDay(newExp)}) короче текущего — доверенность будет сокращена.`) : h('p', { class: 'muted small' }, `Новый срок: до ${fmtDay(newExp)}.`));
  };
  draw();
  dialog({
    title: `Продлить «${g.label}»`,
    body: h('div', { class: 'stack-sm' }, h('p', {}, `Сейчас действует до ${fmtDay(g.exp)}. Срок отсчитывается от сегодняшнего дня; ключ и серийный номер не меняются — раздавать заново обычно не нужно (новый токен — по кнопке «Токен»).`), chips, warn, maxH < 8760 && parentExp ? h('p', { class: 'muted small' }, 'Нельзя выйти за срок родительской доверенности.') : null),
    actions: [{ label: 'Продлить', icon: 'calendar', variant: 'primary', run: async () => { const r = await api('POST', `grants/${g.serial}/extend`, { ttl_hours: ttl }); toast(`Продлено до ${fmtDay(r.exp)}`); refresh(); } }],
  });
}

function detailsDialog(m, g) {
  const parent = g.parent ? m.grants.find((x) => x.serial === g.parent) : null;
  dialog({
    title: g.label, wide: true,
    body: h('dl', { class: 'kv' },
      h('dt', {}, 'Серийный номер'), h('dd', {}, secret(g.serial, 'Серийный номер скопирован')),
      h('dt', {}, 'Ключ держателя'), h('dd', {}, secret(g.holder, 'Публичный ключ скопирован')),
      h('dt', {}, 'Подписал'), h('dd', {}, parent ? `«${parent.label}»` : 'корень сети', ' ', h('code', { class: 'mono muted' }, short(g.issuer, 8))),
      h('dt', {}, 'Цепочка'), h('dd', {}, g.chain.map((s) => h('code', { class: 'mono' }, short(s, 5))).flatMap((n, i) => (i ? [' → ', n] : [n]))),
      h('dt', {}, 'Роли'), h('dd', {}, h('div', { class: 'chips' }, g.roles.map((r) => badge(r, 'primary', ROLE_HINT[r])))),
      h('dt', {}, 'Узлы'), h('dd', {}, g.nodes ? g.nodes.map((n) => h('div', { class: 'mono' }, n)) : 'любые узлы сети'),
      h('dt', {}, 'Действует'), h('dd', {}, `${fmtDate(g.nbf)} — ${fmtDate(g.exp)}`),
      h('dt', {}, 'Передоверие'), h('dd', {}, g.delegate ? `ещё ${g.delegate} ур.` : 'не разрешено'),
      h('dt', {}, 'Корень'), h('dd', {}, `эпоха ${g.root_epoch}`),
      g.note ? [h('dt', {}, 'Заметка'), h('dd', {}, g.note)] : null),
  });
}

function metaDialog(g) {
  const label = h('input', { type: 'text', maxlength: 80, value: g.label });
  const note = h('textarea', { rows: 3, maxlength: 500 });
  note.value = g.note || '';
  dialog({
    title: 'Изменить доверенность', body: h('div', { class: 'stack' }, field('Метка', label), field('Заметка', note)),
    actions: [{ label: 'Сохранить', variant: 'primary', run: async () => { await api('POST', `grants/${g.serial}/meta`, { label: label.value, note: note.value }); refresh(); } }],
  });
}

// ── сеть: создание, ротации ────────────────────────────────────────────────

function createMeshDialog() {
  const name = h('input', { type: 'text', maxlength: 64, placeholder: 'Например: office, family, prod' });
  const isSwarm = store.node?.mode === 'swarm';
  let source = 'new';
  const own = h('input', { type: 'text', class: 'mono', placeholder: '64 hex-символа', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Ключ роя' });
  const ownField = h('div', { hidden: true }, field('Ключ роя', own));
  const options = [['new', 'Сгенерировать новый', 'Для новой сети: узлы потом запускаются с этим ключом'], ...(isSwarm ? [['node', 'Ключ этого узла', 'Подхватить рой, в котором узел уже работает']] : []), ['own', 'Вставить свой', 'Ключ существующей сети (PROXY_SWARM_KEY)']];
  const radios = h('div', { class: 'stack-sm' });
  const draw = () => {
    put(radios, ...options.map(([v, t, d]) => h('label', { class: 'preset', style: 'cursor:pointer', 'aria-pressed': String(source === v) }, h('span', { class: 'row', style: 'gap:8px' }, h('input', { type: 'radio', name: 'key-src', checked: source === v, onclick: () => { source = v; draw(); } }), h('strong', {}, t)), h('span', {}, d))));
    ownField.hidden = source !== 'own';
  };
  draw();
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') e.target.closest('dialog').querySelector('.btn.primary').click(); });
  dialog({
    title: 'Новая сеть',
    body: h('div', { class: 'stack' }, field('Название', name), h('div', { class: 'stack-sm' }, h('span', { class: 'label-text' }, 'Ключ роя'), radios, ownField),
      h('p', { class: 'muted small' }, 'Вместе с сетью создаётся корень доверенностей — им подписывается выдаваемый доступ.')),
    actions: [{ label: 'Создать', icon: 'plus', variant: 'primary', run: async () => {
      const r = await api('POST', 'meshes', { name: name.value, from_node: source === 'node', swarm_key: source === 'own' ? own.value : null });
      toast('Сеть создана'); nav(`#/meshes/${r.id}`);
    } }],
  });
}

function rotateDialog(m, kind) {
  const isSwarm = kind === 'swarm';
  const grace = h('input', { type: 'number', min: 0, max: 2160, value: isSwarm ? 24 : 72, style: 'width:110px' });
  dialog({
    title: isSwarm ? 'Ротация ключа роя' : 'Ротация корня доверенностей',
    body: h('div', { class: 'stack' },
      notice('warn', isSwarm
        ? 'Узлы со старым ключом перестанут проходить входной барьер узлов с новым: каждый узел нужно перезапустить с новым PROXY_SWARM_KEY.'
        : 'Выданные доверенности остаются действующими только в переходный период, затем их нужно перевыпустить и раздать токены заново. Ноль — отозвать всё сразу.'),
      field(isSwarm ? 'Помнить прежний ключ, часов (справочно)' : 'Переходный период, часов (0 — без перехода)', grace)),
    actions: [{ label: 'Ротировать', icon: 'refresh', variant: 'danger solid', run: async () => { await api('POST', `meshes/${m.id}/rotate-${kind}`, { grace_hours: Number(grace.value) || 0 }); toast('Ключ заменён'); refresh(); } }],
  });
}

// ── представление ──────────────────────────────────────────────────────────

const TABS = [['access', 'Доступ', 'key'], ['keys', 'Ключи', 'shield'], ['revoked', 'Отзывы', 'x'], ['settings', 'Настройки', 'gear']];

export function meshesView({ id, tab }) {
  const root = h('div', { class: 'stack' }, skeleton(40, '50%'), skeleton(120), skeleton(240));
  let alive = true;
  (async () => {
    const list = await act(() => api('GET', 'meshes'));
    if (!alive || !list) return;
    const meshes = list.meshes;
    const head = h('div', { class: 'page-head' }, h('div', { class: 'titles' }, eyebrow('сети и доступ'), h('h1', {}, 'Доступ к mesh-сетям')),
      btn({ label: 'Новая сеть', icon: 'plus', variant: meshes.length ? '' : 'primary', onclick: createMeshDialog }));
    if (!meshes.length) {
      put(root, head, h('section', { class: 'card' }, empty('network', 'Создайте первую mesh-сеть',
        'У сети есть ключ роя — общий секрет узлов, и корень доверенностей — им подписывается выдаваемый доступ. Всё хранится локально, в каталоге данных панели.',
        btn({ label: 'Создать сеть', icon: 'plus', variant: 'primary', onclick: createMeshDialog }))));
      return;
    }
    const sel = meshes.find((m) => m.id === id) || meshes[0];
    const m = await act(() => api('GET', `meshes/${sel.id}`));
    if (!alive || !m) return;
    const t = TABS.some(([k]) => k === tab) ? tab : 'access';

    const switcher = meshes.length > 1 ? h('div', { class: 'chips' }, meshes.map((x) => h('a', { class: 'chip', href: `#/meshes/${x.id}`, 'aria-pressed': String(x.id === m.id), style: 'text-decoration:none' }, x.name))) : null;
    const nodeBadge = m.on_this_node === 'current' ? badge('работает на этом узле', 'ok') : m.on_this_node === 'previous' ? badge('узел на прежнем ключе', 'warn') : null;
    const summary = h('div', { class: 'grid cols-4 keep-2' },
      stat('Действуют', m.counts.active + m.counts.stale, 'доверенностей'), stat('Истекают', m.expiring, 'в ближайшие 7 дней', m.expiring ? 'warn' : ''),
      stat('Отозвано', m.revoked_total, 'всего'), stat('Ключи', `#${m.swarm_epoch}`, `роя · корень #${m.root_epoch}`));
    const tabs = h('div', { class: 'segmented', role: 'tablist' }, TABS.map(([k, l, ic]) => h('button', { type: 'button', role: 'tab', 'aria-pressed': String(k === t), onclick: () => nav(`#/meshes/${m.id}/${k}`) }, icon(ic, 'sm'), l)));
    const body = { access: () => accessTab(m), keys: () => keysTab(m), revoked: () => revokedTab(m), settings: () => settingsTab(m) }[t]();
    put(root, ...[head, switcher, h('div', { class: 'row' }, h('h2', { style: 'font-size:20px' }, m.name), nodeBadge, badge(`ключ ${m.swarm_fp}`, 'mono', 'Отпечаток ключа роя — для сверки'), m.note ? h('span', { class: 'muted small' }, m.note) : null), summary, tabs, body].filter(Boolean));
  })();
  return { el: root, dispose: () => { alive = false; } };
}

function stat(label, value, hint, kind = '') {
  return h('div', { class: 'card tile' }, h('span', { class: 'label' }, label), h('div', { class: 'value', style: kind === 'warn' ? 'color:var(--warn)' : '' }, String(value)), h('div', { class: 'hint' }, hint));
}

// Доступ -------------------------------------------------------------------

function accessTab(m) {
  const list = h('div', {});
  const now = Date.now() / 1000;
  const usable = (g) => g.state === 'active' || g.state === 'stale';
  const filters = [
    ['all', 'Все', () => true], ['active', 'Действуют', usable],
    ['expiring', 'Истекают', (g) => usable(g) && g.exp - now <= 7 * DAY], ['inactive', 'Не действуют', (g) => !usable(g)],
  ];
  const chips = h('div', { class: 'chips' });
  const search = h('input', { type: 'search', 'data-search': '1', placeholder: 'Поиск по метке, заметке, роли…', value: ui.q, 'aria-label': 'Поиск' });
  const draw = () => {
    const f = filters.find(([k]) => k === ui.filter) || filters[0];
    const q = ui.q.trim().toLowerCase();
    const shown = m.grants.filter(f[2]).filter((g) => !q || [g.label, g.note, g.serial, ...g.roles].join(' ').toLowerCase().includes(q));
    put(chips, ...filters.map(([k, l, fn]) => h('button', { class: 'chip', type: 'button', 'aria-pressed': String(k === ui.filter), onclick: () => { ui.filter = k; draw(); } }, l, h('span', { class: 'count' }, m.grants.filter(fn).length))));
    const tree = ui.filter === 'all' && !q;
    put(list, ...(shown.length ? orderGrants(shown, tree).map(([g, depth]) => grantRow(m, g, tree ? depth : 0)) : [m.grants.length
      ? empty('search', 'Ничего не найдено', 'Измените фильтр или строку поиска.')
      : empty('key', 'Доступ ещё не выдавали', 'Выдайте первую доверенность: она подписывается корнем сети, а получатель может проверить её офлайн.', btn({ label: 'Выдать доступ', icon: 'key', variant: 'primary', onclick: () => openIssue({ meshId: m.id, mesh: m.id }) }))]));
  };
  search.addEventListener('input', () => { ui.q = search.value; draw(); });
  const presetsMenu = (e) => menu(e.currentTarget, PRESETS.filter((p) => p.id !== 'custom').map((p) => ({ label: p.title, desc: p.desc, icon: 'key', onclick: () => openIssue({ meshId: m.id, mesh: m.id, presetId: p.id }) })));
  const toolbar = h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search', 'sm'), search), chips,
    h('div', { class: 'grow' }),
    h('div', { class: 'btn-split' }, btn({ label: 'Выдать доступ', icon: 'key', variant: 'primary', onclick: () => openIssue({ meshId: m.id, mesh: m.id }) }),
      h('button', { class: 'btn primary', type: 'button', title: 'Выбрать тип доступа', 'aria-label': 'Выбрать тип доступа', onclick: presetsMenu }, icon('down', 'sm'))));
  draw();
  return h('div', { class: 'stack' },
    notice('info', 'Доверенности подписываются и проверяются панелью. Узлы пока не проверяют их при подключении (этап B децентрализации) — токены уже можно выдавать, отзывать и ротировать.'),
    h('section', { class: 'card flush' }, toolbar, list));
}

function orderGrants(grants, tree) {
  if (!tree) return grants.map((g) => [g, 0]);
  const kids = new Map();
  for (const g of grants) (kids.get(g.parent || '') || kids.set(g.parent || '', []).get(g.parent || '')).push(g);
  const out = [], seen = new Set();
  const walk = (p, d) => (kids.get(p) || []).forEach((g) => { out.push([g, d]); seen.add(g.serial); walk(g.serial, d + 1); });
  walk('', 0);
  grants.filter((g) => !seen.has(g.serial)).forEach((g) => out.push([g, 0]));
  return out;
}

function grantRow(m, g, depth) {
  const now = Date.now() / 1000;
  const [stLabel, stKind] = STATE[g.state] || [g.state, ''];
  const ok = g.state === 'active' || g.state === 'stale';
  const total = Math.max(1, g.exp - g.nbf), left = Math.max(0, Math.min(1, (g.exp - now) / total));
  const soon = ok && g.exp - now <= 7 * DAY;
  const parentExp = g.parent ? m.grants.find((x) => x.serial === g.parent)?.exp : null;
  const acts = () => menu(kebab, [
    { label: 'Передоверить', desc: g.delegate ? `ещё ${g.delegate} ур.` : 'не разрешено', icon: 'branch', onclick: () => (g.delegate ? openIssue({ meshId: m.id, mesh: m.id, parent: g }) : toast('Передоверие для этой доверенности не разрешено', 'bad')) },
    { label: 'Продлить срок', icon: 'calendar', onclick: () => extendDialog(g, parentExp) },
    { label: 'Изменить метку и заметку', icon: 'edit', onclick: () => metaDialog(g) },
    { label: 'Подробности', icon: 'info', onclick: () => detailsDialog(m, g) },
    { label: 'Ротировать ключ', icon: 'refresh', onclick: () => rotateGrant(g) },
    'sep', { label: 'Отозвать…', icon: 'x', danger: true, onclick: () => revokeDialog(g) },
  ]);
  const kebab = iconBtn('more', 'Действия', acts);
  if (!ok) kebab.disabled = true;
  const scope = g.nodes ? `${g.nodes.length} ${plural(g.nodes.length, 'узел', 'узла', 'узлов')}` : 'любые узлы';
  return h('div', { class: 'grant', style: `--depth:${depth};--tree:${depth ? 'block' : 'none'}` },
    h('div', { class: 'who' }, h('div', { class: `avatar ${ok ? (g.delegate ? 'violet' : '') : 'off'}` }, initials(g.label)),
      h('div', { class: 'who-text' }, h('strong', {}, g.label), h('div', { class: 'muted small' }, short(g.serial, 5), g.note ? ` · ${g.note}` : ''))),
    h('div', { class: 'roles stack-sm' }, h('div', { class: 'chips' }, g.roles.map((r) => badge(r, 'primary', ROLE_HINT[r])), g.delegate ? badge(`передоверие ${g.delegate}`, 'violet', 'Может выдавать доступ дальше') : null), h('div', { class: 'muted small' }, scope)),
    h('div', { class: 'expiry' }, h('div', { class: 'row', style: 'gap:6px' }, badge(stLabel, stKind, g.reason), ok ? h('span', { class: 'small muted' }, `до ${fmtDay(g.exp)} · ${rel(g.exp)}`) : h('span', { class: 'small muted' }, g.reason || '')),
      ok ? h('div', { class: `bar ${soon ? 'warn' : ''}` }, h('i', { style: `width:${(left * 100).toFixed(1)}%` })) : null),
    h('div', { class: 'acts' }, btn({ label: 'Токен', icon: 'key', size: 'sm', disabled: !ok, onclick: () => act(async () => showToken(`Токен: ${g.label}`, (await api('GET', `grants/${g.serial}/token`)).token, null, g.label)) }), kebab));
}

// Ключи ---------------------------------------------------------------------

function keysTab(m) {
  const slot = h('div', {});
  let shown = false;
  const reveal = async (b) => {
    if (shown) { put(slot, ); shown = false; put(b, icon('eye', 'sm'), 'Показать ключ'); return; }
    const k = await act(() => api('GET', `meshes/${m.id}/swarm-key`));
    if (!k) return;
    put(slot, h('div', { class: 'stack-sm', style: 'margin-top:12px' }, secret(k.swarm_key, 'Ключ роя скопирован'),
      h('div', { class: 'row' }, btn({ label: 'PROXY_SWARM_KEY=…', icon: 'copy', size: 'sm', onclick: () => copy(`PROXY_SWARM_KEY=${k.swarm_key}`, 'Скопировано как переменная окружения') })),
      k.previous ? h('p', { class: 'muted small' }, `Прежний ключ (эпоха ${m.swarm_epoch - 1}) помечен переходным до ${fmtDate(k.previous.until)}.`) : null));
    shown = true; put(b, icon('eyeoff', 'sm'), 'Скрыть ключ');
  };
  const showBtn = btn({ label: 'Показать ключ', icon: 'eye', onclick: (e) => reveal(e.currentTarget) });
  const swarm = h('section', { class: 'card stack-sm' },
    h('div', { class: 'card-head' }, h('h2', {}, 'Ключ доступа сети (ключ роя)'), badge(`эпоха ${m.swarm_epoch}`), m.swarm_prev_until ? badge(`переход до ${fmtDay(m.swarm_prev_until)}`, 'warn') : null),
    h('p', { class: 'muted' }, 'Общий секрет сети: из него узлы выводят входные секреты друг друга (PROXY_SWARM_KEY). Утечка снимает входной барьер всей сети — ротируйте при подозрении.'),
    h('dl', { class: 'kv' }, h('dt', {}, 'Отпечаток'), h('dd', {}, h('code', { class: 'mono' }, m.swarm_fp))),
    h('div', { class: 'row' }, showBtn, btn({ label: 'Ротировать…', icon: 'refresh', variant: 'danger', onclick: () => rotateDialog(m, 'swarm') })), slot,
    h('details', { class: 'adv' }, h('summary', {}, icon('help', 'sm'), 'Как применить новый ключ'),
      h('ol', { class: 'steps' }, h('li', {}, 'Скопируйте ключ («Показать ключ» → «PROXY_SWARM_KEY=…»).'), h('li', {}, 'На каждом узле сети замените PROXY_SWARM_KEY в окружении (systemd drop-in, .env или docker env).'), h('li', {}, 'Перезапустите узел — ключ роя читается при старте.'), h('li', {}, 'Вернитесь сюда: на нужной сети должен гореть бейдж «работает на этом узле».'))));

  const root = h('section', { class: 'card stack-sm' },
    h('div', { class: 'card-head' }, h('h2', {}, 'Корень доверенностей'), badge(`эпоха ${m.root_epoch}`)),
    h('p', { class: 'muted' }, 'Ключ, которым подписан выданный доступ. Публичная часть — то, чем узлы проверяют доверенности; секретная не покидает панель.'),
    h('dl', { class: 'kv' }, h('dt', {}, 'Отпечаток'), h('dd', {}, h('code', { class: 'mono' }, m.root_fp)), h('dt', {}, 'Публичный ключ'), h('dd', {}, secret(m.root_public, 'Публичный ключ скопирован')),
      m.root_prev.length ? [h('dt', {}, 'Прежние корни'), h('dd', {}, m.root_prev.map((r) => h('div', {}, `эпоха ${r.epoch} — принимается до ${fmtDate(r.until)}`)))] : null),
    h('div', { class: 'row' }, btn({ label: 'Ротировать корень…', icon: 'refresh', variant: 'danger', onclick: () => rotateDialog(m, 'root') }),
      btn({ label: `Перевыпустить цепочки${m.counts.stale ? ` (${m.counts.stale})` : ''}`, icon: 'history', disabled: !m.counts.stale, onclick: () => act(async () => { await api('POST', `meshes/${m.id}/reissue`); toast('Цепочки перевыпущены — раздайте токены заново'); refresh(); }) }),
      btn({ label: 'Публичный набор для узлов', icon: 'download', onclick: () => act(async () => bundleDialog(await api('GET', `meshes/${m.id}/bundle`))) })));
  return h('div', { class: 'grid cols-2' }, swarm, root);
}

function bundleDialog(b) {
  const ta = h('textarea', { readOnly: true, rows: 10 });
  ta.value = JSON.stringify(b, null, 2);
  dialog({ title: 'Публичный набор', body: h('div', { class: 'stack-sm' }, h('p', { class: 'muted' }, 'Доверенные корни и отозванные серийные номера — для узлов, которые будут проверять доверенности. Секретов здесь нет.'), ta),
    actions: [{ label: 'Скачать', icon: 'download', run: async () => { download(`bundle-${b.mesh}.json`, ta.value); return false; } }, { label: 'Копировать', icon: 'copy', variant: 'primary', run: async () => { await copy(ta.value); return false; } }] });
}

// Отзывы --------------------------------------------------------------------

function revokedTab(m) {
  return h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', {}, 'Список отзывов'), h('span', { class: 'muted small' }, 'Эти серийные номера узлы должны считать недействительными')),
    m.revoked.length ? m.revoked.map((r) => h('div', { class: 'list-row', style: 'grid-template-columns:minmax(0,1.4fr) minmax(0,1.6fr) auto' }, h('div', { class: 'who-text' }, h('strong', {}, r.label || '—'), h('div', { class: 'muted small mono' }, r.serial)), h('span', { class: 'muted' }, r.reason), h('span', { class: 'muted small nowrap' }, fmtDate(r.at))))
      : empty('check', 'Отзывов нет', 'Отозванные и ротированные доверенности появятся здесь.'));
}

// Настройки -----------------------------------------------------------------

function settingsTab(m) {
  const name = h('input', { type: 'text', maxlength: 64, value: m.name });
  const note = h('textarea', { rows: 3, maxlength: 500 });
  note.value = m.note || '';
  return h('div', { class: 'stack' },
    h('section', { class: 'card stack' }, h('div', { class: 'card-head' }, h('h2', {}, 'Название и заметка')),
      h('div', { class: 'grid cols-2' }, field('Название', name), field('Заметка', note)),
      h('div', { class: 'row' }, btn({ label: 'Сохранить', variant: 'primary', onclick: () => act(async () => { await api('POST', `meshes/${m.id}/rename`, { name: name.value, note: note.value }); toast('Сохранено'); refresh(); }) }))),
    h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', { style: 'color:var(--bad)' }, 'Удаление сети')),
      h('p', { class: 'muted' }, 'Удаляет ключи и все доверенности из хранилища панели. Работающие узлы не затрагиваются, но выданный доступ станет непроверяемым. Сделайте резервную копию заранее.'),
      btn({ label: 'Удалить сеть…', icon: 'trash', variant: 'danger', onclick: async () => { if (await confirmDialog({ title: `Удалить «${m.name}»`, text: 'Ключи и доверенности будут удалены безвозвратно.', confirmLabel: 'Удалить', danger: true, type: m.name })) act(async () => { await api('POST', `meshes/${m.id}/delete`, { confirm: m.name }); toast('Сеть удалена'); nav('#/meshes'); }); } })));
}
