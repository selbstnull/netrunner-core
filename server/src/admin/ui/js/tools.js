// Инструменты из бургер-меню: проверка токена, журнал, резервная копия, конфигурация узла,
// безопасность панели и остановка узла — важное, но не ежедневное.
import { api, store, nav } from './api.js';
import { h, icon, btn, badge, field, notice, empty, skeleton, secret, eyebrow, dialog, confirmDialog, toast, copy, download, act, fmtDate, fmtDay, rel, short, put } from './ui.js';
import { ROLE_HINT } from './meshes.js';
import { getAutolock, setAutolock, logout } from './main.js';

export const TOOLS = {
  verify: { title: 'Проверка токена', desc: 'Проверить доверенность офлайн', icon: 'shield' },
  audit: { title: 'Журнал действий', desc: 'Кто и что менял', icon: 'file' },
  backup: { title: 'Резервная копия', desc: 'Экспорт и восстановление ключей', icon: 'database' },
  metrics: { title: 'Метрики процесса', desc: 'Счётчики узла без внешнего Prometheus', icon: 'activity' },
  config: { title: 'Конфигурация узла', desc: 'Эффективные флаги и уровень логов', icon: 'gear' },
  security: { title: 'Безопасность панели', desc: 'Токен, автоблокировка, доступ', icon: 'lock' },
};

const ACTIONS = {
  'mesh.create': 'Создана сеть', 'mesh.delete': 'Удалена сеть', 'mesh.rename': 'Сеть переименована', 'mesh.rotate-swarm': 'Ротация ключа роя',
  'mesh.rotate-root': 'Ротация корня доверенностей', 'mesh.reissue': 'Перевыпуск цепочек', 'mesh.swarm-key.view': 'Просмотр ключа роя',
  'grant.issue': 'Выдан доступ', 'grant.revoke': 'Доступ отозван', 'grant.rotate': 'Ротация доверенности', 'grant.extend': 'Доступ продлён',
  'grant.meta': 'Изменена доверенность', 'grant.token.view': 'Просмотр токена', 'admin-token.rotate': 'Смена токена панели',
  'backup.export': 'Снята резервная копия', 'backup.restore': 'Восстановление из копии', 'node.seed.add': 'Добавлен сосед',
  'node.directory.gc': 'Очистка каталога', 'node.client-config.view': 'Выдан клиентский конфиг', 'node.log-level': 'Изменён уровень логов', 'node.shutdown': 'Остановка узла',
};
export const actionLabel = (a) => ACTIONS[a] || a;

/** Человекочитаемые подробности записи журнала (в файле они — служебные key=value). */
export function detailText(e) {
  const kv = Object.fromEntries([...(e.detail || '').matchAll(/(\w+)=(.*?)(?=\s\w+=|$)/g)].map((m) => [m[1], m[2]]));
  switch (e.action) {
    case 'grant.issue': return [kv.label, kv.parent && kv.parent !== '-' ? '(передоверие)' : ''].filter(Boolean).join(' ');
    case 'grant.extend': return kv.exp ? `до ${fmtDay(Number(kv.exp))}` : '';
    case 'grant.rotate': return kv.children && kv.children !== '0' ? `потомков для перевыдачи: ${kv.children}` : '';
    case 'mesh.rotate-swarm': case 'mesh.rotate-root': return parseInt(kv.grace) ? `переход ${Math.round(parseInt(kv.grace) / 3600)} ч` : 'без перехода';
    case 'mesh.reissue': return kv.grants ? `доверенностей: ${kv.grants}` : '';
    case 'backup.export': case 'backup.restore': return kv.meshes ? `сетей: ${kv.meshes}` : '';
    case 'node.directory.gc': return kv.removed ? `удалено: ${kv.removed}` : '';
    default: return e.detail || '';
  }
}
const CATS = [['all', 'Все', () => true], ['grant', 'Доступ', (a) => a.startsWith('grant.')], ['mesh', 'Сети и ключи', (a) => a.startsWith('mesh.')], ['node', 'Узел', (a) => a.startsWith('node.')], ['panel', 'Панель', (a) => a.startsWith('backup.') || a.startsWith('admin-')]];

export function toolView(name) {
  const t = TOOLS[name];
  const body = h('div', {}, skeleton(160));
  let alive = true;
  const ctx = { alive: () => alive };
  const builder = { verify, audit, backup, config, metrics, security }[name];
  Promise.resolve(builder(ctx)).then((el) => { if (alive) put(body, el); }).catch((e) => toast(e.message, 'bad'));
  return { el: h('div', { class: 'stack' }, h('div', { class: 'page-head' }, h('div', { class: 'titles' }, eyebrow('инструменты'), h('h1', {}, t.title), h('p', { class: 'muted' }, t.desc))), body), dispose: () => { alive = false; } };
}

// Проверка токена -----------------------------------------------------------

function verify() {
  const ta = h('textarea', { rows: 5, placeholder: 'nrxp-cap1.…', 'aria-label': 'Токен', spellcheck: 'false' });
  const out = h('div', { class: 'stack-sm', style: 'margin-top:14px' });
  const check = () => act(async () => {
    const r = await api('POST', 'verify', { token: ta.value });
    const e = r.effective;
    put(out, r.valid
      ? h('div', { class: 'card stack-sm' }, h('div', { class: 'row' }, badge('токен действителен', 'ok'), r.mesh ? badge(r.mesh.name, 'primary') : null),
        h('dl', { class: 'kv' },
          h('dt', {}, 'Роли'), h('dd', {}, h('div', { class: 'chips' }, e.roles.map((x) => badge(x, 'primary', ROLE_HINT[x])))),
          h('dt', {}, 'Узлы'), h('dd', {}, e.nodes ? e.nodes.map((n) => h('div', { class: 'mono' }, n)) : 'любые узлы сети'),
          h('dt', {}, 'Срок'), h('dd', {}, `${fmtDate(e.nbf)} — ${fmtDate(e.exp)} (${rel(e.exp)})`),
          h('dt', {}, 'Передоверие'), h('dd', {}, e.delegate ? `ещё ${e.delegate} ур.` : 'не разрешено'),
          h('dt', {}, 'Цепочка'), h('dd', {}, `${r.depth} зв.: ${r.serials.join(' → ')}`)))
      : h('div', { class: 'card stack-sm' }, h('div', { class: 'row' }, badge('токен не проходит проверку', 'bad')), h('p', {}, r.reason)));
  });
  return h('section', { class: 'card stack-sm' },
    h('p', { class: 'muted' }, 'Проверяет подписи цепочки, ослабление прав, сроки и отзыв — так, как это делал бы узел офлайн, зная только публичный корень сети.'),
    ta, h('div', { class: 'row' }, btn({ label: 'Проверить', icon: 'shield', variant: 'primary', onclick: check })), out);
}

// Журнал --------------------------------------------------------------------

async function audit() {
  const { entries } = await api('GET', 'audit');
  let cat = 'all', q = '';
  const list = h('div', {});
  const chips = h('div', { class: 'chips' });
  const search = h('input', { type: 'search', 'data-search': '1', placeholder: 'Поиск…', 'aria-label': 'Поиск', style: 'width:220px' });
  const draw = () => {
    const f = CATS.find(([k]) => k === cat)[2];
    const shown = entries.filter((e) => f(e.action)).filter((e) => !q || `${actionLabel(e.action)} ${e.target} ${e.detail}`.toLowerCase().includes(q));
    put(chips, ...CATS.map(([k, l, fn]) => h('button', { class: 'chip', type: 'button', 'aria-pressed': String(k === cat), onclick: () => { cat = k; draw(); } }, l, h('span', { class: 'count' }, entries.filter((e) => fn(e.action)).length))));
    put(list, ...(shown.length ? shown.map((e) => h('div', { class: 'audit-row' }, h('span', { class: 'muted small', title: fmtDate(e.ts) }, fmtDate(e.ts)), h('strong', {}, actionLabel(e.action)), h('span', { class: 'muted' }, [e.target ? h('code', { class: 'mono' }, short(e.target, 8)) : null, detailText(e) ? ` ${detailText(e)}` : ''])))
      : [empty('file', 'Записей нет', 'Здесь появятся все изменения: выдача, отзыв, ротации, просмотры секретов.')]));
  };
  search.addEventListener('input', () => { q = search.value.toLowerCase(); draw(); });
  draw();
  return h('section', { class: 'card flush' }, h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search', 'sm'), search), chips, h('div', { class: 'grow' }),
    btn({ label: 'Скачать', icon: 'download', size: 'sm', onclick: () => download(`netrunner-audit-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(entries, null, 2)) })), list);
}

// Метрики процесса ----------------------------------------------------------

const METRIC_GROUPS = [
  ['Соединения и сессии', /^netrunner_(connections|legs|leg_|sessions|vpn|stream|credit|datagram)/],
  ['Защита и маскировка', /^netrunner_(auth|scanner|nrxp|circuit)/],
  ['Mesh', /^netrunner_(mesh|mix|reverse)/],
  ['Каталог роя', /^netrunner_directory/],
  ['UDP', /^netrunner_udp/],
];
async function metrics() {
  const m = await api('GET', 'metrics');
  if (!m.available) return h('section', { class: 'card' }, empty('activity', 'Метрики не собираются', 'Рекордер метрик включается вместе с панелью управления — перезапустите узел с --admin-port.'));
  let q = '';
  const body = h('div', { class: 'stack' });
  const fmtV = (v) => (Number.isInteger(v) ? String(v) : v.toFixed(3));
  const draw = () => {
    const rows = m.metrics.filter((x) => !q || x.name.includes(q));
    const used = new Set();
    const groups = METRIC_GROUPS.map(([title, re]) => [title, rows.filter((x) => re.test(x.name) && !used.has(x.name) && used.add(x.name))]);
    groups.push(['Прочее', rows.filter((x) => !used.has(x.name))]);
    put(body, ...groups.filter(([, r]) => r.length).map(([title, r]) => h('section', { class: 'card flush' }, h('div', { class: 'card-head' }, h('h2', {}, title), badge(String(r.length))),
      r.map((x) => h('div', { class: 'list-row', style: 'grid-template-columns:1fr auto' }, h('code', { class: 'mono' }, x.name.replace('netrunner_', '')), h('strong', { class: 'mono' }, fmtV(x.value)))))));
    if (!rows.length) put(body, empty('search', 'Ничего не найдено', 'Измените строку поиска.'));
  };
  const search = h('input', { type: 'search', 'data-search': '1', placeholder: 'Фильтр по имени метрики…', 'aria-label': 'Фильтр', style: 'width:min(320px,100%)' });
  search.addEventListener('input', () => { q = search.value.trim().toLowerCase(); draw(); });
  draw();
  return h('div', { class: 'stack' }, h('div', { class: 'row' }, h('div', { class: 'search', style: 'flex:1 1 240px;max-width:340px' }, icon('search', 'sm'), search),
    h('span', { class: 'muted small' }, 'Суммы по меткам; значения за время работы процесса. Без привязки к клиентам.')), body);
}

// Резервная копия -----------------------------------------------------------

async function backup() {
  const st = await api('GET', 'status');
  store.status = st;
  const file = h('input', { type: 'file', accept: 'application/json,.json', 'aria-label': 'Файл копии' });
  const preview = h('div', {});
  let parsed = null;
  file.addEventListener('change', async () => {
    parsed = null; put(preview, );
    const f = file.files[0]; if (!f) return;
    try {
      parsed = JSON.parse(await f.text());
      const ms = parsed.state?.meshes ?? [];
      put(preview, notice('warn', `В копии: сетей — ${ms.length}, доверенностей — ${ms.reduce((a, m) => a + m.grants.length, 0)}. Текущее состояние будет заменено (предыдущее сохранится рядом как state.prev.json).`));
    } catch (_) { toast('Файл не похож на копию панели', 'bad'); }
  });
  return h('div', { class: 'grid cols-2' },
    h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', {}, 'Снять копию')),
      h('p', { class: 'muted' }, 'Все сети, ключи и доверенности одним JSON-файлом. Потеря state.json означает потерю всех ключей — копию стоит делать после каждой ротации.'),
      notice('warn', 'В файле лежат секретные ключи сетей и держателей. Храните его так же бережно, как сами ключи; в журнал выгрузка попадает.'),
      h('div', { class: 'row' }, btn({ label: 'Скачать копию', icon: 'download', variant: 'primary', onclick: () => act(async () => { const b = await api('GET', 'backup'); download(`netrunner-admin-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(b, null, 2)); toast('Копия скачана'); store.status.last_backup = b.exported; }) }),
        h('span', { class: 'muted small' }, st.last_backup ? `последняя: ${fmtDate(st.last_backup)}` : 'копий ещё не снимали'))),
    h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', {}, 'Восстановить')),
      h('p', { class: 'muted' }, 'Загрузите JSON, снятый этой панелью. Перед заменой копия проверяется на целостность: ключи, привязка держателей и цепочки.'),
      field('Файл копии', file), preview,
      h('div', { class: 'row' }, btn({ label: 'Восстановить…', icon: 'upload', variant: 'danger', onclick: async () => {
        if (!parsed) { toast('Сначала выберите файл', 'bad'); return; }
        if (await confirmDialog({ title: 'Восстановить из копии', text: 'Текущие сети, ключи и доверенности будут заменены содержимым копии.', confirmLabel: 'Восстановить', danger: true, type: 'RESTORE' }))
          act(async () => { const r = await api('POST', 'backup/restore', { backup: parsed, confirm: 'RESTORE' }); toast(`Восстановлено сетей: ${r.meshes}`); nav('#/meshes'); });
      } }))));
}

// Конфигурация узла ---------------------------------------------------------

async function config() {
  const n = await api('GET', 'node');
  const c = n.config || {};
  const yes = (v) => (v ? badge('да', 'ok') : badge('нет', ''));
  const val = (v) => (v == null || v === '' ? h('span', { class: 'muted' }, '—') : h('code', { class: 'mono' }, String(v)));
  const group = (title, rows) => h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', {}, title)), h('dl', { class: 'kv' }, rows.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])));
  const level = h('div', { class: 'segmented', role: 'group', 'aria-label': 'Уровень логов' }, ['error', 'warn', 'info', 'debug'].map((l) => h('button', { type: 'button', 'aria-pressed': String(n.log_level === l), onclick: (e) => act(async () => { await api('POST', 'node/log-level', { level: l }); e.currentTarget.parentElement.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', 'false')); e.currentTarget.setAttribute('aria-pressed', 'true'); toast(`Уровень логов: ${l}`); }) }, l)));
  return h('div', { class: 'stack' },
    notice('info', 'Конфигурация задаётся флагами и переменными окружения при запуске узла; изменить её можно только перезапуском. Здесь — то, с чем узел работает сейчас (секретов нет).'),
    h('div', { class: 'grid cols-2' },
      group('Сеть и маскировка', [['Порт', val(c.port)], ['Адрес привязки', val(c.host)], ['Сайт-приманка', val(c.decoy_host)], ['Режим маскировки', val(c.decoy_mode)], ['Пресет витрины', val(c.decoy_preset)], ['Свой cover-flight', yes(c.cover_flight)], ['Профиль формы трафика', yes(c.shape_profile)]]),
      group('Идентичность', [['NRXP-ключи заданы', yes(c.nrxp_configured)], ['Строгий режим', yes(c.strict)], ['Режим роя', yes(c.swarm)], ['Публичный адрес', val(c.advertise)]]),
      group('Mesh', [['Включён', yes(c.mesh_enabled)], ['Макс. хопов', val(c.mesh_max_hops)], ['QUIC-порт mesh', val(c.mesh_quic_port)], ['Период обмена каталогом', val(c.gossip_interval && `${c.gossip_interval} с`)], ['Каталог в файле', yes(c.directory_file)]]),
      group('Служебное', [['Требовать авторизацию', yes(c.require_auth)], ['Control-plane бэкенд', yes(c.backend)], ['Порт /health', val(c.health_port)], ['Порт /metrics', val(c.metrics_port)], ['Порт панели', val(c.admin_port)]])),
    h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', {}, 'Уровень логов')),
      h('p', { class: 'muted' }, 'Меняется на лету, без перезапуска. Узел намеренно не пишет логи на диск и не привязывает IP клиентов к записям.'), level));
}

// Безопасность панели -------------------------------------------------------

function security() {
  const st = store.status;
  const lock = h('select', { 'aria-label': 'Автоблокировка' }, [[0, 'выключена'], [5, '5 минут'], [15, '15 минут'], [30, '30 минут'], [60, '1 час']].map(([v, l]) => h('option', { value: v, selected: v === getAutolock() }, l)));
  lock.addEventListener('change', () => { setAutolock(Number(lock.value)); toast('Сохранено'); });
  return h('div', { class: 'grid cols-2' },
    h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', {}, 'Доступ к панели')),
      h('dl', { class: 'kv' }, h('dt', {}, 'Слушает'), h('dd', {}, h('code', { class: 'mono' }, `127.0.0.1:${st.port}`), ' ', badge('только локально', 'ok')), h('dt', {}, 'Каталог данных'), h('dd', {}, h('code', { class: 'mono' }, st.data_dir)), h('dt', {}, 'Токен'), h('dd', {}, h('code', { class: 'mono' }, `${st.data_dir}/admin.token`))),
      notice('info', h('span', {}, 'С удалённого сервера: ', h('code', { class: 'mono' }, `ssh -L ${st.port}:127.0.0.1:${st.port} user@host`), ' и откройте http://localhost:' + st.port)),
      h('p', { class: 'muted small' }, 'Адрес зашит в коде: панель недоступна по сети, а запросы с чужим Host/Origin отклоняются.')),
    h('section', { class: 'card stack-sm' }, h('div', { class: 'card-head' }, h('h2', {}, 'Токен и сеанс')),
      h('p', { class: 'muted' }, 'Смена токена мгновенно отключает все остальные вкладки и скрипты, знающие старый.'),
      h('div', { class: 'row' }, btn({ label: 'Сменить токен панели', icon: 'refresh', variant: 'danger', onclick: async () => { if (await confirmDialog({ title: 'Сменить токен панели', text: 'Выпустится новый токен и запишется в admin.token. Текущий перестанет действовать; эта вкладка получит новый автоматически.', confirmLabel: 'Сменить', danger: true })) act(async () => { const { setToken } = await import('./api.js'); const r = await api('POST', 'admin-token/rotate'); setToken(r.token); toast('Токен панели заменён'); }); } })),
      field('Автоблокировка при бездействии', lock), btn({ label: 'Выйти сейчас', icon: 'logout', variant: 'ghost', onclick: () => logout() })));
}

// Остановка узла ------------------------------------------------------------

export async function stopNode() {
  if (!(await confirmDialog({ title: 'Остановить узел', text: h('div', { class: 'stack-sm' }, h('p', {}, 'Узел штатно завершится: дождётся закрытия активных соединений и остановится вместе с панелью.'), notice('warn', 'Поднять его заново должен supervisor (systemd/docker restart policy). Без него узел останется выключенным.')), confirmLabel: 'Остановить', danger: true, type: 'STOP' }))) return;
  await act(async () => {
    await api('POST', 'node/shutdown', { confirm: 'STOP' });
    store.nodeError = true;
    document.getElementById('app').replaceChildren(h('div', { class: 'login-wrap' }, h('div', { class: 'card hero login stack' }, h('div', { class: 'logo' }, 'Узел останавливается…'), h('p', { class: 'muted' }, 'Панель закроется вместе с ним. Если узел под supervisor’ом, он поднимется сам — обновите страницу через несколько секунд.'))));
  });
}
