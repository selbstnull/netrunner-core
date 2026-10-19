// Каркас: вход, шапка, бургер-меню, роутер по hash, тема, автоблокировка, горячие клавиши.
import { api, auth, setToken, store, nav } from './api.js';
import { h, icon, btn, iconBtn, toast, dialog, act, closeDialog, confirmDialog, closeMenu, eyebrow, plural, put } from './ui.js';
import { overviewView } from './overview.js';
import { meshesView } from './meshes.js';
import { nodesView } from './nodes.js';
import { toolView, TOOLS, stopNode } from './tools.js';

const app = document.getElementById('app');
let current = null;      // {el, dispose}
let drawer = null;       // {panel, scrim}
let pill = null;
let loginMessage = '';

// ── тема ───────────────────────────────────────────────────────────────────

const getTheme = () => { try { return localStorage.getItem('nr-theme') || 'auto'; } catch (_) { return 'auto'; } };
export function setTheme(t) {
  try { t === 'auto' ? localStorage.removeItem('nr-theme') : localStorage.setItem('nr-theme', t); } catch (_) {}
  if (t === 'auto') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t);
  document.querySelectorAll('[data-theme-ui]').forEach((n) => n.replaceWith(themeToggle()));
}
const THEME_ICON = { auto: 'auto', light: 'sun', dark: 'moon' };
const nextTheme = () => ({ auto: 'light', light: 'dark', dark: 'auto' }[getTheme()]);

function themeToggle() {
  const t = getTheme();
  const b = iconBtn(THEME_ICON[t], `Тема: ${{ auto: 'как в системе', light: 'светлая', dark: 'тёмная' }[t]} (нажмите, чтобы сменить)`, () => setTheme(nextTheme()));
  b.dataset.themeUi = '1';
  return b;
}

// ── автоблокировка ─────────────────────────────────────────────────────────

export const getAutolock = () => { try { return Number(localStorage.getItem('nr-autolock') ?? 30); } catch (_) { return 30; } };
export const setAutolock = (m) => { try { localStorage.setItem('nr-autolock', String(m)); } catch (_) {} armIdle(); };
let idleTimer;
function armIdle() {
  clearTimeout(idleTimer);
  const m = getAutolock();
  if (m > 0 && auth.token) idleTimer = setTimeout(() => logout(`Сеанс закрыт после ${m} мин бездействия`), m * 60000);
}
['pointerdown', 'keydown', 'visibilitychange'].forEach((e) => document.addEventListener(e, () => auth.token && armIdle(), { passive: true }));

export function logout(message = '') {
  setToken(null);
  loginMessage = message;
  closeDialog(); closeMenu(); stopPolling();
  location.hash = '#/';
  boot();
}
auth.onLost = (m) => logout(m);

// ── вход ───────────────────────────────────────────────────────────────────

function loginView() {
  const input = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: '64 hex-символа', class: 'mono', 'aria-label': 'Токен панели' });
  const err = h('p', { class: 'err', role: 'alert' }, loginMessage);
  const go = async (btnEl) => {
    err.textContent = '';
    setToken(input.value.trim());
    btnEl.disabled = true;
    try { await api('GET', 'status'); loginMessage = ''; await boot(); }
    catch (e) { setToken(null); err.textContent = e.message === 'Нужен токен панели' ? 'Токен не подошёл' : e.message; btnEl.disabled = false; }
  };
  const submit = h('button', { class: 'btn primary', type: 'button', onclick: (e) => go(e.currentTarget) }, icon('lock', 'sm'), 'Войти');
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit.click(); });
  return h('div', { class: 'login-wrap' }, h('div', { class: 'card hero login stack' },
    h('div', { class: 'stack-sm' }, eyebrow('доступ'), h('div', { class: 'logo' }, 'Netrunner ', h('em', {}, 'Admin'))),
    h('p', { class: 'muted' }, 'Панель управления узлом и mesh-сетями. Доступна только с этой машины.'),
    h('label', { class: 'field' }, h('span', {}, 'Токен панели'), input),
    err, submit,
    h('p', { class: 'lock-note' }, 'Токен лежит в файле admin.token в каталоге данных панели (по умолчанию ./netrunner-admin/, права 0600). С удалённого сервера: ssh -L 9092:127.0.0.1:9092 …')));
}

// ── каркас ─────────────────────────────────────────────────────────────────

const TABS = [['#/', 'Обзор', 'activity'], ['#/meshes', 'Сети и доступ', 'key'], ['#/nodes', 'Узлы', 'network']];
const isActive = (href) => { const p = location.hash || '#/'; return href === '#/' ? p === '#/' || p === '' : p.startsWith(href); };

function shell() {
  pill = h('span', { class: 'status-pill', title: 'Состояние узла' }, h('span', { class: 'led' }), h('span', { class: 'pill-text' }, '…'));
  const tabs = h('nav', { class: 'tabs', 'aria-label': 'Разделы' }, TABS.map(([href, label, ic]) => h('a', { class: 'tab', href, 'aria-current': isActive(href) ? 'page' : null }, icon(ic, 'sm'), label)));
  const bottom = h('nav', { class: 'bottom-nav', 'aria-label': 'Разделы' }, TABS.map(([href, label, ic]) => h('a', { class: 'tab', href, 'aria-current': isActive(href) ? 'page' : null }, icon(ic), label.split(' ')[0])));
  const header = h('header', { class: 'shell-header' },
    iconBtn('menu', 'Меню', openDrawer),
    h('div', { class: 'logo' }, 'Netrunner ', h('em', {}, 'Admin')),
    tabs,
    h('div', { class: 'header-end' }, pill, themeToggle()));
  const main = h('main', { class: 'page', id: 'view' });
  put(app, header, main, bottom);
  updatePill();
  return main;
}

function updatePill() {
  if (!pill) return;
  const n = store.node, led = pill.querySelector('.led'), txt = pill.querySelector('.pill-text');
  if (store.nodeError) { led.className = 'led bad'; txt.textContent = 'нет связи'; return; }
  if (!n) { led.className = 'led'; txt.textContent = '…'; return; }
  led.className = 'led ' + (n.healthy ? 'ok' : 'bad');
  put(txt, n.healthy ? 'в сети' : 'не отвечает', h('span', { class: 'label-long' }, ` · ${n.active_connections} ${plural(n.active_connections, 'соед.', 'соед.', 'соед.')}`));
}

// ── бургер-меню ────────────────────────────────────────────────────────────

function openDrawer() {
  if (drawer) return;
  const close = () => { if (!drawer) return; const d = drawer; drawer = null; d.panel.classList.remove('open'); d.scrim.classList.remove('open'); setTimeout(() => { d.panel.remove(); d.scrim.remove(); }, 220); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const go = (href) => () => { close(); nav(href); };
  const item = (ic, label, desc, onclick, extra = '') => h('button', { class: `nav-item ${extra}`.trim(), type: 'button', onclick, 'aria-current': desc && extra === 'cur' ? 'page' : null }, icon(ic), h('span', {}, label, desc ? h('span', { class: 'desc' }, desc) : null));
  const cur = (name) => (location.hash === `#/tools/${name}` ? 'page' : null);
  const toolItem = (name) => { const t = TOOLS[name]; const b = item(t.icon, t.title, t.desc, go(`#/tools/${name}`)); if (cur(name)) b.setAttribute('aria-current', 'page'); return b; };

  const theme = () => h('div', { class: 'segmented', role: 'group', 'aria-label': 'Тема' }, [['auto', 'Авто', 'auto'], ['light', 'Светлая', 'sun'], ['dark', 'Тёмная', 'moon']].map(([v, l, ic]) =>
    h('button', { type: 'button', 'aria-pressed': String(getTheme() === v), onclick: (e) => { setTheme(v); e.currentTarget.parentElement.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', 'false')); e.currentTarget.setAttribute('aria-pressed', 'true'); } }, icon(ic, 'sm'), l)));

  const panel = h('aside', { class: 'drawer', role: 'dialog', 'aria-label': 'Меню' },
    h('div', { class: 'drawer-head' }, h('div', { class: 'logo' }, 'Netrunner ', h('em', {}, 'Admin')), iconBtn('x', 'Закрыть меню', close)),
    h('div', { class: 'drawer-body' },
      h('div', { class: 'drawer-group' }, eyebrow('Инструменты'), toolItem('verify'), toolItem('audit'), toolItem('backup')),
      h('div', { class: 'drawer-group' }, eyebrow('Узел'), toolItem('metrics'), toolItem('config')),
      h('div', { class: 'drawer-group' }, eyebrow('Панель'), toolItem('security'), item('help', 'Горячие клавиши', 'Быстрая навигация', () => { close(); shortcutsDialog(); })),
      h('div', { class: 'drawer-group' }, eyebrow('Оформление'), h('div', { style: 'padding:4px 10px' }, theme())),
      h('div', { class: 'drawer-group' }, eyebrow('Опасная зона'), item('power', 'Остановить узел', 'Штатная остановка с дрейном соединений', () => { close(); stopNode(); }, 'danger'))),
    h('div', { class: 'drawer-foot stack-sm' },
      h('div', {}, `Панель v${store.status?.version ?? ''} · режим: ${({ swarm: 'рой', panel: 'под панелью', standalone: 'автономный' })[store.status?.mode] ?? '—'}`),
      btn({ label: 'Выйти', icon: 'logout', variant: 'ghost sm', onclick: () => { close(); logout(); } })));
  const scrim = h('div', { class: 'drawer-scrim', onclick: close });
  document.body.append(scrim, panel);
  requestAnimationFrame(() => { panel.classList.add('open'); scrim.classList.add('open'); });
  document.addEventListener('keydown', onKey);
  drawer = { panel, scrim };
  panel.querySelector('button.nav-item')?.focus();
}

function shortcutsDialog() {
  const row = (keys, text) => h('div', { class: 'row', style: 'justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--line)' }, h('span', {}, text), h('span', {}, keys.map((k, i) => [i ? ' ' : '', h('span', { class: 'kbd' }, k)])));
  dialog({ title: 'Горячие клавиши', body: h('div', {}, row(['g', 'o'], 'Обзор'), row(['g', 'm'], 'Сети и доступ'), row(['g', 'n'], 'Узлы'), row(['/'], 'Поиск на странице'), row(['t'], 'Сменить тему'), row(['?'], 'Эта подсказка')) });
}

let gPending = false;
document.addEventListener('keydown', (e) => {
  if (!auth.token || e.ctrlKey || e.metaKey || e.altKey) return;
  const tag = (e.target.tagName || '').toLowerCase();
  if (['input', 'textarea', 'select'].includes(tag) || document.getElementById('dlg').open) return;
  if (gPending) { gPending = false; const to = { o: '#/', m: '#/meshes', n: '#/nodes' }[e.key]; if (to) { e.preventDefault(); nav(to); } return; }
  if (e.key === 'g') { gPending = true; setTimeout(() => (gPending = false), 900); }
  else if (e.key === 't') setTheme(nextTheme());
  else if (e.key === '?') shortcutsDialog();
  else if (e.key === '/') { const s = document.querySelector('[data-search]'); if (s) { e.preventDefault(); s.focus(); } }
});

// ── маршрутизация ──────────────────────────────────────────────────────────

function route() {
  closeMenu();
  const main = document.getElementById('view');
  if (!main) return;
  current?.dispose?.();
  const parts = (location.hash || '#/').replace(/^#\/?/, '').split('/').filter(Boolean);
  let view;
  if (!parts.length) view = overviewView();
  else if (parts[0] === 'meshes') view = meshesView({ id: parts[1], tab: parts[2] });
  else if (parts[0] === 'nodes') view = nodesView();
  else if (parts[0] === 'tools' && TOOLS[parts[1]]) view = toolView(parts[1]);
  else view = overviewView();
  current = view;
  put(main, view.el);
  document.querySelectorAll('.tab').forEach((t) => (isActive(t.getAttribute('href')) ? t.setAttribute('aria-current', 'page') : t.removeAttribute('aria-current')));
  window.scrollTo(0, 0);
  document.title = 'Netrunner · Admin';
}

// ── опрос статуса узла ─────────────────────────────────────────────────────

let poll;
async function refreshNode() {
  try { store.node = await api('GET', 'node'); store.nodeError = false; }
  catch (e) { if (auth.token) store.nodeError = true; }
  updatePill();
}
function stopPolling() { clearInterval(poll); }

export async function boot() {
  stopPolling();
  if (!auth.token) { put(app, loginView()); return; }
  try { store.status = await api('GET', 'status'); }
  catch (e) { if (auth.token) { loginMessage = e.message; setToken(null); } put(app, loginView()); return; }
  shell();
  await refreshNode();
  route();
  armIdle();
  poll = setInterval(refreshNode, 10000);
}

window.addEventListener('hashchange', () => { if (auth.token && document.getElementById('view')) route(); });
boot();
