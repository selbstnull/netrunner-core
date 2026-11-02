// Общие примитивы интерфейса. Весь текст попадает в DOM только как текст (createTextNode):
// данные из API не могут внедрить разметку, а CSP запрещает inline-скрипты и style-атрибуты.
import { icon } from './icons.js';
export { icon };

export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    // setAttribute('style') запрещён CSP (style-src 'self'); через CSSOM — можно.
    else if (k === 'style') for (const decl of String(v).split(';')) { const [n, ...val] = decl.split(':'); if (val.length) el.style.setProperty(n.trim(), val.join(':').trim()); }
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (['value', 'checked', 'disabled', 'selected', 'readOnly', 'indeterminate'].includes(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}

/** Заменяет содержимое `el`: разворачивает вложенные массивы и отбрасывает null/false
 *  (голый `replaceChildren` вывел бы их как текст «null»). */
export function put(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
}

// ── форматирование ─────────────────────────────────────────────────────────

export const fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleString('ru-RU', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
export const fmtDay = (ts) => ts ? new Date(ts * 1000).toLocaleDateString('ru-RU', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
export const short = (s, n = 6) => (s && s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s || '');
export const plural = (n, one, few, many) => { const m = Math.abs(n) % 100, d = m % 10; return m > 10 && m < 20 ? many : d === 1 ? one : d > 1 && d < 5 ? few : many; };

export function dur(sec) {
  sec = Math.max(0, Math.round(sec));
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} д ${hh} ч`;
  if (hh) return `${hh} ч ${m} мин`;
  if (m) return `${m} мин`;
  return `${sec} с`;
}

/** «через 3 дн.» / «2 ч назад». */
export function rel(ts, now = Date.now() / 1000) {
  const diff = ts - now, a = Math.abs(diff);
  const u = a >= 86400 ? [Math.round(a / 86400), 'дн.'] : a >= 3600 ? [Math.round(a / 3600), 'ч'] : [Math.max(1, Math.round(a / 60)), 'мин'];
  return diff >= 0 ? `через ${u[0]} ${u[1]}` : `${u[0]} ${u[1]} назад`;
}

export const initials = (s) => (s || '?').trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join('').toUpperCase();

// ── мелкие компоненты ──────────────────────────────────────────────────────

export function btn({ label, icon: ic, variant = '', size = '', onclick, title, disabled, aria } = {}) {
  return h('button', { class: `btn ${variant} ${size}`.trim(), type: 'button', title, disabled, onclick, 'aria-label': aria || (label ? null : title) },
    ic ? icon(ic, size === 'sm' ? 'sm' : '') : null, label);
}

export const iconBtn = (ic, title, onclick) => h('button', { class: 'icon-btn', type: 'button', title, 'aria-label': title, onclick }, icon(ic));
export const badge = (text, kind = '', title) => h('span', { class: `badge ${kind}`.trim(), title }, text);

export function field(label, input, help) {
  return h('label', { class: 'field' }, h('span', {}, label), input, help ? h('span', { class: 'help muted small' }, help) : null);
}

export function notice(kind, content, ic) {
  return h('div', { class: `notice ${kind}` }, icon(ic || (kind === 'bad' || kind === 'warn' ? 'alert' : 'info')), h('div', {}, content));
}

export function empty(ic, title, text, ...actions) {
  const art = icon(ic); art.classList.add('art');
  return h('div', { class: 'empty' }, art, h('h3', {}, title), text ? h('p', {}, text) : null, actions.length ? h('div', { class: 'row' }, actions) : null);
}

export const skeleton = (height = 16, width = '100%') => h('div', { class: 'skeleton', style: `height:${height}px;width:${width}` });

/** Блок с моноширинным значением; клик копирует. */
export function secret(text, msg = 'Скопировано') {
  return h('code', { class: 'secret copyable', title: 'Нажмите, чтобы скопировать', onclick: () => copy(text, msg) }, text);
}

export function eyebrow(text) { return h('span', { class: 'eyebrow' }, text); }

// ── тосты, буфер, файлы ────────────────────────────────────────────────────

export function toast(msg, kind = '') {
  const host = document.getElementById('toast-host');
  const t = h('div', { class: `toast ${kind}`.trim() }, msg);
  host.append(t);
  setTimeout(() => t.remove(), kind === 'bad' ? 4500 : 2300);
}

export async function copy(text, msg = 'Скопировано') {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch (_) {
    // запасной путь: вне secure context буфер недоступен, но localhost им считается
    const ta = h('textarea', { style: 'position:fixed;opacity:0' }); ta.value = text; document.body.append(ta); ta.select();
    try { document.execCommand('copy'); toast(msg); } catch (__) { toast('Не удалось скопировать — выделите вручную', 'bad'); }
    ta.remove();
  }
}

export function download(filename, text, mime = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h('a', { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Выполняет действие; ошибку показывает тостом и возвращает undefined. */
export async function act(fn) {
  try { return await fn(); } catch (e) { if (e && e.message) toast(e.message, 'bad'); }
}

// ── диалог ─────────────────────────────────────────────────────────────────

const dlgEl = () => document.getElementById('dlg');
export function closeDialog() { const d = dlgEl(); if (d.open) d.close(); }

/**
 * Показывает модальный диалог. `actions`: [{label, variant, run}] — `run` вернёт `false`,
 * чтобы оставить окно открытым. Кнопка «Закрыть» добавляется сама.
 */
export function dialog({ title, body, actions = [], wide = false, closeLabel = 'Закрыть' }) {
  const d = dlgEl();
  d.className = wide ? 'wide' : '';
  const x = iconBtn('x', 'Закрыть', closeDialog);
  const foot = h('div', { class: 'dlg-foot' },
    h('button', { class: 'btn ghost', type: 'button', onclick: closeDialog }, closeLabel),
    actions.map((a) => h('button', {
      class: `btn ${a.variant || ''}`.trim(), type: 'button',
      onclick: async (ev) => {
        const b = ev.currentTarget; b.disabled = true;
        const keep = await act(a.run);
        b.disabled = false;
        if (keep !== false && !(keep === undefined && a.keepOnError)) closeDialog();
      },
    }, a.icon ? icon(a.icon, 'sm') : null, a.label)));
  d.replaceChildren(h('div', { class: 'dlg-head' }, h('h2', {}, title), x), h('div', { class: 'dlg-body' }, body), foot);
  if (!d.open) d.showModal();
  d.querySelector('input:not([type=checkbox]):not([type=radio]), textarea, select')?.focus();
  return d;
}

/** Подтверждение; для необратимого можно потребовать ввести слово. Resolve(true|false). */
export function confirmDialog({ title, text, confirmLabel = 'Подтвердить', danger = false, type }) {
  return new Promise((resolve) => {
    const input = type ? h('input', { type: 'text', placeholder: type, autocomplete: 'off', 'aria-label': `Введите ${type}` }) : null;
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const d = dialog({
      title, body: h('div', { class: 'stack-sm' }, typeof text === 'string' ? h('p', {}, text) : text, type ? h('p', { class: 'muted small' }, `Для подтверждения введите «${type}»:`) : null, input),
      actions: [{ label: confirmLabel, variant: danger ? 'danger solid' : 'primary', run: async () => { if (type && input.value !== type) throw new Error(`Введите «${type}» точно как показано`); finish(true); } }],
    });
    d.addEventListener('close', () => finish(false), { once: true });
  });
}

// ── меню-поповер ───────────────────────────────────────────────────────────

let openMenu = null;
export function closeMenu() { if (openMenu) { openMenu.remove(); openMenu = null; } }

/** items: [{label, icon, desc, danger, onclick} | 'sep'] */
export function menu(anchor, items) {
  closeMenu();
  const m = h('div', { class: 'menu', role: 'menu' }, items.map((it) => it === 'sep' ? h('hr') : h('button', {
    type: 'button', role: 'menuitem', class: it.danger ? 'danger' : '',
    onclick: () => { closeMenu(); it.onclick(); },
  }, it.icon ? icon(it.icon, 'sm') : null, h('span', {}, it.label, it.desc ? h('span', { class: 'd' }, it.desc) : null))));
  document.body.append(m);
  const r = anchor.getBoundingClientRect(), mw = m.offsetWidth, mh = m.offsetHeight;
  m.style.left = `${Math.max(8, Math.min(innerWidth - mw - 8, r.right - mw))}px`;
  m.style.top = `${r.bottom + 6 + mh > innerHeight ? Math.max(8, r.top - mh - 6) : r.bottom + 6}px`;
  openMenu = m;
  m.querySelector('button')?.focus();
  const off = (e) => { if (!m.contains(e.target)) { closeMenu(); cleanup(); } };
  const key = (e) => {
    if (e.key === 'Escape') { closeMenu(); cleanup(); anchor.focus(); }
    const bs = [...m.querySelectorAll('button')], i = bs.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); bs[(i + 1) % bs.length].focus(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); bs[(i - 1 + bs.length) % bs.length].focus(); }
  };
  const cleanup = () => { document.removeEventListener('pointerdown', off, true); document.removeEventListener('keydown', key, true); };
  setTimeout(() => { document.addEventListener('pointerdown', off, true); document.addEventListener('keydown', key, true); }, 0);
  return m;
}
