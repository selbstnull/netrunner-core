// Клиент API панели. Токен живёт только в sessionStorage вкладки; запросы — с заголовком
// Authorization (cookie нет, поэтому CSRF невозможен по построению).

export const auth = { token: null, onLost: () => {} };
try { auth.token = sessionStorage.getItem('nr-admin-token'); } catch (_) {}

export function setToken(t) {
  auth.token = t;
  try { t ? sessionStorage.setItem('nr-admin-token', t) : sessionStorage.removeItem('nr-admin-token'); } catch (_) {}
}

export async function api(method, path, body) {
  const hasBody = body !== undefined || method === 'POST';
  const res = await fetch('/api/' + path, {
    method,
    headers: { Authorization: 'Bearer ' + auth.token, ...(hasBody ? { 'Content-Type': 'application/json' } : {}) },
    body: hasBody ? JSON.stringify(body ?? {}) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401) { setToken(null); auth.onLost('Токен не принят или был сменён'); throw new Error('Нужен токен панели'); }
  if (!res.ok) throw new Error(data.error || `Ошибка ${res.status}`);
  return data;
}

/** Общее состояние приложения: обновляется в main.js, читается представлениями. */
export const store = { status: null, node: null, nodeError: false };
export const nav = (hash) => { if (location.hash === hash) window.dispatchEvent(new HashChangeEvent('hashchange')); else location.hash = hash; };
