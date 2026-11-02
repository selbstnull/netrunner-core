// Узлы: этот узел, клиентский конфиг, самоописание для соседей и список соседей с RTT.
import { api, nav } from './api.js';
import { networkGraph } from './network.js';
import { h, icon, btn, badge, field, notice, empty, skeleton, secret, eyebrow, dialog, confirmDialog, toast, copy, download, act, fmtDate, rel, dur, short, plural, put } from './ui.js';

const MODE = { swarm: 'сеть узлов (Directory)', panel: 'Legacy / внешняя авторизация', standalone: 'автономный' };
const ORIGIN = { local_admin: 'панель узла', controller: 'внешний контроллер', startup: 'параметры запуска' };
const ROLE = { relay: ['ретранслятор', 'primary'], exit: ['выход', 'violet'], bridge: ['мост', 'warn'] };
const ROLE_HELP = {
  relay: 'Пересылает трафик по mesh-маршруту.',
  exit: 'Может быть последним узлом маршрута и открывать соединение к сайту.',
  bridge: 'Вход для пользователей; адреса не распространяются обычным gossip.',
};

function rtt(ms) {
  if (ms == null) return h('span', { class: 'muted small' }, 'не замерен');
  const cls = ms < 80 ? '' : ms < 200 ? 'mid' : 'high';
  return h('span', { class: `rtt ${cls}`.trim(), title: 'Задержка до узла (TCP-проба)' }, `${ms} мс`, h('i', {}, h('b', { style: `width:${Math.min(100, ms / 3)}%` })));
}

export function nodesView() {
  const own = h('section', { class: 'card' }, skeleton(200));
  const cfg = h('section', { class: 'card' }, skeleton(200));
  const rolesCard = h('section', { class: 'card' }, skeleton(150));
  const desc = h('div', {});
  const graphCard = h('section', { class: 'card' }, skeleton(320));
  const peersCard = h('section', { class: 'card flush' }, skeleton(160));
  const el = h('div', { class: 'stack' },
    h('div', { class: 'page-head' }, h('div', { class: 'titles' }, eyebrow('узлы'), h('h1', {}, 'Этот узел и соседи'))),
    h('div', { class: 'grid cols-2' }, own, cfg), rolesCard, desc, graphCard, peersCard);
  let alive = true, q = '';
  let node = null, peers = null, network = null;
  let rolesDirty = false;
  const delivery = h('p', { class: 'muted small', 'aria-live': 'polite' });
  const renderDelivery = () => {
    const revision = node?.configuration?.revision;
    const acknowledged = node?.configuration_delivery?.acknowledged_revision ?? 0;
    delivery.textContent = !node?.config?.node_events
      ? 'Внешний контроллер не подключён. Настройки сохраняются на этом узле.'
      : acknowledged >= revision
        ? `Внешний контроллер получил версию ${acknowledged}.`
        : `Версия ${revision ?? '—'} ожидает подтверждения внешнего контроллера. Доставка повторяется автоматически.`;
  };
  const camera = { zoom: 1, x: 0, y: 0, selected: null };

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

  const renderRoles = () => {
    const d = node.directory;
    if (!d) {
      put(rolesCard,
        h('div', { class: 'card-head' }, h('h2', {}, 'Роли узла')),
        notice('info', 'Роли Relay, Exit и Bridge публикуются в подписанном каталоге роя. Этот узел сейчас не запущен с --swarm-key, поэтому роли каталога для него не заданы.'));
      return;
    }
    const roles = d.roles || [];
    const expectedRevision = node.configuration?.revision;
    const roleList = roles.length
      ? h('div', { class: 'chips' }, roles.map((r) => badge(...(ROLE[r] || [r, '']), ROLE_HELP[r])))
      : badge('роль не назначена', 'warn');
    const gossipLabel = d.encrypted_gossip ? 'AES-GCM с обновлёнными пирами' : 'шифрование gossip не поддерживается';
    const pairwiseLabel = d.pairwise ? 'поддержка PAIRWISE' : 'без поддержки PAIRWISE';
    const exitToggle = h('input', { type: 'checkbox', checked: roles.includes('exit') });
    const bridgeToggle = h('input', { type: 'checkbox', checked: roles.includes('bridge') });
    exitToggle.addEventListener('change', () => { rolesDirty = true; if (exitToggle.checked) bridgeToggle.checked = false; });
    bridgeToggle.addEventListener('change', () => { rolesDirty = true; if (bridgeToggle.checked) exitToggle.checked = false; });

    const userId = h('input', { type: 'text', maxlength: 256, placeholder: 'UUID или user ID', autocomplete: 'off', spellcheck: 'false' });
    const blind = h('input', { type: 'checkbox' });
    const ttl = h('input', { type: 'number', min: 60, max: 31536000, step: 1, value: 86400 });
    const tokenOut = h('div', {});
    let issuedToken = null;
    blind.addEventListener('change', () => { userId.disabled = blind.checked; });
    const issueToken = () => act(async () => {
      issuedToken = await api('POST', 'node/bridge-token', {
        user_id: blind.checked ? null : userId.value.trim(),
        ttl_secs: Number(ttl.value),
        blind: blind.checked,
      });
      const tokenText = h('textarea', { readOnly: true, rows: 4, class: 'mono', 'aria-label': 'Bridge capability token' });
      tokenText.value = issuedToken.token;
      put(tokenOut, h('div', { class: 'stack-sm' },
        h('p', { class: 'muted small' }, `Действует до ${fmtDate(issuedToken.expires_at)} · ${issuedToken.blind ? 'без user ID' : `user ${issuedToken.user_id}`}`),
        tokenText,
        btn({ label: 'Копировать токен', icon: 'copy', size: 'sm', onclick: () => copy(issuedToken.token, 'Bridge-токен скопирован') })));
      toast('Bridge-токен создан; он не сохраняется в панели');
    });

    put(rolesCard,
      h('div', { class: 'card-head' }, h('h2', {}, 'Роли и политика mesh'), badge(d.managed ? 'допуск по поручительствам' : 'допуск по ключу сети', 'ok')),
      h('div', { class: 'stack-sm' }, h('span', { class: 'label-text' }, 'Роли этого узла'), roleList),
      h('dl', { class: 'kv' },
        h('dt', {}, 'Маршрут'), h('dd', {}, `до ${node.config.mesh_max_hops ?? '—'} узлов · ${node.mesh.peers} известных пиров`),
        h('dt', {}, 'Gossip'), h('dd', {}, `${d.gossip ? 'поддерживается' : 'не поддерживается'} · ${gossipLabel}`),
        h('dt', {}, 'Аутентификация пиров'), h('dd', {}, `${pairwiseLabel} · строгий режим ${node.config.swarm_strict ? 'включён' : 'выключен'}`),
        h('dt', {}, 'Обновление каталога'), h('dd', {}, `примерно каждые ${node.config.gossip_interval ?? '—'} с · начальных записей: ${node.config.directory_seed_count ?? 0}`),
        h('dt', {}, 'Самоописание'), h('dd', {}, `seq ${d.seq} · действительно до ${fmtDate(d.valid_until)}`)),
      notice('info', 'Роли в этом блоке — возможности серверного узла. Они отличаются от ролей в доверенностях на вкладке «Сети и доступ»: доверенность ограничивает держателя токена, а роль каталога определяет, как узел участвует в маршрутизации.'),
      notice('info', `Relay — базовая роль сети. Exit и Bridge взаимоисключающие. Принятые изменения сохраняются и переживают перезапуск. Версия конфигурации: ${expectedRevision ?? 'недоступна'} · источник: ${ORIGIN[node.configuration?.origin] ?? 'неизвестен'}.`), delivery,
      h('div', { class: 'stack-sm' },
        h('div', { class: 'grid cols-2' },
          h('label', { class: 'field' }, h('span', {}, 'Exit'), h('span', { class: 'row' }, exitToggle, 'Узел может завершать маршрут и выходить в интернет')),
          h('label', { class: 'field' }, h('span', {}, 'Bridge'), h('span', { class: 'row' }, bridgeToggle, 'Скрытый вход; объявления доступны через BridgeHint'))),
        btn({ label: 'Применить роли к этому узлу', icon: 'check', variant: 'primary', onclick: () => act(async () => {
          await api('POST', 'node/roles', { exit: exitToggle.checked, bridge: bridgeToggle.checked, expected_revision: expectedRevision, request_id: crypto.randomUUID() });
          rolesDirty = false;
          toast('Роли сохранены, применены и подписаны заново');
          await load();
        }) }),
        btn({ label: 'Перечитать роли', onclick: () => act(async () => { rolesDirty = false; await load(); }) })),
      h('section', { class: 'card stack-sm' },
        h('div', { class: 'card-head' }, h('h3', {}, 'Bridge capability-token')),
        notice('info', 'Токен v1 подписывается ключом этого узла и подходит для BridgeHint-запросов к нему. Общий токен может выпускать отдельный доверенный подписант сети.'),
        field('User ID (пустой ID доступен только в слепом режиме)', userId),
        h('label', { class: 'row' }, blind, 'Слепой токен — user ID не попадёт в claims'),
        field('Срок, секунд (от 60 до 31 536 000)', ttl),
        btn({ label: 'Выдать токен', icon: 'key', variant: 'primary', onclick: issueToken }),
        tokenOut));
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
        h('div', { class: 'stack-sm' }, h('div', { class: 'chips' }, (p.roles || []).map((r) => badge(...(ROLE[r] || [r, '']), ROLE_HELP[r])), p.gossip ? badge('gossip', 'mono') : null, p.encrypted_gossip ? badge('AEAD gossip', 'ok', 'Пир объявил поддержку шифрования gossip') : null, p.pairwise ? badge('PAIRWISE', 'mono', 'Возможна проверка парного доказательства') : null), rtt(p.rtt_ms)),
        h('div', { class: 'small muted nowrap' }, p.valid_until ? [`до ${fmtDate(p.valid_until)}`, h('div', {}, `seq ${p.seq}`)] : '')))
        : empty('network', peers.source === 'none' ? 'Mesh не включён' : 'Соседей пока нет',
          peers.source === 'none' ? 'Запустите узел с --mesh-enabled или в режиме роя (--swarm-key), чтобы он находил другие узлы.'
            : isDir ? 'Добавьте соседа по его самоописанию — дальше узлы обмениваются записями сами.' : 'Каталог пиров приходит с control-plane; пока он пуст.',
          isDir ? btn({ label: 'Добавить соседа', icon: 'plus', variant: 'primary', onclick: addSeed }) : null));
  };

  const renderGraph = () => {
    if (!network) return;
    const count = (network.nodes || []).length;
    put(graphCard,
      h('div', { class: 'card-head' }, h('h2', {}, 'Сеть узлов'), badge(`${count} ${plural(count, 'узел', 'узла', 'узлов')}`, 'primary')),
      network.source === 'directory'
        ? network.operator_topology
          ? h('p', { class: 'muted small' }, 'Каталог и подписанные отчёты приходят от узлов этой сети. Внешний контроллер необязателен для обмена между ними. Отчёты о связях действуют 90 секунд.')
          : notice('info', 'Показан локальный каталог. Обмен операторскими отчётами выключен; для закрытой сети собственных узлов включите --operator-topology на её серверах. Этот режим раскрывает инфраструктуру доверенным участникам сети.')
        : notice('info', 'Это Legacy-снимок: список соседей поступает из настроенного внешнего сервиса. Распределённые отчёты доступны узлам в режиме Directory.'),
      h('div', { class: 'row muted small' }, network.network_id ? h('code', { class: 'mono' }, `Сеть: ${network.network_id}`) : null, `Подписанных отчётов: ${network.reports || 0} · снимок ${fmtDate(network.generated_at)}`),
      networkGraph(network, camera));
  };

  async function load() {
    const [n, p, view] = await Promise.all([api('GET', 'node'), api('GET', 'node/peers'), api('GET', 'node/network')]);
    if (!alive) return;
    node = n; peers = p; network = view;
    renderOwn(); renderCfg(); renderRoles(); renderDelivery(); renderPeers(); renderGraph(); renderDesc();
  }
  let refreshing = false;
  const refresh = setInterval(async () => {
    if (!alive || refreshing || document.visibilityState === 'hidden') return;
    refreshing = true;
    try {
      const [view, current] = await Promise.all([api('GET', 'node/network'), api('GET', 'node')]);
      if (alive) {
        const revisionChanged = current.configuration?.revision !== node?.configuration?.revision;
        network = view; node = current; renderGraph(); renderOwn(); renderDelivery();
        if (revisionChanged) {
          if (rolesDirty) toast('Конфигурация узла изменилась. Перечитайте роли перед применением.');
          else renderRoles();
        }
      }
    } catch { /* Keep the last snapshot and its visible timestamp. */ }
    finally { refreshing = false; }
  }, 10000);
  act(load);
  return { el, dispose: () => { alive = false; clearInterval(refresh); } };
}
