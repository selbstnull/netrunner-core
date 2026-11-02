// Набор иконок 24×24 (штрих). Описание: пути через «|»; «c:cx,cy,r» — круг, «r:x,y,w,h,rx» — прямоугольник.
const NS = 'http://www.w3.org/2000/svg';

const SPEC = {
  menu: 'M4 6h16|M4 12h16|M4 18h16',
  sun: 'c:12,12,4|M12 2v2|M12 20v2|M4.9 4.9l1.4 1.4|M17.7 17.7l1.4 1.4|M2 12h2|M20 12h2|M4.9 19.1l1.4-1.4|M17.7 6.3l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
  auto: 'r:3,4,18,12,2|M8 20h8|M12 16v4',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  key: 'c:7.5,15.5,4.5|M10.7 12.3L21 2|M16 7l3 3',
  network: 'c:12,5,2|c:5,19,2|c:19,19,2|M11 6.8L6 17.2|M13 6.8l5 10.4|M7 19h10',
  server: 'r:2,3,20,7,2|r:2,14,20,7,2|M6 6.5h.01|M6 17.5h.01',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  plus: 'M12 5v14|M5 12h14',
  copy: 'r:9,9,13,13,2|M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  more: 'c:12,5,1|c:12,12,1|c:12,19,1',
  refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8|M21 3v5h-5',
  trash: 'M3 6h18|M8 6V4h8v2|M19 6l-1 14H6L5 6|M10 11v6|M14 11v6',
  clock: 'c:12,12,9|M12 7v5l3 2',
  check: 'M20 6L9 17l-5-5',
  x: 'M18 6L6 18|M6 6l12 12',
  alert: 'M12 9v4|M12 17h.01|M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  info: 'c:12,12,9|M12 16v-4|M12 8h.01',
  search: 'c:11,11,7|M21 21l-4.3-4.3',
  download: 'M12 3v12|M7 10l5 5 5-5|M5 21h14',
  upload: 'M12 15V3|M7 8l5-5 5 5|M5 21h14',
  power: 'M12 2v10|M18.4 6.6a9 9 0 1 1-12.8 0',
  lock: 'r:3,11,18,11,2|M7 11V7a5 5 0 0 1 10 0v4',
  user: 'c:12,8,4|M4 21a8 8 0 0 1 16 0',
  branch: 'c:6,5,2|c:6,19,2|c:18,8,2|M6 7v10|M18 10a6 6 0 0 1-6 6H8',
  file: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z|M14 3v6h6|M8 13h8|M8 17h8',
  gear: 'c:12,12,3|M12 2v3|M12 19v3|M4.9 4.9l2.1 2.1|M17 17l2.1 2.1|M2 12h3|M19 12h3|M4.9 19.1L7 17|M17 7l2.1-2.1',
  terminal: 'M4 17l6-6-6-6|M12 19h8',
  database: 'M3 5c0-1.7 4-3 9-3s9 1.3 9 3-4 3-9 3-9-1.3-9-3z|M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5|M3 12c0 1.7 4 3 9 3s9-1.3 9-3',
  radio: 'c:12,12,2|M16.2 7.8a6 6 0 0 1 0 8.4|M7.8 16.2a6 6 0 0 1 0-8.4|M19 5a10 10 0 0 1 0 14|M5 19a10 10 0 0 1 0-14',
  down: 'M6 9l6 6 6-6',
  right: 'M9 6l6 6-6 6',
  arrow: 'M5 12h14|M13 6l6 6-6 6',
  eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z|c:12,12,3',
  eyeoff: 'M3 3l18 18|M10.6 6.1A9.8 9.8 0 0 1 12 6c6.4 0 10 6 10 6a17 17 0 0 1-3.2 3.9|M6.6 6.7A17 17 0 0 0 2 12s3.6 6 10 6a9.7 9.7 0 0 0 4.2-.9',
  calendar: 'r:3,4,18,18,2|M16 2v4|M8 2v4|M3 10h18|M12 14v4|M10 16h4',
  edit: 'M12 20h9|M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
  help: 'c:12,12,9|M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3|M12 17h.01',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4|M16 17l5-5-5-5|M21 12H9',
  chip: 'r:5,5,14,14,2|r:9,9,6,6,1|M9 2v3|M15 2v3|M9 19v3|M15 19v3|M2 9h3|M2 15h3|M19 9h3|M19 15h3',
  link: 'M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7|M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7',
  history: 'M3 12a9 9 0 1 0 3-6.7L3 8|M3 3v5h5|M12 7v5l3 2',
};

export function icon(name, cls = '') {
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'i ' + cls);
  svg.setAttribute('aria-hidden', 'true');
  for (const part of (SPEC[name] || SPEC.info).split('|')) {
    let el;
    if (part.startsWith('c:')) {
      const [cx, cy, r] = part.slice(2).split(',');
      el = document.createElementNS(NS, 'circle');
      el.setAttribute('cx', cx); el.setAttribute('cy', cy); el.setAttribute('r', r);
    } else if (part.startsWith('r:')) {
      const [x, y, w, h, rx] = part.slice(2).split(',');
      el = document.createElementNS(NS, 'rect');
      el.setAttribute('x', x); el.setAttribute('y', y); el.setAttribute('width', w); el.setAttribute('height', h); el.setAttribute('rx', rx);
    } else {
      el = document.createElementNS(NS, 'path');
      el.setAttribute('d', part);
    }
    svg.append(el);
  }
  return svg;
}
