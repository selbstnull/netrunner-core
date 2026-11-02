// Тема применяется до первой отрисовки, чтобы не мигала: auto (по системе) | light | dark.
(function () {
  try {
    var t = localStorage.getItem('nr-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
})();
