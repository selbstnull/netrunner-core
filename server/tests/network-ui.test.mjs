import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

// Exercise the browser source directly; layout/camera functions use no DOM.
const source = (await readFile(new URL('../src/admin/ui/js/network.js', import.meta.url), 'utf8'))
  .replace(/^import .*?;\r?\n/, '');
const { networkLayout, zoomNetworkCamera } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

test('every shipped admin JavaScript module parses', async () => {
  const directory = new URL('../src/admin/ui/js/', import.meta.url);
  for (const file of (await readdir(directory)).filter((file) => file.endsWith('.js'))) {
    const parsed = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: await readFile(new URL(file, directory)), encoding: 'utf8' });
    assert.equal(parsed.status, 0, `${file}: ${parsed.stderr}`);
  }
});

test('membership alone never invents graph links; stale and unknown links are excluded', () => {
  const nodes = [{ node_id: 'bridge', roles: ['relay', 'bridge'] }, { node_id: 'relay' }, { node_id: 'exit' }];
  assert.deepEqual(networkLayout({ nodes, links: [] }).links, []);
  const graph = networkLayout({ generated_at: 1000, nodes, links: [
    { source: 'bridge', target: 'relay', connected: true, valid_until: 1090, reported_at: 990 },
    { source: 'bridge', target: 'relay', connected: true, valid_until: 1090, reported_at: 1000 },
    { source: 'relay', target: 'exit', tcp_reachable: true, valid_until: 1090 },
    { source: 'exit', target: 'missing', connected: true },
    { source: 'relay', target: 'relay', connected: true },
    { source: 'exit', target: 'bridge', connected: true, valid_until: 1000 },
    { source: 'exit', target: 'bridge', connected: true, valid_until: 1090, observed_at: 900 },
  ] });
  assert.equal(graph.links.length, 2);
  assert.equal(graph.links[0].reported_at, 1000);
  assert.deepEqual(graph.nodes.map((node) => node.node_id), ['bridge', 'exit', 'relay']);
  for (const node of graph.nodes) assert.ok(Number.isFinite(node.x) && Number.isFinite(node.y));
});

test('zoom preserves the cursor anchor and clamps limits without NaN', () => {
  const camera = { x: 37, y: -19, zoom: 1 };
  const anchor = { x: 420, y: 240 };
  const before = { x: (anchor.x - camera.x) / camera.zoom, y: (anchor.y - camera.y) / camera.zoom };
  for (const requested of [1.2, 2, 50, 0.001, 1]) {
    zoomNetworkCamera(camera, requested, anchor);
    assert.ok(camera.zoom >= 0.35 && camera.zoom <= 4);
    assert.ok(Math.abs((anchor.x - camera.x) / camera.zoom - before.x) < 1e-8);
    assert.ok(Math.abs((anchor.y - camera.y) / camera.zoom - before.y) < 1e-8);
  }
});
