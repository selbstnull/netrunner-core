//! Живые показатели узла для обзора: кольцевой буфер замеров раз в несколько секунд.
//!
//! Источники — счётчик активных соединений и Prometheus-метрики процесса. Только агрегаты:
//! ни адресов клиентов, ни чего-либо «по пользователю» панель не хранит и не показывает
//! (узел сам намеренно не привязывает IP клиента к логам).

use super::node::NodeView;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

pub const INTERVAL_SECS: u64 = 5;
const CAPACITY: usize = 720; // час при шаге 5 с

/// Ряды: имя в API → метрики, чьи суммы складываются (счётчики).
const SERIES: &[(&str, &[&str])] = &[
    ("new", &["netrunner_connections_total"]),
    ("auth_fail", &["netrunner_auth_failures_total"]),
    ("scanner", &["netrunner_scanner_fallback_total"]),
    ("mesh", &["netrunner_mesh_onion_streams_total", "netrunner_mesh_egress_streams_total"]),
];

/// Суммы значений по имени метрики (метки игнорируются) из текста Prometheus.
pub fn parse_prometheus(text: &str) -> HashMap<String, f64> {
    let mut out: HashMap<String, f64> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name_end = line.find(['{', ' ']).unwrap_or(line.len());
        let Some(value) = line.rsplit(' ').next().and_then(|v| v.parse::<f64>().ok()) else { continue };
        if value.is_finite() {
            *out.entry(line[..name_end].to_string()).or_default() += value;
        }
    }
    out
}

#[derive(Clone)]
struct Raw {
    ts: u64,
    conns: u64,
    totals: Vec<f64>,
}

#[derive(Default)]
pub struct Live {
    ring: Mutex<VecDeque<Raw>>,
}

impl Live {
    pub fn record(&self, node: &NodeView, now: u64) {
        let metrics = node.metrics.as_ref().map(|h| parse_prometheus(&h.render())).unwrap_or_default();
        let totals = SERIES
            .iter()
            .map(|(_, names)| names.iter().map(|n| metrics.get(*n).copied().unwrap_or(0.0)).sum())
            .collect();
        let raw = Raw { ts: now, conns: node.active_connections.load(Ordering::Relaxed), totals };
        let mut ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        if ring.len() == CAPACITY {
            ring.pop_front();
        }
        ring.push_back(raw);
    }

    /// Ряды для графиков: по точке на замер, счётчики — приращением за шаг.
    pub fn snapshot(&self, node: &NodeView) -> Value {
        let ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        let mut points = Vec::with_capacity(ring.len());
        let mut prev: Option<&Raw> = None;
        for r in ring.iter() {
            let mut p = json!({ "ts": r.ts, "conns": r.conns });
            for (i, (name, _)) in SERIES.iter().enumerate() {
                let d = prev.map_or(0.0, |q| (r.totals[i] - q.totals[i]).max(0.0));
                p[*name] = json!(d);
            }
            points.push(p);
            prev = Some(r);
        }
        let last = ring.back();
        let mut totals = serde_json::Map::new();
        for (i, (name, _)) in SERIES.iter().enumerate() {
            totals.insert((*name).to_string(), json!(last.map_or(0.0, |r| r.totals[i])));
        }
        json!({
            "interval": INTERVAL_SECS,
            "metrics": node.metrics.is_some(),
            "active_connections": node.active_connections.load(Ordering::Relaxed),
            "totals": totals,
            "points": points,
        })
    }
}

/// Все метрики процесса (суммы по меткам) — для страницы «Метрики» без внешнего Prometheus.
pub fn all_metrics(node: &NodeView) -> Value {
    let Some(h) = node.metrics.as_ref() else { return json!({ "available": false, "metrics": [] }) };
    let mut v: Vec<(String, f64)> = parse_prometheus(&h.render()).into_iter().collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    json!({ "available": true, "metrics": v.into_iter().map(|(name, value)| json!({ "name": name, "value": value })).collect::<Vec<_>>() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_sums_labelled_counters() {
        let text = "# HELP x y\n# TYPE netrunner_connections_total counter\n\
                    netrunner_connections_total{kind=\"a\"} 3\n\
                    netrunner_connections_total{kind=\"b\"} 4\n\
                    netrunner_connections_active 2\n\
                    broken line without number\n\
                    netrunner_x{quantile=\"0.5\"} NaN\n";
        let m = parse_prometheus(text);
        assert_eq!(m["netrunner_connections_total"], 7.0);
        assert_eq!(m["netrunner_connections_active"], 2.0);
        assert!(!m.contains_key("netrunner_x"));
    }

    #[test]
    fn ring_is_bounded_and_counters_become_deltas() {
        let node = NodeView::detached();
        let live = Live::default();
        for i in 0..(CAPACITY as u64 + 10) {
            node.active_connections.store(i, Ordering::Relaxed);
            live.record(&node, 1000 + i);
        }
        let snap = live.snapshot(&node);
        let pts = snap["points"].as_array().unwrap();
        assert_eq!(pts.len(), CAPACITY);
        assert_eq!(pts[0]["ts"], 1010);
        assert_eq!(pts.last().unwrap()["new"], 0.0);
        assert_eq!(snap["metrics"], false);
    }
}
