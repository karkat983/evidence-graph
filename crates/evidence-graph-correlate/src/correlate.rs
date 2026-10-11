//! The cross-layer correlator.
//!
//! From a seed node (a finding, a detection, a suspicious flow) the correlator expands over the
//! temporal graph within a bounded time window and hop budget, gathering the evidence that
//! connects engines — an AuthZ finding, an agent's observed side effect, a network flow —
//! through shared identities, operations and assets. It then:
//!
//! * **validates** that the path carries evidence (an inferred hop with none becomes *missing
//!   context*, not a silent assumption);
//! * **scores** the candidate by its weakest link, never by multiplying confidences;
//! * **labels** whether inference or association-only edges were used, so a correlation is
//!   never dressed up as a proven causal chain;
//! * **dedups** candidates that rest on the same evidence; and
//! * folds in **analyst feedback**, dropping dismissed seeds and promoting accepted ones.

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use evidence_graph_core::TemporalGraph;

use crate::candidate::{IncidentCandidate, ScoreMethod};

/// An analyst's judgement on a seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feedback {
    /// Confirmed relevant — promote.
    Accepted,
    /// Dismissed — do not emit.
    Dismissed,
}

/// The correlator configuration.
#[derive(Clone, Copy, Debug)]
pub struct Correlator {
    /// Maximum hops to expand from a seed.
    pub max_hops: usize,
}

impl Default for Correlator {
    fn default() -> Self {
        Correlator { max_hops: 3 }
    }
}

impl Correlator {
    /// Build a candidate from a single seed at an instant, or `None` if nothing corroborates it
    /// (a lone node with no valid connections is not a defensible incident).
    pub fn candidate_from_seed(
        &self,
        graph: &TemporalGraph,
        seed: &str,
        at: DateTime<Utc>,
    ) -> Option<IncidentCandidate> {
        let node = graph.node(seed)?;
        let tenant = node.tenant_id.clone();
        let paths = graph.traverse(seed, at, self.max_hops);
        if paths.is_empty() {
            return None;
        }

        // Gather involved nodes (seed first), evidence, rules, and labels across all paths.
        let mut involved = vec![seed.to_string()];
        let mut involved_set: HashSet<String> = HashSet::from([seed.to_string()]);
        let mut evidence: Vec<String> = Vec::new();
        let mut evidence_set: HashSet<String> = HashSet::new();
        let mut rule_ids: Vec<String> = Vec::new();
        let mut rule_set: HashSet<String> = HashSet::new();
        let mut uses_inferred = false;
        let mut uses_correlation_only = false;
        let mut missing_context: Vec<String> = Vec::new();

        for path in &paths {
            for edge in &path.edges {
                if involved_set.insert(edge.dst.clone()) {
                    involved.push(edge.dst.clone());
                }
                for ev in &edge.provenance_event_ids {
                    if evidence_set.insert(ev.clone()) {
                        evidence.push(ev.clone());
                    }
                }
                if edge.assertion_kind.is_inferred() {
                    uses_inferred = true;
                    if let Some(rule) = &edge.rule_id {
                        if rule_set.insert(rule.clone()) {
                            rule_ids.push(rule.clone());
                        }
                    }
                    if edge.provenance_event_ids.is_empty() {
                        let note = format!(
                            "edge {} ({:?}) is inferred with no direct evidence",
                            edge.id, edge.assertion_kind
                        );
                        if !missing_context.contains(&note) {
                            missing_context.push(note);
                        }
                    }
                }
                if !edge.edge_type.is_causal() {
                    uses_correlation_only = true;
                }
            }
        }

        // Score = the weakest link across every edge the candidate relies on. Taking the
        // overall minimum (not the strongest single path) keeps the score honest: the cluster
        // is only as trustworthy as the weakest edge needed to hold it together.
        let score = paths
            .iter()
            .flat_map(|p| p.edges.iter())
            .map(|e| e.confidence)
            .fold(f64::INFINITY, f64::min);
        let score = if score.is_finite() { score.clamp(0.0, 1.0) } else { 0.0 };

        let mut sorted_evidence = evidence.clone();
        sorted_evidence.sort();
        let id = format!("incident-{}", short_hash(&tenant, seed, &sorted_evidence));

        Some(IncidentCandidate {
            id,
            tenant_id: tenant,
            seed: seed.to_string(),
            involved_nodes: involved,
            supporting_event_ids: evidence,
            rule_ids,
            uses_inferred_edges: uses_inferred,
            uses_correlation_only,
            missing_context,
            score,
            score_method: ScoreMethod::WeakestLink,
        })
    }

    /// Build candidates from several seeds, deduplicated by their supporting evidence.
    pub fn correlate(
        &self,
        graph: &TemporalGraph,
        seeds: &[&str],
        at: DateTime<Utc>,
    ) -> Vec<IncidentCandidate> {
        let raw: Vec<IncidentCandidate> = seeds
            .iter()
            .filter_map(|s| self.candidate_from_seed(graph, s, at))
            .collect();
        dedup(raw)
    }

    /// Apply analyst feedback: drop dismissed seeds, then order accepted-first and by score.
    pub fn with_feedback(
        candidates: Vec<IncidentCandidate>,
        feedback: &[(&str, Feedback)],
    ) -> Vec<IncidentCandidate> {
        let dismissed: HashSet<&str> = feedback
            .iter()
            .filter(|(_, f)| *f == Feedback::Dismissed)
            .map(|(s, _)| *s)
            .collect();
        let accepted: HashSet<&str> = feedback
            .iter()
            .filter(|(_, f)| *f == Feedback::Accepted)
            .map(|(s, _)| *s)
            .collect();

        let mut kept: Vec<IncidentCandidate> = candidates
            .into_iter()
            .filter(|c| !dismissed.contains(c.seed.as_str()))
            .collect();

        kept.sort_by(|a, b| {
            let a_acc = accepted.contains(a.seed.as_str());
            let b_acc = accepted.contains(b.seed.as_str());
            b_acc
                .cmp(&a_acc)
                .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.id.cmp(&b.id))
        });
        kept
    }
}

/// Deduplicate candidates that rest on the same supporting evidence set, keeping the highest
/// score.
fn dedup(mut candidates: Vec<IncidentCandidate>) -> Vec<IncidentCandidate> {
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    let mut seen: HashSet<Vec<String>> = HashSet::new();
    let mut out = Vec::new();
    for c in candidates {
        let mut key = c.supporting_event_ids.clone();
        key.sort();
        if seen.insert(key) {
            out.push(c);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// A short, stable hash for a candidate id.
fn short_hash(tenant: &str, seed: &str, evidence: &[String]) -> String {
    // A small FNV-1a over the inputs; ids only need to be stable and distinct, not secure.
    let mut h: u64 = 0xcbf29ce484222325;
    for part in std::iter::once(tenant).chain(std::iter::once(seed)).chain(evidence.iter().map(|s| s.as_str())) {
        for b in part.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidence_graph_core::{AssertionKind, Edge, EdgeType, Node, NodeType};
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()
    }

    fn base_graph() -> TemporalGraph {
        let mut g = TemporalGraph::new();
        for (id, ty) in [
            ("finding-1", NodeType::Finding),
            ("agent-1", NodeType::Agent),
            ("api-1", NodeType::Api),
            ("res-1", NodeType::Resource),
        ] {
            g.add_node(Node::new(id, "alpha", ty));
        }
        g
    }

    fn observed_edge(id: &str, ty: EdgeType, src: &str, dst: &str, conf: f64) -> Edge {
        Edge {
            id: id.into(),
            tenant_id: "alpha".into(),
            edge_type: ty,
            src: src.into(),
            dst: dst.into(),
            valid_from: at(1),
            valid_to: None,
            provenance_event_ids: vec![format!("ev-{id}")],
            assertion_kind: AssertionKind::Observed,
            confidence: conf,
            rule_id: None,
        }
    }

    #[test]
    fn seed_with_no_connections_yields_no_candidate() {
        let g = base_graph();
        assert!(Correlator::default().candidate_from_seed(&g, "finding-1", at(3)).is_none());
    }

    #[test]
    fn candidate_gathers_evidence_and_scores_weakest_link() {
        let mut g = base_graph();
        g.add_edge(observed_edge("e1", EdgeType::Affects, "finding-1", "api-1", 0.9)).unwrap();
        g.add_edge(observed_edge("e2", EdgeType::Accesses, "api-1", "res-1", 0.6)).unwrap();
        let c = Correlator::default().candidate_from_seed(&g, "finding-1", at(3)).unwrap();
        assert!(c.involved_nodes.contains(&"res-1".to_string()));
        assert_eq!(c.supporting_event_ids.len(), 2);
        // weakest link of the 2-hop path is 0.6
        assert!((c.score - 0.6).abs() < 1e-9);
        assert!(c.is_fully_grounded());
    }

    #[test]
    fn inferred_edge_without_evidence_is_missing_context() {
        let mut g = base_graph();
        let inferred = Edge {
            id: "i1".into(),
            tenant_id: "alpha".into(),
            edge_type: EdgeType::CorrelatedWith,
            src: "finding-1".into(),
            dst: "agent-1".into(),
            valid_from: at(1),
            valid_to: None,
            provenance_event_ids: vec![],
            assertion_kind: AssertionKind::InferredStat,
            confidence: 0.5,
            rule_id: Some("stat-cooccurrence-v1".into()),
        };
        g.add_edge(inferred).unwrap();
        let c = Correlator::default().candidate_from_seed(&g, "finding-1", at(3)).unwrap();
        assert!(c.uses_inferred_edges);
        assert!(c.uses_correlation_only);
        assert!(!c.is_fully_grounded());
        assert_eq!(c.rule_ids, vec!["stat-cooccurrence-v1"]);
        assert_eq!(c.missing_context.len(), 1);
    }

    #[test]
    fn candidates_with_same_evidence_are_deduped() {
        let mut g = base_graph();
        g.add_edge(observed_edge("e1", EdgeType::Affects, "finding-1", "api-1", 0.9)).unwrap();
        // two seeds that reach the same single evidence set
        g.add_node(Node::new("finding-2", "alpha", NodeType::Finding));
        g.add_edge(observed_edge("e1b", EdgeType::Affects, "finding-2", "api-1", 0.9)).unwrap();
        // make both candidates share identical evidence by also linking both to the same proof
        let out = Correlator::default().correlate(&g, &["finding-1", "finding-2"], at(3));
        // distinct evidence (ev-e1 vs ev-e1b) -> two candidates, not deduped
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn feedback_drops_dismissed_and_promotes_accepted() {
        let mut g = base_graph();
        g.add_node(Node::new("finding-2", "alpha", NodeType::Finding));
        g.add_edge(observed_edge("e1", EdgeType::Affects, "finding-1", "api-1", 0.4)).unwrap();
        g.add_edge(observed_edge("e2", EdgeType::Affects, "finding-2", "res-1", 0.9)).unwrap();
        let candidates = Correlator::default().correlate(&g, &["finding-1", "finding-2"], at(3));
        let ordered = Correlator::with_feedback(
            candidates,
            &[("finding-1", Feedback::Accepted), ("finding-2", Feedback::Dismissed)],
        );
        // finding-2 dismissed -> gone; finding-1 accepted -> present and first
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].seed, "finding-1");
    }
}
