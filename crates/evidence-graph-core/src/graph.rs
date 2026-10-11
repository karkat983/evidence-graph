//! The temporal graph store, its edge validator, and bounded traversal.
//!
//! The store enforces the provenance invariants at insert time (so the graph can never hold an
//! observed edge with no evidence, or an inferred edge with no rule), and traversal is always
//! **time-scoped and hop-bounded**: you ask "from this node, at this instant, within N hops,
//! what is reachable?" and get back paths whose every edge was valid at that instant, together
//! with all the evidence references along the way. Traversal never leaves the starting tenant
//! and never revisits a node, so cycles and cross-tenant paths cannot run away.

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use crate::model::{AssertionKind, Edge, EdgeType, Node};

/// Why an edge was rejected.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum EdgeError {
    /// Confidence outside `[0, 1]`.
    #[error("confidence {0} out of range [0,1]")]
    BadConfidence(f64),
    /// An observed edge carried no provenance evidence.
    #[error("observed edge {0:?} must reference provenance evidence")]
    ObservedWithoutEvidence(String),
    /// An inferred edge named no rule/method.
    #[error("inferred edge {0:?} must name a rule_id")]
    InferredWithoutRule(String),
    /// A `CorrelatedWith` edge was asserted as observed.
    #[error("CorrelatedWith edge {0:?} may not be asserted as observed (association, not causation)")]
    CorrelatedMustBeInferred(String),
    /// The edge referenced a node not in the graph.
    #[error("edge references unknown node {0:?}")]
    UnknownNode(String),
    /// The edge's endpoints are in different tenants, or differ from the edge's tenant.
    #[error("edge tenant mismatch for edge {0:?}")]
    TenantMismatch(String),
}

/// A path found by traversal: the edges followed, in order.
#[derive(Clone, Debug, PartialEq)]
pub struct Path {
    /// The edges traversed from the seed, in order.
    pub edges: Vec<Edge>,
}

impl Path {
    /// The node id this path ends at.
    pub fn endpoint(&self) -> Option<&str> {
        self.edges.last().map(|e| e.dst.as_str())
    }

    /// Hop count.
    pub fn hops(&self) -> usize {
        self.edges.len()
    }

    /// All provenance event ids referenced along the path, de-duplicated in order.
    pub fn evidence(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for e in &self.edges {
            for ev in &e.provenance_event_ids {
                if seen.insert(ev.clone()) {
                    out.push(ev.clone());
                }
            }
        }
        out
    }

    /// Whether every edge on the path is causal (no `CorrelatedWith` hop).
    pub fn is_fully_causal(&self) -> bool {
        self.edges.iter().all(|e| e.edge_type.is_causal())
    }
}

/// The temporal graph.
#[derive(Default)]
pub struct TemporalGraph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

impl TemporalGraph {
    /// An empty graph.
    pub fn new() -> Self {
        TemporalGraph::default()
    }

    /// Add a node.
    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    /// Look up a node.
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Validate and add an edge, enforcing the provenance invariants.
    pub fn add_edge(&mut self, edge: Edge) -> Result<(), EdgeError> {
        self.validate_edge(&edge)?;
        self.edges.push(edge);
        Ok(())
    }

    /// Validate an edge without inserting it.
    pub fn validate_edge(&self, edge: &Edge) -> Result<(), EdgeError> {
        if !(0.0..=1.0).contains(&edge.confidence) {
            return Err(EdgeError::BadConfidence(edge.confidence));
        }
        // CorrelatedWith is association, never causation, so it can't be an observed fact.
        if edge.edge_type == EdgeType::CorrelatedWith && edge.assertion_kind == AssertionKind::Observed {
            return Err(EdgeError::CorrelatedMustBeInferred(edge.id.clone()));
        }
        match edge.assertion_kind {
            AssertionKind::Observed => {
                if edge.provenance_event_ids.is_empty() {
                    return Err(EdgeError::ObservedWithoutEvidence(edge.id.clone()));
                }
            }
            AssertionKind::InferredRule | AssertionKind::InferredStat => {
                if edge.rule_id.as_deref().unwrap_or("").is_empty() {
                    return Err(EdgeError::InferredWithoutRule(edge.id.clone()));
                }
            }
        }
        // endpoints must exist and share the edge's tenant
        let src = self.node(&edge.src).ok_or_else(|| EdgeError::UnknownNode(edge.src.clone()))?;
        let dst = self.node(&edge.dst).ok_or_else(|| EdgeError::UnknownNode(edge.dst.clone()))?;
        if src.tenant_id != edge.tenant_id || dst.tenant_id != edge.tenant_id {
            return Err(EdgeError::TenantMismatch(edge.id.clone()));
        }
        Ok(())
    }

    /// Provenance lookup: the event ids backing a given edge.
    pub fn provenance_of(&self, edge_id: &str) -> Option<&[String]> {
        self.edges
            .iter()
            .find(|e| e.id == edge_id)
            .map(|e| e.provenance_event_ids.as_slice())
    }

    /// Bounded, time-scoped traversal from `seed` at instant `at`, up to `max_hops` hops.
    ///
    /// Returns every path (1..=max_hops edges) whose edges were all valid at `at`, staying in
    /// the seed's tenant and never revisiting a node. Results are ordered by hop count then by
    /// endpoint id, so a query is reproducible.
    pub fn traverse(&self, seed: &str, at: DateTime<Utc>, max_hops: usize) -> Vec<Path> {
        let tenant = match self.node(seed) {
            Some(n) => n.tenant_id.clone(),
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(seed.to_string());
        self.walk(seed, &tenant, at, max_hops, &mut Vec::new(), &mut visited, &mut out);
        out.sort_by(|a, b| {
            a.hops()
                .cmp(&b.hops())
                .then_with(|| a.endpoint().cmp(&b.endpoint()))
        });
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        current: &str,
        tenant: &str,
        at: DateTime<Utc>,
        hops_left: usize,
        trail: &mut Vec<Edge>,
        visited: &mut HashSet<String>,
        out: &mut Vec<Path>,
    ) {
        if hops_left == 0 {
            return;
        }
        // Collect the outgoing edges first so we don't hold an immutable borrow of `visited`
        // (through the filter) while mutating it in the loop body.
        let outgoing: Vec<Edge> = self
            .edges
            .iter()
            .filter(|e| {
                e.tenant_id == tenant
                    && e.src == current
                    && e.is_valid_at(at)
                    && !visited.contains(&e.dst)
            })
            .cloned()
            .collect();
        for edge in outgoing {
            trail.push(edge.clone());
            out.push(Path { edges: trail.clone() });
            visited.insert(edge.dst.clone());
            self.walk(&edge.dst, tenant, at, hops_left - 1, trail, visited, out);
            visited.remove(&edge.dst);
            trail.pop();
        }
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NodeType;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()
    }

    fn graph() -> TemporalGraph {
        let mut g = TemporalGraph::new();
        for (id, ty) in [
            ("agent-1", NodeType::Agent),
            ("tool-1", NodeType::Tool),
            ("api-1", NodeType::Api),
            ("res-1", NodeType::Resource),
        ] {
            g.add_node(Node::new(id, "alpha", ty));
        }
        g
    }

    fn observed(id: &str, ty: EdgeType, src: &str, dst: &str, from: u32, to: Option<u32>) -> Edge {
        Edge {
            id: id.into(),
            tenant_id: "alpha".into(),
            edge_type: ty,
            src: src.into(),
            dst: dst.into(),
            valid_from: at(from),
            valid_to: to.map(at),
            provenance_event_ids: vec![format!("ev-{id}")],
            assertion_kind: AssertionKind::Observed,
            confidence: 1.0,
            rule_id: None,
        }
    }

    #[test]
    fn observed_edge_needs_evidence() {
        let mut g = graph();
        let mut e = observed("e1", EdgeType::Invokes, "agent-1", "tool-1", 1, None);
        e.provenance_event_ids.clear();
        assert!(matches!(g.add_edge(e), Err(EdgeError::ObservedWithoutEvidence(_))));
    }

    #[test]
    fn inferred_edge_needs_rule() {
        let mut g = graph();
        let e = Edge {
            id: "e1".into(),
            tenant_id: "alpha".into(),
            edge_type: EdgeType::CorrelatedWith,
            src: "agent-1".into(),
            dst: "res-1".into(),
            valid_from: at(1),
            valid_to: None,
            provenance_event_ids: vec![],
            assertion_kind: AssertionKind::InferredRule,
            confidence: 0.6,
            rule_id: None,
        };
        assert!(matches!(g.add_edge(e), Err(EdgeError::InferredWithoutRule(_))));
    }

    #[test]
    fn correlated_with_cannot_be_observed() {
        let mut g = graph();
        let mut e = observed("e1", EdgeType::CorrelatedWith, "agent-1", "res-1", 1, None);
        // observed + correlated_with is contradictory
        e.assertion_kind = AssertionKind::Observed;
        assert!(matches!(g.add_edge(e), Err(EdgeError::CorrelatedMustBeInferred(_))));
    }

    #[test]
    fn bad_confidence_is_rejected() {
        let mut g = graph();
        let mut e = observed("e1", EdgeType::Invokes, "agent-1", "tool-1", 1, None);
        e.confidence = 1.5;
        assert!(matches!(g.add_edge(e), Err(EdgeError::BadConfidence(_))));
    }

    #[test]
    fn three_hop_traversal_is_time_scoped_and_returns_evidence() {
        let mut g = graph();
        g.add_edge(observed("e1", EdgeType::Invokes, "agent-1", "tool-1", 1, None)).unwrap();
        g.add_edge(observed("e2", EdgeType::Calls, "tool-1", "api-1", 1, None)).unwrap();
        g.add_edge(observed("e3", EdgeType::Accesses, "api-1", "res-1", 1, None)).unwrap();

        let paths = g.traverse("agent-1", at(3), 3);
        // the full 3-hop path reaches res-1
        let full = paths.iter().find(|p| p.endpoint() == Some("res-1")).unwrap();
        assert_eq!(full.hops(), 3);
        assert_eq!(full.evidence(), vec!["ev-e1", "ev-e2", "ev-e3"]);
        assert!(full.is_fully_causal());
    }

    #[test]
    fn traversal_respects_edge_time_windows() {
        let mut g = graph();
        // e2 only valid days 1-2; querying at day 3 should not traverse it
        g.add_edge(observed("e1", EdgeType::Invokes, "agent-1", "tool-1", 1, None)).unwrap();
        g.add_edge(observed("e2", EdgeType::Calls, "tool-1", "api-1", 1, Some(2))).unwrap();
        let paths = g.traverse("agent-1", at(3), 3);
        assert!(paths.iter().all(|p| p.endpoint() != Some("api-1")));
    }

    #[test]
    fn traversal_handles_cycles_without_runaway() {
        let mut g = graph();
        g.add_edge(observed("e1", EdgeType::Connects, "agent-1", "tool-1", 1, None)).unwrap();
        g.add_edge(observed("e2", EdgeType::Connects, "tool-1", "agent-1", 1, None)).unwrap();
        let paths = g.traverse("agent-1", at(3), 5);
        // no node is revisited within a path
        for p in &paths {
            let mut seen = std::collections::HashSet::new();
            seen.insert("agent-1");
            for e in &p.edges {
                assert!(seen.insert(e.dst.as_str()), "revisited {}", e.dst);
            }
        }
    }

    #[test]
    fn traversal_stays_within_tenant() {
        let mut g = graph();
        g.add_node(Node::new("foreign", "bravo", NodeType::Resource));
        // an edge into bravo would fail validation (tenant mismatch), so build it in alpha only
        g.add_edge(observed("e1", EdgeType::Invokes, "agent-1", "tool-1", 1, None)).unwrap();
        let paths = g.traverse("agent-1", at(3), 3);
        assert!(paths.iter().all(|p| p.endpoint() != Some("foreign")));
    }

    #[test]
    fn provenance_lookup_returns_event_ids() {
        let mut g = graph();
        g.add_edge(observed("e1", EdgeType::Invokes, "agent-1", "tool-1", 1, None)).unwrap();
        assert_eq!(g.provenance_of("e1"), Some(&["ev-e1".to_string()][..]));
    }
}
