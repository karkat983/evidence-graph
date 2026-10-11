//! Nodes and edges of the temporal graph.
//!
//! The graph represents observations, relationships and inferences **without conflating
//! association with causation**. That discipline is encoded in the types:
//!
//! * an edge states its [`AssertionKind`] — directly `Observed`, inferred by a `Rule`, or
//!   inferred statistically — and the validator enforces what each kind must carry;
//! * an **observed** edge must reference the evidence it came from (`provenance_event_ids`);
//! * an **inferred** edge must name the `rule_id`/method that produced it;
//! * the [`EdgeType::CorrelatedWith`] relation is explicitly non-causal and may never be
//!   asserted as `Observed`.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The kind of graph node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// A principal.
    Identity,
    /// An AI agent.
    Agent,
    /// A tool.
    Tool,
    /// An API/operation.
    Api,
    /// A data resource.
    Resource,
    /// A compute workload.
    Workload,
    /// A security finding.
    Finding,
    /// A raw event.
    Event,
    /// A stored evidence blob.
    Evidence,
    /// An incident.
    Incident,
}

/// A node in the graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Stable node id.
    pub id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// The node kind.
    pub node_type: NodeType,
    /// Free-form attributes.
    #[serde(default)]
    pub attributes: IndexMap<String, String>,
}

impl Node {
    /// Construct a node.
    pub fn new(id: impl Into<String>, tenant_id: impl Into<String>, node_type: NodeType) -> Self {
        Node {
            id: id.into(),
            tenant_id: tenant_id.into(),
            node_type,
            attributes: IndexMap::new(),
        }
    }

    /// Builder: add an attribute.
    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.attributes.insert(k.into(), v.into());
        self
    }
}

/// The kind of relationship an edge expresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// A principal uses an agent/tool.
    Uses,
    /// An agent invokes a tool.
    Invokes,
    /// A tool calls an API.
    Calls,
    /// An actor accesses a resource.
    Accesses,
    /// A workload connects to another.
    Connects,
    /// An action affects a resource/finding.
    Affects,
    /// Evidence supports a finding/incident.
    Supports,
    /// Two things are correlated — association only, never causation.
    CorrelatedWith,
}

impl EdgeType {
    /// Whether this relation expresses causation. `CorrelatedWith` never does.
    pub fn is_causal(self) -> bool {
        !matches!(self, EdgeType::CorrelatedWith)
    }
}

/// How an edge's claim was established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionKind {
    /// Directly observed, backed by evidence.
    Observed,
    /// Inferred by an explicit rule.
    InferredRule,
    /// Inferred statistically.
    InferredStat,
}

impl AssertionKind {
    /// Whether the assertion is inferred (not directly observed).
    pub fn is_inferred(self) -> bool {
        !matches!(self, AssertionKind::Observed)
    }
}

/// A time-bounded, provenance-carrying edge.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    /// Stable edge id.
    pub id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// The relationship kind.
    pub edge_type: EdgeType,
    /// Source node id.
    pub src: String,
    /// Destination node id.
    pub dst: String,
    /// When the edge became valid.
    pub valid_from: DateTime<Utc>,
    /// When it stopped being valid (`None` = still valid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,
    /// Event ids that provide provenance for the edge.
    #[serde(default)]
    pub provenance_event_ids: Vec<String>,
    /// How the edge was asserted.
    pub assertion_kind: AssertionKind,
    /// Confidence in `[0, 1]`.
    pub confidence: f64,
    /// The rule/method id for an inferred edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

impl Edge {
    /// Whether the edge is valid at `at` (`[valid_from, valid_to)`).
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.valid_from && self.valid_to.map(|end| at < end).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlated_with_is_never_causal() {
        assert!(!EdgeType::CorrelatedWith.is_causal());
        assert!(EdgeType::Accesses.is_causal());
    }

    #[test]
    fn assertion_inferred_flag() {
        assert!(!AssertionKind::Observed.is_inferred());
        assert!(AssertionKind::InferredRule.is_inferred());
        assert!(AssertionKind::InferredStat.is_inferred());
    }
}
