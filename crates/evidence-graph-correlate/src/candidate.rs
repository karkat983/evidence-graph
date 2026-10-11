//! Incident candidates and how their uncertainty is scored.
//!
//! A candidate is a *defensible* grouping of evidence, not a verdict. It carries everything a
//! reviewer needs to judge it: the supporting event ids, the rule ids behind any inferred step,
//! whether inference or mere correlation was used, and what context is missing. Its score is a
//! **weakest-link** aggregate, deliberately *not* a product of edge confidences — multiplying
//! confidences would manufacture a precise-looking probability the evidence does not support.

use serde::{Deserialize, Serialize};

/// How a candidate's score was aggregated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreMethod {
    /// The score is the lowest edge confidence on the strongest path (the weakest link). This
    /// preserves uncertainty rather than inflating it by multiplication.
    WeakestLink,
}

/// A defensible incident candidate assembled from correlated evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentCandidate {
    /// A stable id derived from the supporting evidence.
    pub id: String,
    /// The tenant.
    pub tenant_id: String,
    /// The seed node the candidate grew from.
    pub seed: String,
    /// All nodes involved, in discovery order.
    pub involved_nodes: Vec<String>,
    /// Supporting event ids, deduplicated, for reproducibility.
    pub supporting_event_ids: Vec<String>,
    /// Rule ids behind any inferred edges used.
    pub rule_ids: Vec<String>,
    /// Whether any inferred (non-observed) edge was used.
    pub uses_inferred_edges: bool,
    /// Whether any `CorrelatedWith` (association-only) edge was used — such a candidate must
    /// never be presented as a proven causal chain.
    pub uses_correlation_only: bool,
    /// Context the candidate is missing (unbacked inferences, gaps), surfaced for review.
    pub missing_context: Vec<String>,
    /// The aggregate score in `[0, 1]`.
    pub score: f64,
    /// How the score was computed.
    pub score_method: ScoreMethod,
}

impl IncidentCandidate {
    /// Whether this candidate rests only on observed, causal evidence (no inference, no
    /// association-only hops, nothing missing) — the strongest kind.
    pub fn is_fully_grounded(&self) -> bool {
        !self.uses_inferred_edges && !self.uses_correlation_only && self.missing_context.is_empty()
    }
}
