//! Cross-layer correlation for the evidence graph.
//!
//! Single engines raise single-source alerts; real incidents span layers. This crate assembles
//! *defensible incident candidates* by expanding over the [temporal graph](evidence_graph_core)
//! from a seed, gathering the evidence that links an AuthZ finding, an agent's observed side
//! effect and a network flow through shared identities, operations and assets within a bounded
//! time window.
//!
//! The correlator is built to resist over-claiming:
//!
//! * it scores a candidate by its **weakest link**, never by multiplying edge confidences into
//!   a false probability;
//! * it **labels** every candidate with whether inference or association-only edges were used,
//!   and records **missing context** instead of assuming it;
//! * it never invents a causal edge — a [`CorrelatedWith`](evidence_graph_core::EdgeType)
//!   hop keeps the candidate flagged as association, not causation;
//! * it **dedups** candidates resting on the same evidence and folds in analyst **feedback**.
//!
//! ```
//! use evidence_graph_correlate::Correlator;
//! use evidence_graph_core::{TemporalGraph, Node, NodeType, Edge, EdgeType, AssertionKind};
//! use chrono::{TimeZone, Utc};
//!
//! let mut g = TemporalGraph::new();
//! g.add_node(Node::new("finding-1", "alpha", NodeType::Finding));
//! g.add_node(Node::new("res-1", "alpha", NodeType::Resource));
//! g.add_edge(Edge {
//!     id: "e1".into(), tenant_id: "alpha".into(), edge_type: EdgeType::Affects,
//!     src: "finding-1".into(), dst: "res-1".into(),
//!     valid_from: Utc.with_ymd_and_hms(2026,1,1,0,0,0).unwrap(), valid_to: None,
//!     provenance_event_ids: vec!["ev-1".into()],
//!     assertion_kind: AssertionKind::Observed, confidence: 0.8, rule_id: None,
//! }).unwrap();
//!
//! let at = Utc.with_ymd_and_hms(2026,1,2,0,0,0).unwrap();
//! let c = Correlator::default().candidate_from_seed(&g, "finding-1", at).unwrap();
//! assert!(c.is_fully_grounded());
//! assert_eq!(c.supporting_event_ids, vec!["ev-1"]);
//! ```

pub mod candidate;
pub mod correlate;

pub use candidate::{IncidentCandidate, ScoreMethod};
pub use correlate::{Correlator, Feedback};
