//! A provenance-aware temporal graph.
//!
//! The graph records observations, relationships and inferences across every engine — agents,
//! APIs, findings, network flows — in a form that keeps **association separate from
//! causation** and every fact traceable to its evidence.
//!
//! * [`model`] — [`Node`]s and time-bounded [`Edge`]s. Each edge declares an [`AssertionKind`]
//!   (observed / inferred-by-rule / inferred-statistically) and carries provenance; the
//!   [`EdgeType::CorrelatedWith`] relation is non-causal by construction.
//! * [`graph`] — the [`TemporalGraph`] store: it validates the provenance invariants at insert
//!   time and offers bounded, time-scoped, tenant-isolated traversal that returns every
//!   supporting evidence reference along a path.
//!
//! ```
//! use evidence_graph_core::{TemporalGraph, Node, NodeType, Edge, EdgeType, AssertionKind};
//! use chrono::{TimeZone, Utc};
//!
//! let mut g = TemporalGraph::new();
//! g.add_node(Node::new("agent-1", "alpha", NodeType::Agent));
//! g.add_node(Node::new("res-1", "alpha", NodeType::Resource));
//! g.add_edge(Edge {
//!     id: "e1".into(), tenant_id: "alpha".into(), edge_type: EdgeType::Accesses,
//!     src: "agent-1".into(), dst: "res-1".into(),
//!     valid_from: Utc.with_ymd_and_hms(2026,1,1,0,0,0).unwrap(), valid_to: None,
//!     provenance_event_ids: vec!["ev-1".into()],
//!     assertion_kind: AssertionKind::Observed, confidence: 1.0, rule_id: None,
//! }).unwrap();
//!
//! let at = Utc.with_ymd_and_hms(2026,1,2,0,0,0).unwrap();
//! let paths = g.traverse("agent-1", at, 2);
//! assert_eq!(paths[0].evidence(), vec!["ev-1"]);
//! ```

pub mod graph;
pub mod model;

pub use graph::{EdgeError, Path, TemporalGraph};
pub use model::{AssertionKind, Edge, EdgeType, Node, NodeType};
