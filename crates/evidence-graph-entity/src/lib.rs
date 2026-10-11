//! Identity and asset resolution for the evidence graph.
//!
//! Before anything can be correlated, the platform has to agree on *what* it is talking about:
//! the same principal, agent, workload or resource appears under many names across engines and
//! over time. This crate resolves a name to an entity, deterministically where it can and
//! probabilistically where it must — and, crucially, leaves a genuinely ambiguous match
//! *explicitly ambiguous* rather than guessing.
//!
//! * [`types`] — [`Entity`], [`Alias`], and the [`ResolutionMethod`] (deterministic namespaces
//!   first, then probabilistic with a retained method and confidence);
//! * [`resolver`] — the [`EntityResolver`]: time-bounded, tenant-isolated resolution with
//!   conflict handling, merge/split/correction audit, and manual override.
//!
//! ```
//! use evidence_graph_entity::{EntityResolver, Entity, EntityType, Alias, ResolutionMethod, DeterministicKey};
//! use chrono::{TimeZone, Utc};
//!
//! let mut r = EntityResolver::new();
//! r.add_entity(Entity::new("agent-7", "alpha", EntityType::Agent, "assistant-7"));
//! r.add_alias(Alias {
//!     alias: "assistant-7".into(), entity_id: "agent-7".into(), tenant_id: "alpha".into(),
//!     method: ResolutionMethod::Deterministic { key: DeterministicKey::AgentId },
//!     valid_from: Utc.with_ymd_and_hms(2026,1,1,0,0,0).unwrap(), valid_to: None,
//! }).unwrap();
//!
//! let at = Utc.with_ymd_and_hms(2026,1,2,0,0,0).unwrap();
//! assert_eq!(r.resolve("alpha", "assistant-7", at).entity_id(), Some("agent-7"));
//! ```

pub mod resolver;
pub mod types;

pub use resolver::{AuditEntry, Candidate, EntityResolver, Resolution, ResolveError};
pub use types::{Alias, DeterministicKey, Entity, EntityType, ResolutionMethod};
