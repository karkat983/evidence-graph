//! Entities, aliases, and how an alias was matched to an entity.
//!
//! An entity is a thing the graph talks about — a principal, an agent, a tool, an API, a
//! resource, a workload. The hard part is that the same entity shows up under many names across
//! sources (an OIDC subject here, a Kubernetes UID there, a reused IP somewhere else), so each
//! name is an [`Alias`] that resolves to an entity by a stated [`ResolutionMethod`] and — for
//! probabilistic matches — a confidence. Aliases are time-bounded, because a name (an IP, a
//! hostname) can belong to different entities at different times.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The kind of thing an entity is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    /// A human or machine principal.
    Identity,
    /// An AI agent.
    Agent,
    /// A tool an agent can call.
    Tool,
    /// An API or operation.
    Api,
    /// A data resource (an order, a document…).
    Resource,
    /// A compute workload (a pod, a VM, a function).
    Workload,
}

/// A deterministic identifier namespace — a key that, within a tenant, identifies exactly one
/// entity with no guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterministicKey {
    /// An OIDC `sub` claim.
    OidcSubject,
    /// A cloud instance id.
    CloudInstanceId,
    /// A Kubernetes object UID.
    K8sUid,
    /// An agent id.
    AgentId,
    /// A canonical API resource key.
    ApiResourceKey,
}

/// How an alias was matched to its entity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolutionMethod {
    /// A deterministic match in a known namespace — certain.
    Deterministic {
        /// Which namespace.
        key: DeterministicKey,
    },
    /// A probabilistic match by some named method, with a confidence in `[0, 1]`.
    Probabilistic {
        /// The matching method (e.g. `name_similarity`, `ip_lease_window`).
        method: String,
        /// Confidence in `[0, 1]`.
        confidence: f64,
    },
}

impl ResolutionMethod {
    /// Whether this is a deterministic (certain) match.
    pub fn is_deterministic(&self) -> bool {
        matches!(self, ResolutionMethod::Deterministic { .. })
    }

    /// The confidence: 1.0 for deterministic, the stated value otherwise (clamped).
    pub fn confidence(&self) -> f64 {
        match self {
            ResolutionMethod::Deterministic { .. } => 1.0,
            ResolutionMethod::Probabilistic { confidence, .. } => confidence.clamp(0.0, 1.0),
        }
    }
}

/// A resolved entity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// The entity's stable id.
    pub id: String,
    /// The owning tenant.
    pub tenant_id: String,
    /// The kind of entity.
    pub entity_type: EntityType,
    /// The canonical key that identifies it within its tenant.
    pub canonical_key: String,
    /// Free-form attributes.
    #[serde(default)]
    pub attributes: IndexMap<String, String>,
}

impl Entity {
    /// Construct an entity.
    pub fn new(
        id: impl Into<String>,
        tenant_id: impl Into<String>,
        entity_type: EntityType,
        canonical_key: impl Into<String>,
    ) -> Self {
        Entity {
            id: id.into(),
            tenant_id: tenant_id.into(),
            entity_type,
            canonical_key: canonical_key.into(),
            attributes: IndexMap::new(),
        }
    }

    /// Builder: add an attribute.
    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.attributes.insert(k.into(), v.into());
        self
    }
}

/// A name that resolves to an entity, valid over a time interval.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Alias {
    /// The alias string (an IP, a username, an instance id…).
    pub alias: String,
    /// The entity it resolves to.
    pub entity_id: String,
    /// The tenant (aliases never cross tenants).
    pub tenant_id: String,
    /// How the match was made.
    pub method: ResolutionMethod,
    /// When the alias became valid.
    pub valid_from: DateTime<Utc>,
    /// When it stopped being valid (`None` = still valid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,
}

impl Alias {
    /// Whether the alias is valid at `at` (`[valid_from, valid_to)`).
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.valid_from && self.valid_to.map(|end| at < end).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn deterministic_method_is_full_confidence() {
        let m = ResolutionMethod::Deterministic {
            key: DeterministicKey::OidcSubject,
        };
        assert!(m.is_deterministic());
        assert_eq!(m.confidence(), 1.0);
    }

    #[test]
    fn probabilistic_confidence_is_clamped() {
        let m = ResolutionMethod::Probabilistic {
            method: "x".into(),
            confidence: 2.0,
        };
        assert_eq!(m.confidence(), 1.0);
    }

    #[test]
    fn alias_validity_is_half_open() {
        let alias = Alias {
            alias: "10.0.0.5".into(),
            entity_id: "e1".into(),
            tenant_id: "alpha".into(),
            method: ResolutionMethod::Deterministic {
                key: DeterministicKey::CloudInstanceId,
            },
            valid_from: at(1),
            valid_to: Some(at(5)),
        };
        assert!(!alias.is_valid_at(at(1) - chrono::Duration::seconds(1)));
        assert!(alias.is_valid_at(at(1)));
        assert!(alias.is_valid_at(at(4)));
        assert!(!alias.is_valid_at(at(5))); // end is exclusive
    }
}
