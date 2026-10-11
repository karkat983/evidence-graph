//! The entity resolver.
//!
//! Given an alias and a point in time, the resolver answers which entity it refers to — or says,
//! explicitly, that it cannot tell. The rules, in order:
//!
//! 1. **Deterministic first.** A valid deterministic alias wins outright. If two *different*
//!    entities both claim the alias deterministically at the same instant, that is a genuine
//!    conflict and the result is [`Resolution::Ambiguous`] — never a silent pick.
//! 2. **Probabilistic only if no deterministic match.** The best-confidence probabilistic alias
//!    resolves, but if several are within a small margin of each other the result stays
//!    ambiguous, because guessing between near-equal candidates is exactly what we must not do.
//! 3. **Time bounds matter.** A reused IP or hostname resolves to whichever entity held it at
//!    the queried time; outside every valid window the alias is [`Resolution::Unknown`].
//!
//! Aliases never cross tenants: a resolve names a tenant and only that tenant's aliases are
//! considered. Merges, splits and manual corrections are recorded in an audit log.

use chrono::{DateTime, Utc};

use crate::types::{Alias, Entity, ResolutionMethod};

/// The margin within which two probabilistic candidates are "too close to call".
const AMBIGUITY_MARGIN: f64 = 0.05;

/// A candidate entity for an alias, with how and how strongly it matched.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    /// The entity id.
    pub entity_id: String,
    /// The match method.
    pub method: ResolutionMethod,
}

/// The outcome of resolving an alias at a time.
#[derive(Clone, Debug, PartialEq)]
pub enum Resolution {
    /// Resolved to exactly one entity.
    Resolved(Candidate),
    /// Several candidates could not be separated; kept explicitly ambiguous.
    Ambiguous(Vec<Candidate>),
    /// No valid alias at the queried time.
    Unknown,
}

impl Resolution {
    /// The resolved entity id, if unambiguous.
    pub fn entity_id(&self) -> Option<&str> {
        match self {
            Resolution::Resolved(c) => Some(&c.entity_id),
            _ => None,
        }
    }

    /// Whether the resolution is ambiguous.
    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Resolution::Ambiguous(_))
    }
}

/// An audited structural change to the entity set.
#[derive(Clone, Debug, PartialEq)]
pub enum AuditEntry {
    /// Two entities were merged into one.
    Merge {
        /// The surviving entity id.
        into: String,
        /// The id that was merged away.
        from: String,
        /// Reason, for audit.
        reason: String,
    },
    /// An entity was split, moving some aliases to a new entity.
    Split {
        /// The original entity id.
        from: String,
        /// The new entity id.
        into: String,
        /// The aliases moved.
        aliases: Vec<String>,
        /// Reason, for audit.
        reason: String,
    },
    /// A manual correction overrode automatic resolution.
    Correction {
        /// The alias corrected.
        alias: String,
        /// The entity it now points to.
        entity_id: String,
        /// Reason, for audit.
        reason: String,
    },
}

/// Why a resolver operation failed.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ResolveError {
    /// An alias's tenant did not match the entity's tenant.
    #[error("alias tenant {alias_tenant:?} does not match entity tenant {entity_tenant:?}")]
    CrossTenantAlias {
        /// The alias's tenant.
        alias_tenant: String,
        /// The entity's tenant.
        entity_tenant: String,
    },
    /// Referenced an entity that does not exist.
    #[error("unknown entity {0:?}")]
    UnknownEntity(String),
}

/// The resolver: entities, their aliases, and an audit log.
#[derive(Default)]
pub struct EntityResolver {
    entities: Vec<Entity>,
    aliases: Vec<Alias>,
    audit: Vec<AuditEntry>,
}

impl EntityResolver {
    /// An empty resolver.
    pub fn new() -> Self {
        EntityResolver::default()
    }

    /// Register an entity.
    pub fn add_entity(&mut self, entity: Entity) {
        self.entities.push(entity);
    }

    /// Look up an entity by id.
    pub fn entity(&self, id: &str) -> Option<&Entity> {
        self.entities.iter().find(|e| e.id == id)
    }

    /// Add an alias. Fails if the alias's tenant differs from the entity's tenant, or the
    /// entity is unknown.
    pub fn add_alias(&mut self, alias: Alias) -> Result<(), ResolveError> {
        let entity = self
            .entities
            .iter()
            .find(|e| e.id == alias.entity_id)
            .ok_or_else(|| ResolveError::UnknownEntity(alias.entity_id.clone()))?;
        if entity.tenant_id != alias.tenant_id {
            return Err(ResolveError::CrossTenantAlias {
                alias_tenant: alias.tenant_id,
                entity_tenant: entity.tenant_id.clone(),
            });
        }
        self.aliases.push(alias);
        Ok(())
    }

    /// Resolve an alias within a tenant at a time.
    pub fn resolve(&self, tenant: &str, alias: &str, at: DateTime<Utc>) -> Resolution {
        let valid: Vec<&Alias> = self
            .aliases
            .iter()
            .filter(|a| a.tenant_id == tenant && a.alias == alias && a.is_valid_at(at))
            .collect();

        if valid.is_empty() {
            return Resolution::Unknown;
        }

        // 1) deterministic matches
        let det: Vec<&&Alias> = valid.iter().filter(|a| a.method.is_deterministic()).collect();
        if !det.is_empty() {
            let mut entities: Vec<String> = det.iter().map(|a| a.entity_id.clone()).collect();
            entities.sort();
            entities.dedup();
            if entities.len() == 1 {
                let a = det[0];
                return Resolution::Resolved(Candidate {
                    entity_id: a.entity_id.clone(),
                    method: a.method.clone(),
                });
            }
            // conflicting deterministic claims -> ambiguous
            return Resolution::Ambiguous(
                det.iter()
                    .map(|a| Candidate {
                        entity_id: a.entity_id.clone(),
                        method: a.method.clone(),
                    })
                    .collect(),
            );
        }

        // 2) probabilistic — rank by confidence
        let mut probs: Vec<&&Alias> = valid.iter().collect();
        probs.sort_by(|a, b| {
            b.method
                .confidence()
                .partial_cmp(&a.method.confidence())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.entity_id.cmp(&b.entity_id))
        });
        let best = probs[0];
        let best_conf = best.method.confidence();
        let near: Vec<&&&Alias> = probs
            .iter()
            .filter(|a| {
                (best_conf - a.method.confidence()).abs() <= AMBIGUITY_MARGIN
                    && a.entity_id != best.entity_id
            })
            .collect();
        if near.is_empty() {
            Resolution::Resolved(Candidate {
                entity_id: best.entity_id.clone(),
                method: best.method.clone(),
            })
        } else {
            let mut cands = vec![Candidate {
                entity_id: best.entity_id.clone(),
                method: best.method.clone(),
            }];
            cands.extend(near.iter().map(|a| Candidate {
                entity_id: a.entity_id.clone(),
                method: a.method.clone(),
            }));
            Resolution::Ambiguous(cands)
        }
    }

    /// Merge `from` into `into`: repoint aliases and record the merge.
    pub fn merge(&mut self, into: &str, from: &str, reason: impl Into<String>) -> Result<(), ResolveError> {
        if self.entity(into).is_none() {
            return Err(ResolveError::UnknownEntity(into.to_string()));
        }
        if self.entity(from).is_none() {
            return Err(ResolveError::UnknownEntity(from.to_string()));
        }
        for a in self.aliases.iter_mut() {
            if a.entity_id == from {
                a.entity_id = into.to_string();
            }
        }
        self.entities.retain(|e| e.id != from);
        self.audit.push(AuditEntry::Merge {
            into: into.to_string(),
            from: from.to_string(),
            reason: reason.into(),
        });
        Ok(())
    }

    /// Apply a manual correction: repoint an alias to an entity and record it.
    pub fn correct(&mut self, alias: &str, entity_id: &str, reason: impl Into<String>) -> Result<(), ResolveError> {
        let entity = self
            .entity(entity_id)
            .ok_or_else(|| ResolveError::UnknownEntity(entity_id.to_string()))?;
        let tenant = entity.tenant_id.clone();
        let mut found = false;
        for a in self.aliases.iter_mut() {
            if a.alias == alias && a.tenant_id == tenant {
                a.entity_id = entity_id.to_string();
                found = true;
            }
        }
        if !found {
            return Err(ResolveError::UnknownEntity(format!("alias:{alias}")));
        }
        self.audit.push(AuditEntry::Correction {
            alias: alias.to_string(),
            entity_id: entity_id.to_string(),
            reason: reason.into(),
        });
        Ok(())
    }

    /// The audit log.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit
    }

    /// Number of entities currently tracked.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeterministicKey, Entity, EntityType};
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()
    }

    fn det(key: DeterministicKey) -> ResolutionMethod {
        ResolutionMethod::Deterministic { key }
    }

    fn prob(method: &str, confidence: f64) -> ResolutionMethod {
        ResolutionMethod::Probabilistic {
            method: method.into(),
            confidence,
        }
    }

    fn alias(a: &str, entity: &str, tenant: &str, method: ResolutionMethod, from: u32, to: Option<u32>) -> Alias {
        Alias {
            alias: a.into(),
            entity_id: entity.into(),
            tenant_id: tenant.into(),
            method,
            valid_from: at(from),
            valid_to: to.map(at),
        }
    }

    fn resolver_with_two_entities() -> EntityResolver {
        let mut r = EntityResolver::new();
        r.add_entity(Entity::new("e1", "alpha", EntityType::Workload, "vm-1"));
        r.add_entity(Entity::new("e2", "alpha", EntityType::Workload, "vm-2"));
        r
    }

    #[test]
    fn deterministic_alias_resolves_cleanly() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("i-123", "e1", "alpha", det(DeterministicKey::CloudInstanceId), 1, None))
            .unwrap();
        let res = r.resolve("alpha", "i-123", at(3));
        assert_eq!(res.entity_id(), Some("e1"));
    }

    #[test]
    fn reused_ip_resolves_by_time_window() {
        let mut r = resolver_with_two_entities();
        // 10.0.0.5 belonged to e1 on days 1-5, then e2 from day 5 on
        r.add_alias(alias("10.0.0.5", "e1", "alpha", det(DeterministicKey::CloudInstanceId), 1, Some(5)))
            .unwrap();
        r.add_alias(alias("10.0.0.5", "e2", "alpha", det(DeterministicKey::CloudInstanceId), 5, None))
            .unwrap();
        assert_eq!(r.resolve("alpha", "10.0.0.5", at(3)).entity_id(), Some("e1"));
        assert_eq!(r.resolve("alpha", "10.0.0.5", at(6)).entity_id(), Some("e2"));
    }

    #[test]
    fn stale_alias_outside_window_is_unknown() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("host-a", "e1", "alpha", det(DeterministicKey::K8sUid), 1, Some(5)))
            .unwrap();
        assert_eq!(r.resolve("alpha", "host-a", at(9)), Resolution::Unknown);
    }

    #[test]
    fn conflicting_deterministic_claims_are_ambiguous() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("dup", "e1", "alpha", det(DeterministicKey::AgentId), 1, None)).unwrap();
        r.add_alias(alias("dup", "e2", "alpha", det(DeterministicKey::AgentId), 1, None)).unwrap();
        let res = r.resolve("alpha", "dup", at(2));
        assert!(res.is_ambiguous());
    }

    #[test]
    fn near_equal_probabilistic_candidates_stay_ambiguous() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("agentX", "e1", "alpha", prob("name", 0.80), 1, None)).unwrap();
        r.add_alias(alias("agentX", "e2", "alpha", prob("name", 0.78), 1, None)).unwrap();
        assert!(r.resolve("alpha", "agentX", at(2)).is_ambiguous());
    }

    #[test]
    fn clearly_better_probabilistic_candidate_resolves() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("agentX", "e1", "alpha", prob("name", 0.95), 1, None)).unwrap();
        r.add_alias(alias("agentX", "e2", "alpha", prob("name", 0.40), 1, None)).unwrap();
        assert_eq!(r.resolve("alpha", "agentX", at(2)).entity_id(), Some("e1"));
    }

    #[test]
    fn deterministic_beats_probabilistic() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("x", "e1", "alpha", det(DeterministicKey::OidcSubject), 1, None)).unwrap();
        r.add_alias(alias("x", "e2", "alpha", prob("name", 0.99), 1, None)).unwrap();
        assert_eq!(r.resolve("alpha", "x", at(2)).entity_id(), Some("e1"));
    }

    #[test]
    fn alias_cannot_cross_tenant() {
        let mut r = resolver_with_two_entities();
        let bad = alias("x", "e1", "bravo", det(DeterministicKey::AgentId), 1, None);
        assert!(matches!(r.add_alias(bad), Err(ResolveError::CrossTenantAlias { .. })));
    }

    #[test]
    fn tenant_collision_does_not_resolve_across_tenants() {
        let mut r = resolver_with_two_entities();
        r.add_entity(Entity::new("e3", "bravo", EntityType::Workload, "vm-3"));
        r.add_alias(alias("shared-name", "e1", "alpha", det(DeterministicKey::AgentId), 1, None)).unwrap();
        r.add_alias(alias("shared-name", "e3", "bravo", det(DeterministicKey::AgentId), 1, None)).unwrap();
        // resolving in bravo never sees alpha's alias
        assert_eq!(r.resolve("bravo", "shared-name", at(2)).entity_id(), Some("e3"));
    }

    #[test]
    fn merge_repoints_aliases_and_audits() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("a1", "e2", "alpha", det(DeterministicKey::AgentId), 1, None)).unwrap();
        r.merge("e1", "e2", "duplicate inventory").unwrap();
        assert_eq!(r.resolve("alpha", "a1", at(2)).entity_id(), Some("e1"));
        assert_eq!(r.entity_count(), 1);
        assert!(matches!(r.audit_log()[0], AuditEntry::Merge { .. }));
    }

    #[test]
    fn manual_correction_overrides_and_audits() {
        let mut r = resolver_with_two_entities();
        r.add_alias(alias("mis", "e1", "alpha", prob("name", 0.6), 1, None)).unwrap();
        r.correct("mis", "e2", "analyst reviewed").unwrap();
        assert_eq!(r.resolve("alpha", "mis", at(2)).entity_id(), Some("e2"));
        assert!(matches!(r.audit_log()[0], AuditEntry::Correction { .. }));
    }
}
