//! A controlled, deterministic cross-layer scenario.
//!
//! Three engines each contribute one observation about the same real-world event — an agent for
//! tenant `alpha` reading tenant `bravo`'s order:
//!
//! * **AuthZ Fuzzer** raised a verified BOLA finding on `GET /orders/{id}` (`finding-bola`);
//! * **AgentTrace** observed the agent's tool call that performed the read (`agent-7`);
//! * **EastWest** observed the network flow carrying the response bytes (`flow-9`).
//!
//! Entity resolution agrees these refer to the same API operation and agent, the graph links
//! them with observed edges (plus one explicit, non-causal `CorrelatedWith` association to the
//! network flow), and correlation reconstructs a single incident candidate that carries all the
//! supporting evidence — without inventing a causal edge for the correlation hop.

use chrono::{DateTime, TimeZone, Utc};

use evidence_graph_core::{AssertionKind, Edge, EdgeType, Node, NodeType, TemporalGraph};
use evidence_graph_correlate::{Correlator, IncidentCandidate};
use evidence_graph_entity::{
    Alias, DeterministicKey, Entity, EntityResolver, EntityType, ResolutionMethod,
};

fn at(min: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 9, min, 0).unwrap()
}

/// The result of running the scenario.
pub struct ScenarioOutput {
    /// Whether the agent alias resolved to the expected entity.
    pub agent_resolved: bool,
    /// The reconstructed incident candidate.
    pub incident: IncidentCandidate,
}

/// Build the resolver with the entities the three engines reference.
fn build_resolver() -> EntityResolver {
    let mut r = EntityResolver::new();
    r.add_entity(Entity::new("agent-7", "alpha", EntityType::Agent, "assistant-7"));
    r.add_entity(Entity::new("api-orders", "alpha", EntityType::Api, "GET /orders/{id}"));
    r.add_entity(Entity::new("res-bravo-order", "alpha", EntityType::Resource, "order:order-bravo-1"));
    r.add_alias(Alias {
        alias: "assistant-7".into(),
        entity_id: "agent-7".into(),
        tenant_id: "alpha".into(),
        method: ResolutionMethod::Deterministic {
            key: DeterministicKey::AgentId,
        },
        valid_from: at(0),
        valid_to: None,
    })
    .expect("alias is in-tenant");
    r
}

/// Build the temporal graph linking the three engines' observations.
fn build_graph() -> TemporalGraph {
    let mut g = TemporalGraph::new();
    for (id, ty) in [
        ("finding-bola", NodeType::Finding),
        ("api-orders", NodeType::Api),
        ("agent-7", NodeType::Agent),
        ("res-bravo-order", NodeType::Resource),
        ("flow-9", NodeType::Workload),
    ] {
        g.add_node(Node::new(id, "alpha", ty));
    }

    // AuthZ finding affects the API operation (observed).
    g.add_edge(observed("ed-finding-api", EdgeType::Affects, "finding-bola", "api-orders", &["authz-finding-1"]))
        .unwrap();
    // The agent called that API operation (observed by AgentTrace).
    g.add_edge(observed("ed-agent-api", EdgeType::Calls, "agent-7", "api-orders", &["agenttrace-span-1"]))
        .unwrap();
    // The API access touched the cross-tenant resource (observed).
    g.add_edge(observed("ed-api-res", EdgeType::Accesses, "api-orders", "res-bravo-order", &["gateway-evt-1"]))
        .unwrap();
    // The response was carried by a network flow — but we only *correlate* the flow by timing
    // and size, we did not observe causation, so this edge is inferred + association-only.
    g.add_edge(Edge {
        id: "ed-res-flow".into(),
        tenant_id: "alpha".into(),
        edge_type: EdgeType::CorrelatedWith,
        src: "res-bravo-order".into(),
        dst: "flow-9".into(),
        valid_from: at(0),
        valid_to: None,
        provenance_event_ids: vec!["eastwest-flow-9".into()],
        assertion_kind: AssertionKind::InferredStat,
        confidence: 0.55,
        rule_id: Some("flow-size-time-correlation-v1".into()),
    })
    .unwrap();

    g
}

fn observed(id: &str, ty: EdgeType, src: &str, dst: &str, evidence: &[&str]) -> Edge {
    Edge {
        id: id.into(),
        tenant_id: "alpha".into(),
        edge_type: ty,
        src: src.into(),
        dst: dst.into(),
        valid_from: at(0),
        valid_to: None,
        provenance_event_ids: evidence.iter().map(|s| s.to_string()).collect(),
        assertion_kind: AssertionKind::Observed,
        confidence: 0.95,
        rule_id: None,
    }
}

/// Run the scenario and return the resolution check and reconstructed incident.
pub fn run() -> ScenarioOutput {
    let resolver = build_resolver();
    let agent_resolved = resolver.resolve("alpha", "assistant-7", at(5)).entity_id() == Some("agent-7");

    let graph = build_graph();
    let incident = Correlator::default()
        .candidate_from_seed(&graph, "finding-bola", at(5))
        .expect("the finding connects to corroborating evidence");

    ScenarioOutput {
        agent_resolved,
        incident,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_incident_with_all_supporting_evidence() {
        let out = run();
        assert!(out.agent_resolved);
        let inc = &out.incident;
        // all four engines' evidence items are gathered
        for ev in [
            "authz-finding-1",
            "gateway-evt-1",
            "eastwest-flow-9",
        ] {
            assert!(inc.supporting_event_ids.contains(&ev.to_string()), "missing {ev}");
        }
        // the network-flow link is association-only, so the candidate is flagged accordingly
        assert!(inc.uses_correlation_only);
        assert!(inc.uses_inferred_edges);
        assert!(!inc.is_fully_grounded());
        // the weakest link (the 0.55 correlation edge) bounds the score
        assert!((inc.score - 0.55).abs() < 1e-9);
    }

    #[test]
    fn does_not_invent_a_causal_chain_for_the_correlation_hop() {
        let out = run();
        // the rule behind the only inferred/association hop is named, not hidden
        assert!(out.incident.rule_ids.contains(&"flow-size-time-correlation-v1".to_string()));
    }
}
