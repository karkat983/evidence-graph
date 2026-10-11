//! Sample: reconstruct a cross-layer incident from multi-engine evidence.
//!
//! Running this binary plays the built-in scenario — an AuthZ BOLA finding, an AgentTrace tool
//! call, and an EastWest network flow all about one cross-tenant read — and prints the single
//! incident candidate the correlator reconstructs, with its evidence, labels and score.

mod scenario;

use serde_json::json;

fn main() {
    let out = scenario::run();
    let inc = &out.incident;

    let summary = json!({
        "agent_alias_resolved": out.agent_resolved,
        "incident": {
            "id": inc.id,
            "tenant_id": inc.tenant_id,
            "seed": inc.seed,
            "involved_nodes": inc.involved_nodes,
            "supporting_event_ids": inc.supporting_event_ids,
            "rule_ids": inc.rule_ids,
            "uses_inferred_edges": inc.uses_inferred_edges,
            "uses_correlation_only": inc.uses_correlation_only,
            "missing_context": inc.missing_context,
            "score": inc.score,
            "score_method": format!("{:?}", inc.score_method),
            "fully_grounded": inc.is_fully_grounded(),
        }
    });

    println!("{}", serde_json::to_string_pretty(&summary).expect("summary serializes"));
}
