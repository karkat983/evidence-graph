# evidence-graph

The correlation engine of [Lattivant](https://github.com/karkat983), an evidence-first security
platform. It resolves *what* the platform is talking about, records observations and inferences
in a provenance-aware temporal graph, and assembles cross-layer incident candidates — joining an
AuthZ finding, an agent's observed side effect and a network flow into one defensible cluster of
evidence.

Its whole job is to connect signals **without conflating association with causation**. That
discipline is enforced in the types, not left to convention:

- every edge states whether it is **observed** (and links to its evidence) or **inferred** (and
  names the rule that produced it);
- the `CorrelatedWith` relation is non-causal by construction and can never be stored as an
  observed fact;
- incident candidates are scored by their **weakest link**, never by multiplying confidences
  into a false probability, and they carry their missing context rather than assuming it.

## Crates

| Crate | What it provides |
|-------|------------------|
| [`evidence-graph-entity`](crates/evidence-graph-entity) | **Identity & asset resolution.** Resolves a name to an entity deterministically where it can (OIDC subject, instance id, Kubernetes UID, agent id, canonical API key) and probabilistically where it must — with time-bounded, tenant-isolated aliases, conflict handling, and merge/split/correction audit. A genuinely ambiguous match stays *explicitly ambiguous*. |
| [`evidence-graph-core`](crates/evidence-graph-core) | **The provenance-aware temporal graph.** Typed nodes and time-bounded edges carrying assertion kind, provenance and confidence; a store that enforces the provenance invariants at insert time; and bounded, time-scoped, tenant-isolated traversal that returns every supporting evidence reference along a path. |
| [`evidence-graph-correlate`](crates/evidence-graph-correlate) | **Cross-layer correlation.** Expands from a seed over the graph to build incident candidates from multi-source evidence, scoring by weakest link, labelling inference and association, deduplicating by evidence, and folding in analyst feedback. |
| [`evidence-graph-sample`](crates/evidence-graph-sample) | A worked scenario that reconstructs one cross-tenant-read incident from three engines' observations and prints the resulting candidate. |

## Try it

```sh
cargo run -p evidence-graph-sample
```

The scenario: an AuthZ BOLA finding, an AgentTrace tool call, and an EastWest network flow all
describe the same agent reading another tenant's order. Entity resolution agrees they refer to
the same agent and operation; the graph links them with observed edges plus one explicit,
non-causal correlation to the network flow; and the correlator reconstructs a single incident
candidate carrying all the supporting evidence — flagged as resting partly on association, with
its score bounded by that weakest (0.55) correlation edge, and the inference rule named rather
than hidden.

```sh
cargo test              # all crates
cargo clippy --all-targets
```

Requires a recent stable Rust toolchain (edition 2021, rustc ≥ 1.80). The platform event
envelope is available from
[`lattivant-platform`](https://github.com/karkat983/lattivant-platform).

## License

MIT. See [LICENSE](LICENSE).

## Authorized testing only

All tenants, identities, resources and events in this repository are synthetic. Use these tools
only against systems you own or are explicitly authorized to test.
