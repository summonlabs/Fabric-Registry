// Example 3 — idempotent replay versus conflicting and stale requests.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "support.hpp"

int main() {
  fabric_registry::Registry registry;

  fabric_registry::RegisterEntityRequest request;
  request.attempt = example::attempt_from("ex3-register");
  request.authority = registry.local_authority();
  request.entity_class = fabric_registry::EntityClass::Switch;
  request.derivation_namespace = "example/fabric-a";
  request.friendly_name = "spine-02";
  request.facts.push_back(example::serial_fact("SPINE-0002"));
  request.provenance = example::real_provenance("operator-import", "example");
  request.evidence_class = fabric_registry::EvidenceClass::DurableAuthority;

  const fabric_registry::Outcome first = registry.register_entity(request);
  example::report(first, "first");
  if (!first.committed()) {
    return example::fail("the first request must commit");
  }
  const fabric_registry::RegistryGeneration after_first = registry.stats().generation;

  // The exact same request replayed is idempotent: no new generation is spent.
  const fabric_registry::Outcome replayed = registry.register_entity(request);
  example::report(replayed, "replay");
  if (replayed.code != fabric_registry::OutcomeCode::Idempotent) {
    return example::fail("an exact replay must be reported as idempotent");
  }
  if (!(registry.stats().generation == after_first)) {
    return example::fail("an idempotent replay must not advance the registry generation");
  }

  // The same attempt identifier with different content is a conflicting replay.
  fabric_registry::RegisterEntityRequest tampered = request;
  tampered.friendly_name = "spine-02-renamed";
  const fabric_registry::Outcome conflicting = registry.register_entity(tampered);
  example::report(conflicting, "conflicting replay");
  if (conflicting.code != fabric_registry::OutcomeCode::ConflictingReplay) {
    return example::fail("reusing an attempt identifier with different content must be rejected");
  }

  // A request that expected an older generation is stale and changes nothing.
  fabric_registry::RegisterEntityRequest stale = request;
  stale.attempt = example::attempt_from("ex3-stale");
  stale.expected_generation = fabric_registry::RecordGeneration(1);
  stale.friendly_name = "spine-02-renamed";
  const fabric_registry::Outcome updated = registry.register_entity(stale);
  example::report(updated, "update at generation 1");
  if (!updated.committed()) {
    return example::fail("an update at the current generation must commit");
  }
  fabric_registry::RegisterEntityRequest stale_again = stale;
  stale_again.attempt = example::attempt_from("ex3-stale-again");
  const fabric_registry::Outcome rejected = registry.register_entity(stale_again);
  example::report(rejected, "stale update");
  if (rejected.code != fabric_registry::OutcomeCode::StaleGeneration) {
    return example::fail("an update against a superseded generation must be rejected as stale");
  }
  std::cout << rejected.render();
  return 0;
}
