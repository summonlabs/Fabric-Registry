// Example 4 — supersession, retirement and permanent closure.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "support.hpp"

int main() {
  fabric_registry::Registry registry;
  fabric_registry::Registry& const_registry = registry;

  const auto make_request = [&registry](const std::string& label, const std::string& serial) {
    fabric_registry::RegisterEntityRequest request;
    request.attempt = example::attempt_from(label);
    request.authority = registry.local_authority();
    request.entity_class = fabric_registry::EntityClass::Switch;
    request.derivation_namespace = "example/fabric-a";
    request.friendly_name = label;
    request.facts.push_back(example::serial_fact(serial));
    request.provenance = example::real_provenance("operator-import", "example");
    request.evidence_class = fabric_registry::EvidenceClass::DurableAuthority;
    return request;
  };

  const fabric_registry::Outcome original = registry.register_entity(make_request("ex4-original", "SW-1000"));
  if (!original.committed()) {
    return example::fail("the original registration must commit");
  }
  const fabric_registry::Outcome replacement = registry.register_entity(make_request("ex4-replacement", "SW-2000"));
  if (!replacement.committed()) {
    return example::fail("the replacement registration must commit");
  }

  fabric_registry::SupersedeEntityRequest supersede;
  supersede.attempt = example::attempt_from("ex4-supersede");
  supersede.authority = registry.local_authority();
  supersede.target = *original.record;
  supersede.expected_generation = *original.record_generation;
  supersede.successor = *replacement.record;
  supersede.reason = "chassis replaced under warranty";
  const fabric_registry::Outcome superseded = registry.supersede_entity(supersede);
  example::report(superseded, "supersede");
  if (!superseded.committed()) {
    return example::fail("the supersession must commit");
  }

  // The superseded identity can never become current again.
  fabric_registry::RegisterEntityRequest resurrect = make_request("ex4-resurrect", "SW-1000");
  resurrect.canonical_id = original.record;
  resurrect.derivation_namespace.clear();
  const fabric_registry::Outcome blocked = registry.register_entity(resurrect);
  example::report(blocked, "resurrect superseded");
  if (blocked.code != fabric_registry::OutcomeCode::Superseded) {
    return example::fail("a superseded identity must refuse further mutation");
  }

  const fabric_registry::Outcome reference =
      const_registry.validate_reference(*original.record, std::nullopt);
  example::report(reference, "validate reference to superseded record");
  if (reference.code != fabric_registry::OutcomeCode::NotCurrent) {
    return example::fail("a superseded record must not validate as current");
  }

  fabric_registry::TombstoneEntityRequest tombstone;
  tombstone.attempt = example::attempt_from("ex4-tombstone");
  tombstone.authority = registry.local_authority();
  tombstone.target = *original.record;
  tombstone.reason = "identity permanently closed";
  const fabric_registry::Outcome tombstoned = registry.tombstone_entity(tombstone);
  example::report(tombstoned, "tombstone");
  if (!tombstoned.committed()) {
    return example::fail("a superseded record may still be tombstoned");
  }
  const fabric_registry::Outcome after_tombstone = registry.tombstone_entity(tombstone);
  example::report(after_tombstone, "tombstone again");
  if (after_tombstone.code != fabric_registry::OutcomeCode::Idempotent) {
    return example::fail("tombstoning twice must be idempotent, not a new generation");
  }

  std::cout << fabric_registry::render_history(
      [&] {
        fabric_registry::RecordHistory history;
        registry.history(*original.record, history);
        return history;
      }());
  return 0;
}
