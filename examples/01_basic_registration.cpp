// Example 1 — basic canonical registration.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "support.hpp"

int main() {
  fabric_registry::Registry registry;

  fabric_registry::RegisterEntityRequest request;
  request.attempt = example::attempt_from("ex1-register");
  request.authority = registry.local_authority();
  request.entity_class = fabric_registry::EntityClass::Switch;
  request.derivation_namespace = "example/fabric-a";
  request.friendly_name = "leaf-01";
  request.facts.push_back(example::serial_fact("MT2314X0001"));
  fabric_registry::IdentityFact chassis;
  chassis.kind = fabric_registry::IdentityFactKind::ChassisId;
  chassis.value = "CHS-7781";
  request.facts.push_back(chassis);
  request.provenance = example::real_provenance("operator-import", "example");
  request.evidence_class = fabric_registry::EvidenceClass::DurableAuthority;
  request.admission = fabric_registry::AdmissionMode::RequireCurrent;

  const fabric_registry::Outcome outcome = registry.register_entity(request);
  example::report(outcome, "register");
  if (!outcome.committed()) {
    return example::fail("the registration should have committed");
  }
  std::cout << "canonical identity: " << outcome.record->to_string() << "\n";
  std::cout << "record generation: " << outcome.record_generation->to_string() << "\n";

  std::shared_ptr<const fabric_registry::EntityRecord> record;
  const fabric_registry::Outcome found = registry.lookup(*outcome.record, record);
  if (!found.committed()) {
    return example::fail("the record should be found by its canonical identity");
  }
  std::cout << fabric_registry::render_record(*record);

  // The identity is derived from the strong facts in an explicit namespace: the
  // same facts always derive the same identity, on any machine.
  fabric_registry::RegisterEntityRequest repeated = request;
  repeated.attempt = example::attempt_from("ex1-register-second-attempt");
  const fabric_registry::Outcome again = registry.register_entity(repeated);
  if (!again.committed() || !(again.record == outcome.record)) {
    return example::fail("re-deriving the identity from the same facts must find the same record");
  }
  std::cout << "re-derivation matched the existing record without creating a second one\n";
  return 0;
}
