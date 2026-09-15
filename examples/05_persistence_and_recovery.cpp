// Example 5 — persistence, coordinator restart and conservative recovery.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <filesystem>

#include "support.hpp"

int main() {
  const std::filesystem::path state_path =
      std::filesystem::temp_directory_path() / "fabric-registry-example-05.state";
  std::error_code error;
  std::filesystem::remove(state_path, error);
  std::filesystem::remove(fabric_registry::persistence::temporary_path_for(state_path), error);

  fabric_registry::CanonicalId durable_id;
  {
    fabric_registry::Registry registry;

    fabric_registry::RegisterEntityRequest durable;
    durable.attempt = example::attempt_from("ex5-durable");
    durable.authority = registry.local_authority();
    durable.entity_class = fabric_registry::EntityClass::Switch;
    durable.derivation_namespace = "example/fabric-a";
    durable.friendly_name = "durable-switch";
    durable.facts.push_back(example::serial_fact("DURABLE-1"));
    durable.provenance = example::real_provenance("operator-import", "example");
    durable.evidence_class = fabric_registry::EvidenceClass::DurableAuthority;
    const fabric_registry::Outcome durable_outcome = registry.register_entity(durable);
    if (!durable_outcome.committed()) {
      return example::fail("the durable registration must commit");
    }
    durable_id = *durable_outcome.record;

    fabric_registry::RegisterEntityRequest ephemeral;
    ephemeral.attempt = example::attempt_from("ex5-ephemeral");
    ephemeral.authority = registry.local_authority();
    ephemeral.entity_class = fabric_registry::EntityClass::Nic;
    ephemeral.derivation_namespace = "example/fabric-a";
    ephemeral.friendly_name = "agent-observed-nic";
    ephemeral.facts.push_back(example::serial_fact("EPHEMERAL-1"));
    ephemeral.provenance = example::real_provenance("device-agent", "example-agent");
    ephemeral.evidence_class = fabric_registry::EvidenceClass::ProcessBound;
    const fabric_registry::Outcome ephemeral_outcome = registry.register_entity(ephemeral);
    if (!ephemeral_outcome.committed()) {
      return example::fail("the process-bound registration must commit");
    }

    const fabric_registry::Outcome saved = registry.save(state_path);
    example::report(saved, "save");
    if (!saved.committed()) {
      return example::fail("the state must be written");
    }
  }

  // A fresh registry, as a restarted coordinator would build.
  fabric_registry::Registry recovered;
  fabric_registry::RecoveryReport report;
  const fabric_registry::Outcome loaded = recovered.load(state_path, report);
  example::report(loaded, "load");
  if (!loaded.committed()) {
    return example::fail("the state must load");
  }
  std::cout << report.render();

  std::shared_ptr<const fabric_registry::EntityRecord> record;
  if (!recovered.lookup(durable_id, record).committed()) {
    return example::fail("canonical identity must survive a restart");
  }
  std::cout << "durable identity survived: " << record->id.to_string()
            << " lifecycle=" << fabric_registry::to_string(record->lifecycle) << "\n";
  if (record->lifecycle != fabric_registry::Lifecycle::Current) {
    return example::fail("administrative evidence must still be current after a restart");
  }

  for (const fabric_registry::CanonicalId& id : recovered.all_ids(100)) {
    std::shared_ptr<const fabric_registry::EntityRecord> candidate;
    recovered.lookup(id, candidate);
    if (candidate->evidence.evidence_class == fabric_registry::EvidenceClass::ProcessBound &&
        candidate->lifecycle != fabric_registry::Lifecycle::RevalidationRequired) {
      return example::fail("process-bound evidence must not be recovered as current");
    }
  }
  std::cout << "process-bound evidence was conservatively demoted\n";

  std::filesystem::remove(state_path, error);
  std::filesystem::remove(fabric_registry::persistence::temporary_path_for(state_path), error);
  return 0;
}
