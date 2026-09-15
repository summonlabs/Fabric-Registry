// Example 2 — alias resolution and alias scoping.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "support.hpp"

int main() {
  fabric_registry::Registry registry;
  const fabric_registry::FabricId fabric = fabric_registry::FabricId::parse("11111111111111111111111111111111").value();

  fabric_registry::RegisterEntityRequest request;
  request.attempt = example::attempt_from("ex2-register");
  request.authority = registry.local_authority();
  request.entity_class = fabric_registry::EntityClass::Switch;
  request.derivation_namespace = "example/fabric-a";
  request.friendly_name = "spine-01";
  request.facts.push_back(example::serial_fact("SPINE-0001"));
  request.scope.fabric = fabric;
  fabric_registry::AliasInput host_name;
  host_name.alias_namespace = fabric_registry::AliasNamespace::HostName;
  host_name.value = "spine-01";
  request.aliases.push_back(host_name);
  fabric_registry::AliasInput asset;
  asset.alias_namespace = fabric_registry::AliasNamespace::OperatorLabel;
  asset.value = "rack 4 / u12";
  request.aliases.push_back(asset);
  request.provenance = example::real_provenance("operator-import", "example");
  request.evidence_class = fabric_registry::EvidenceClass::DurableAuthority;

  const fabric_registry::Outcome outcome = registry.register_entity(request);
  example::report(outcome, "register");
  if (!outcome.committed()) {
    return example::fail("the registration should have committed");
  }

  const std::optional<fabric_registry::AliasKey> key =
      fabric_registry::AliasKey::parse("host-name:fabric:11111111111111111111111111111111=spine-01");
  if (!key.has_value()) {
    return example::fail("the alias key should parse");
  }
  std::shared_ptr<const fabric_registry::EntityRecord> record;
  const fabric_registry::Outcome resolved = registry.lookup_by_alias(*key, record);
  example::report(resolved, "resolve");
  if (!resolved.committed()) {
    return example::fail("the alias should resolve");
  }
  std::cout << "alias resolved to " << record->id.to_string() << "\n";

  // An operator label is informational: it is stored on the record but it is
  // never an identity and never resolves.
  const std::optional<fabric_registry::AliasKey> informational =
      fabric_registry::AliasKey::parse("operator-label:info=rack 4 / u12");
  std::shared_ptr<const fabric_registry::EntityRecord> ignored;
  const fabric_registry::Outcome rejected = registry.lookup_by_alias(*informational, ignored);
  example::report(rejected, "resolve informational");
  if (rejected.committed()) {
    return example::fail("informational aliases must never resolve to an identity");
  }

  // The same host name in a different fabric is a different key entirely.
  const std::optional<fabric_registry::AliasKey> other_fabric =
      fabric_registry::AliasKey::parse("host-name:fabric:22222222222222222222222222222222=spine-01");
  std::shared_ptr<const fabric_registry::EntityRecord> other;
  const fabric_registry::Outcome not_found = registry.lookup_by_alias(*other_fabric, other);
  example::report(not_found, "resolve in another fabric");
  if (not_found.committed()) {
    return example::fail("an alias in another fabric must not resolve to this record");
  }
  return 0;
}
