// Fabric Registry — integration coverage of the registry engine.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every case drives the public Registry surface and asserts on a specific
// OutcomeCode. A case that asserts a rejection also asserts that the registry
// counters did not move, because a refused request must leave no trace.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "registry_test_support.hpp"
#include "test_harness.hpp"

namespace {

using namespace fabric_registry;

/// Enumeration bound used by the "list everything" assertions.
constexpr std::size_t kEnumerateAll = 1'000'000;

IdBytes bytes_with(std::uint8_t tag, std::uint8_t salt) {
  IdBytes bytes{};
  bytes[0] = tag;
  bytes[15] = salt;
  return bytes;
}

FabricId fabric_with(std::uint8_t salt) { return FabricId::from_bytes(bytes_with(0xF1u, salt)); }

CanonicalId canonical_with(EntityClass entity_class, std::uint8_t salt) {
  return CanonicalId(entity_class, bytes_with(0xC1u, salt));
}

PublisherId publisher_with(std::uint8_t salt) { return PublisherId::from_bytes(bytes_with(0xE1u, salt)); }

std::uint64_t generation_of(const Outcome& outcome) {
  return outcome.record_generation.has_value() ? outcome.record_generation->value() : 0u;
}

/// The counters a refused mutation must leave exactly as they were.
struct Counters {
  std::size_t entities{0};
  std::size_t indexed_aliases{0};
  std::uint64_t generation{0};
  std::uint64_t epoch{0};
};

Counters counters_of(const RegistryStats& stats) {
  Counters counters;
  counters.entities = stats.entities;
  counters.indexed_aliases = stats.indexed_aliases;
  counters.generation = stats.generation.value();
  counters.epoch = stats.epoch.value();
  return counters;
}

bool unchanged(const Counters& left, const Counters& right) {
  return left.entities == right.entities && left.indexed_aliases == right.indexed_aliases &&
         left.generation == right.generation && left.epoch == right.epoch;
}

std::string describe(const Counters& counters) {
  return "entities=" + std::to_string(counters.entities) + " aliases=" + std::to_string(counters.indexed_aliases) +
         " generation=" + std::to_string(counters.generation) + " epoch=" + std::to_string(counters.epoch);
}

/// A committed registration: the outcome and the identity it produced.
struct Registration {
  Outcome outcome;
  CanonicalId id{};
};

Registration register_device(Registry& registry, const std::string& label, const std::string& serial,
                             EntityClass entity_class = EntityClass::Switch,
                             const std::string& derivation_namespace = "test/namespace-a",
                             EvidenceClass evidence_class = EvidenceClass::DurableAuthority) {
  Registration registration;
  registration.outcome = registry.register_entity(
      frtest::device_request(registry, label, serial, entity_class, derivation_namespace, evidence_class));
  if (registration.outcome.record.has_value()) {
    registration.id = *registration.outcome.record;
  }
  return registration;
}

bool holds_alias(const std::shared_ptr<const EntityRecord>& record, const AliasKey& key) {
  return record != nullptr && std::find(record->aliases.begin(), record->aliases.end(), key) != record->aliases.end();
}

/// The fully qualified key of a host-name alias inside one fabric. Host names
/// are fabric-scoped, so the key carries the fabric qualification.
AliasKey host_alias_key(const RegistryLimits& limits, const FabricId& fabric, const std::string& value) {
  AliasKey key;
  const AliasNameResult name = canonicalize_alias(AliasNamespace::HostName, value, limits.max_string_bytes);
  if (name) {
    AliasScopeInput scope;
    scope.fabric = fabric;
    scope.entity_class = EntityClass::Switch;
    const AliasKeyResult qualified = make_alias_key(*name.name, scope);
    if (qualified) {
      key = *qualified.key;
    }
  }
  return key;
}

/// The fully qualified key of an informational (operator-label) alias.
AliasKey label_alias_key(const RegistryLimits& limits, const std::string& value) {
  AliasKey key;
  const AliasNameResult name = canonicalize_alias(AliasNamespace::OperatorLabel, value, limits.max_string_bytes);
  if (name) {
    AliasScopeInput scope;
    const AliasKeyResult qualified = make_alias_key(*name.name, scope);
    if (qualified) {
      key = *qualified.key;
    }
  }
  return key;
}

AliasMutationRequest alias_request(Registry& registry, const std::string& label, const CanonicalId& target,
                                  const AliasInput& alias) {
  AliasMutationRequest request;
  request.attempt = frtest::attempt_from(label);
  request.authority = registry.local_authority();
  request.target = target;
  request.alias = alias;
  return request;
}

AliasMutationRequest alias_request(Registry& registry, const std::string& label, const CanonicalId& target,
                                  const AliasInput& alias, RecordGeneration expected_generation) {
  AliasMutationRequest request = alias_request(registry, label, target, alias);
  request.expected_generation = expected_generation;
  return request;
}

// ---------------------------------------------------------------------------
// Registration and identity derivation
// ---------------------------------------------------------------------------

FR_TEST_CASE(registry, derived_identity_commits_and_is_addressable) {
  auto registry = frtest::make_registry(7);
  const std::vector<IdentityFact> facts{frtest::serial_fact("SN-DERIVE-1")};

  const Registration created = register_device(*registry, "derive-1", "SN-DERIVE-1");
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());
  FR_CHECK_EQ(generation_of(created.outcome), 1u);
  FR_CHECK(created.outcome.record.has_value());
  FR_CHECK(created.outcome.evidence_generation.has_value());
  FR_CHECK_EQ(created.outcome.evidence_generation->value(), 1u);

  const CanonicalIdResult derived =
      derive_canonical_id(EntityClass::Switch, "test/namespace-a", facts, registry->limits().max_string_bytes);
  FR_CHECK_MSG(static_cast<bool>(derived), std::string(to_string(derived.issue)));
  FR_CHECK_EQ(created.id, *derived.id);

  std::shared_ptr<const EntityRecord> record;
  const Outcome lookup = registry->lookup(created.id, record);
  FR_CHECK_EQ(lookup.code, OutcomeCode::Committed);
  FR_CHECK(record != nullptr);
  FR_CHECK_EQ(record->record_generation.value(), 1u);
  FR_CHECK_EQ(record->creation_generation.value(), 1u);
  FR_CHECK(record->lifecycle == Lifecycle::Current);
  FR_CHECK_EQ(record->entity_class, EntityClass::Switch);
  FR_CHECK_EQ(record->derivation_namespace, std::string("test/namespace-a"));
  FR_CHECK(!record->fingerprint.is_null());
  FR_CHECK(!record->hardware_identity.is_null());
  FR_CHECK(record->hardware_identity == compute_stable_hardware_identity(facts));
  FR_CHECK_EQ(record->evidence.publisher, registry->local_authority().publisher);
}

FR_TEST_CASE(registry, derivation_namespace_is_part_of_the_identity) {
  auto registry_a = frtest::make_registry(11);
  auto registry_b = frtest::make_registry(12);
  const std::vector<IdentityFact> facts{frtest::serial_fact("SN-NS-1")};

  RegisterEntityRequest request_a =
      frtest::device_request(*registry_a, "namespace-a", "SN-NS-1", EntityClass::Switch, "test/namespace-a");
  RegisterEntityRequest request_b =
      frtest::device_request(*registry_b, "namespace-b", "SN-NS-1", EntityClass::Switch, "test/namespace-b");
  const Outcome outcome_a = registry_a->register_entity(request_a);
  const Outcome outcome_b = registry_b->register_entity(request_b);
  FR_CHECK_MSG(outcome_a.committed(), outcome_a.render());
  FR_CHECK_MSG(outcome_b.committed(), outcome_b.render());
  FR_CHECK(outcome_a.record.has_value());
  FR_CHECK(outcome_b.record.has_value());

  const CanonicalIdResult derived_a =
      derive_canonical_id(EntityClass::Switch, "test/namespace-a", facts, registry_a->limits().max_string_bytes);
  const CanonicalIdResult derived_b =
      derive_canonical_id(EntityClass::Switch, "test/namespace-b", facts, registry_b->limits().max_string_bytes);
  FR_CHECK(static_cast<bool>(derived_a));
  FR_CHECK(static_cast<bool>(derived_b));
  FR_CHECK_EQ(*outcome_a.record, *derived_a.id);
  FR_CHECK_EQ(*outcome_b.record, *derived_b.id);
  FR_CHECK_MSG(*outcome_a.record != *outcome_b.record,
               "the derivation namespace must be part of the derived identity");

  // The bytes of the two 128-bit identifiers are what a namespace-insensitive
  // derivation would have produced identically.
  FR_CHECK(outcome_a.record->bytes() != outcome_b.record->bytes());

  // A registry that already holds the hardware under one namespace does not
  // mint a second record for the same physical device under another.
  RegisterEntityRequest replay =
      frtest::device_request(*registry_a, "namespace-b-in-a", "SN-NS-1", EntityClass::Switch, "test/namespace-b");
  const Outcome replay_outcome = registry_a->register_entity(replay);
  FR_CHECK_MSG(replay_outcome.committed(), replay_outcome.render());
  FR_CHECK(replay_outcome.record.has_value());
  FR_CHECK_EQ(*replay_outcome.record, *outcome_a.record);
  FR_CHECK_EQ(replay_outcome.match, MatchClass::StableHardware);
  FR_CHECK_EQ(registry_a->stats().entities, 1u);
}

FR_TEST_CASE(registry, re_registration_updates_the_existing_record) {
  auto registry = frtest::make_registry(21);
  const Registration created = register_device(*registry, "update-create", "SN-UPD-1");
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());
  FR_CHECK_EQ(registry->stats().entities, 1u);

  const Registration updated = register_device(*registry, "update-second", "SN-UPD-1");
  FR_CHECK_MSG(updated.outcome.committed(), updated.outcome.render());
  FR_CHECK_EQ(updated.id, created.id);
  FR_CHECK_EQ(generation_of(updated.outcome), 2u);
  FR_CHECK_EQ(registry->stats().entities, 1u);

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record != nullptr);
  FR_CHECK_EQ(record->record_generation.value(), 2u);
  FR_CHECK_EQ(record->creation_generation.value(), 1u);
  FR_CHECK_EQ(record->evidence_generation.value(), 2u);
  FR_CHECK_EQ(record->friendly_name, std::string("update-second"));
  FR_CHECK(record->created_by == registry->local_authority().publisher);
}

FR_TEST_CASE(registry, exact_replay_is_idempotent) {
  auto registry = frtest::make_registry(31);
  RegisterEntityRequest request = frtest::device_request(*registry, "replay-exact", "SN-REPLAY-1");
  const Outcome first = registry->register_entity(request);
  FR_CHECK_MSG(first.committed(), first.render());
  const Counters before = counters_of(registry->stats());

  const Outcome replay = registry->register_entity(request);
  FR_CHECK_MSG(replay.code == OutcomeCode::Idempotent, replay.render());
  FR_CHECK(replay.record.has_value());
  FR_CHECK_EQ(*replay.record, *first.record);
  FR_CHECK_EQ(replay.request_digest->to_string(), first.request_digest->to_string());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "an idempotent replay advanced state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(registry, attempt_reuse_with_new_content_is_a_conflicting_replay) {
  auto registry = frtest::make_registry(41);
  RegisterEntityRequest request = frtest::device_request(*registry, "replay-conflict", "SN-REPLAY-2");
  const Outcome first = registry->register_entity(request);
  FR_CHECK_MSG(first.committed(), first.render());
  const Counters before = counters_of(registry->stats());

  request.friendly_name = "replay-conflict-renamed";
  const Outcome reused = registry->register_entity(request);
  FR_CHECK_MSG(reused.code == OutcomeCode::ConflictingReplay, reused.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a conflicting replay advanced state: " + describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(*first.record, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->friendly_name, std::string("replay-conflict"));
  FR_CHECK_EQ(record->record_generation.value(), 1u);
}

FR_TEST_CASE(registry, expected_generation_guards_the_update) {
  auto registry = frtest::make_registry(51);
  const Registration created = register_device(*registry, "generation-create", "SN-GEN-1");
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());
  FR_CHECK_EQ(generation_of(created.outcome), 1u);

  UpdateEvidenceRequest update;
  update.attempt = frtest::attempt_from("generation-update");
  update.authority = registry->local_authority();
  update.target = created.id;
  update.expected_generation = RecordGeneration(1);
  update.facts.push_back(frtest::serial_fact("SN-GEN-1"));
  update.provenance = frtest::real_provenance();
  update.evidence_class = EvidenceClass::DurableAuthority;
  const Outcome committed = registry->update_evidence(update);
  FR_CHECK_MSG(committed.committed(), committed.render());
  FR_CHECK_EQ(generation_of(committed), 2u);

  const Counters before = counters_of(registry->stats());
  update.attempt = frtest::attempt_from("generation-update-stale");
  const Outcome stale = registry->update_evidence(update);
  FR_CHECK_MSG(stale.code == OutcomeCode::StaleGeneration, stale.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a stale update advanced state: " + describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->record_generation.value(), 2u);
  FR_CHECK_EQ(record->evidence_generation.value(), 2u);
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

FR_TEST_CASE(registry, alias_attach_lookup_and_detach) {
  auto registry = frtest::make_registry(61);
  const FabricId fabric = fabric_with(1);
  const AliasKey host = host_alias_key(registry->limits(), fabric, "Switch-A.Example.NET");

  RegisterEntityRequest first_request = frtest::device_request(*registry, "alias-first", "SN-ALIAS-1");
  first_request.scope.fabric = fabric;
  const Outcome first = registry->register_entity(first_request);
  FR_CHECK_MSG(first.committed(), first.render());
  const CanonicalId first_id = *first.record;

  const Outcome attached =
      registry->attach_alias(alias_request(*registry, "alias-attach", first_id,
                                           frtest::alias_of(AliasNamespace::HostName, "Switch-A.Example.NET")));
  FR_CHECK_MSG(attached.committed(), attached.render());
  FR_CHECK_EQ(generation_of(attached), 2u);

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(first_id, record).code, OutcomeCode::Committed);
  FR_CHECK(holds_alias(record, host));
  FR_CHECK_EQ(record->aliases.size(), 1u);
  FR_CHECK_EQ(registry->stats().indexed_aliases, 1u);

  std::shared_ptr<const EntityRecord> by_alias;
  const Outcome resolved = registry->lookup_by_alias(host, by_alias);
  FR_CHECK_MSG(resolved.committed(), resolved.render());
  FR_CHECK(by_alias != nullptr);
  FR_CHECK_EQ(by_alias->id, first_id);

  // The record moved to generation 2 with the attach, so an alias mutation that
  // still expects generation 1 must be refused without touching anything.
  const Counters before_stale = counters_of(registry->stats());
  const Outcome stale =
      registry->attach_alias(alias_request(*registry, "alias-stale-generation", first_id,
                                           frtest::alias_of(AliasNamespace::HostName, "switch-a.example.net"),
                                           RecordGeneration(1)));
  FR_CHECK_MSG(stale.code == OutcomeCode::StaleGeneration, stale.render());
  FR_CHECK_MSG(unchanged(before_stale, counters_of(registry->stats())),
               "a stale alias mutation advanced state: " + describe(counters_of(registry->stats())));

  RegisterEntityRequest second_request = frtest::device_request(*registry, "alias-second", "SN-ALIAS-2");
  second_request.scope.fabric = fabric;
  const Outcome second = registry->register_entity(second_request);
  FR_CHECK_MSG(second.committed(), second.render());
  const CanonicalId second_id = *second.record;
  FR_CHECK(second_id != first_id);

  const Counters before_conflict = counters_of(registry->stats());
  const Outcome conflict =
      registry->attach_alias(alias_request(*registry, "alias-conflict", second_id,
                                           frtest::alias_of(AliasNamespace::HostName, "switch-a.example.net")));
  FR_CHECK_MSG(conflict.code == OutcomeCode::AliasConflict, conflict.render());
  FR_CHECK(conflict.record.has_value());
  FR_CHECK_EQ(*conflict.record, first_id);
  FR_CHECK_MSG(unchanged(before_conflict, counters_of(registry->stats())),
               "an alias conflict advanced state: " + describe(counters_of(registry->stats())));

  const Counters before_idempotent = counters_of(registry->stats());
  const Outcome repeat =
      registry->attach_alias(alias_request(*registry, "alias-repeat", first_id,
                                           frtest::alias_of(AliasNamespace::HostName, "switch-a.example.net")));
  FR_CHECK_MSG(repeat.code == OutcomeCode::Idempotent, repeat.render());
  FR_CHECK_MSG(unchanged(before_idempotent, counters_of(registry->stats())),
               "a repeated alias attach advanced state: " + describe(counters_of(registry->stats())));

  const Outcome detached =
      registry->detach_alias(alias_request(*registry, "alias-detach", first_id,
                                           frtest::alias_of(AliasNamespace::HostName, "switch-a.example.net")));
  FR_CHECK_MSG(detached.committed(), detached.render());
  FR_CHECK_EQ(registry->stats().indexed_aliases, 0u);
  FR_CHECK_EQ(registry->lookup(first_id, record).code, OutcomeCode::Committed);
  FR_CHECK(!holds_alias(record, host));
  FR_CHECK_EQ(registry->lookup_by_alias(host, by_alias).code, OutcomeCode::NotFound);

  const Counters before_missing = counters_of(registry->stats());
  const Outcome missing =
      registry->detach_alias(alias_request(*registry, "alias-detach-again", first_id,
                                           frtest::alias_of(AliasNamespace::HostName, "switch-a.example.net")));
  FR_CHECK_MSG(missing.code == OutcomeCode::NotFound, missing.render());
  FR_CHECK_MSG(unchanged(before_missing, counters_of(registry->stats())),
               "a missing detach advanced state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(registry, informational_alias_is_stored_but_never_resolved) {
  auto registry = frtest::make_registry(71);
  RegisterEntityRequest request = frtest::device_request(*registry, "alias-informational", "SN-INFO-1");
  request.aliases.push_back(frtest::alias_of(AliasNamespace::OperatorLabel, "operator-label-42"));
  const Outcome created = registry->register_entity(request);
  FR_CHECK_MSG(created.committed(), created.render());

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(*created.record, record).code, OutcomeCode::Committed);
  const AliasKey key = label_alias_key(registry->limits(), "operator-label-42");
  FR_CHECK_EQ(key.scope, std::string("info"));
  FR_CHECK(holds_alias(record, key));
  FR_CHECK_EQ(registry->stats().aliases, 1u);
  FR_CHECK_EQ(registry->stats().indexed_aliases, 0u);

  std::shared_ptr<const EntityRecord> resolved;
  const Outcome refused = registry->lookup_by_alias(key, resolved);
  FR_CHECK_MSG(refused.code == OutcomeCode::MalformedRequest, refused.render());
  FR_CHECK(resolved == nullptr);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

FR_TEST_CASE(registry, enumeration_is_sorted_unique_and_bounded) {
  auto registry = frtest::make_registry(81);
  std::vector<CanonicalId> switches;
  for (int index = 0; index < 4; ++index) {
    const Registration created =
        register_device(*registry, "enumerate-switch-" + std::to_string(index),
                        "SN-ENUM-S" + std::to_string(index));
    FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());
    switches.push_back(created.id);
  }
  const Registration host =
      register_device(*registry, "enumerate-host", "SN-ENUM-H", EntityClass::Host);
  FR_CHECK_MSG(host.outcome.committed(), host.outcome.render());

  const std::vector<CanonicalId> of_class = registry->entities_of_class(EntityClass::Switch, kEnumerateAll);
  FR_CHECK_EQ(of_class.size(), 4u);
  FR_CHECK(std::is_sorted(of_class.begin(), of_class.end()));
  FR_CHECK(std::adjacent_find(of_class.begin(), of_class.end()) == of_class.end());
  std::sort(switches.begin(), switches.end());
  FR_CHECK(of_class == switches);

  const std::vector<CanonicalId> bounded_class = registry->entities_of_class(EntityClass::Switch, 2);
  FR_CHECK_EQ(bounded_class.size(), 2u);
  FR_CHECK(std::equal(bounded_class.begin(), bounded_class.end(), of_class.begin()));

  const std::vector<CanonicalId> current = registry->entities_of_lifecycle(Lifecycle::Current, kEnumerateAll);
  FR_CHECK_EQ(current.size(), 5u);
  FR_CHECK(std::is_sorted(current.begin(), current.end()));
  FR_CHECK(registry->entities_of_lifecycle(Lifecycle::Retired, kEnumerateAll).empty());

  const std::vector<CanonicalId> all = registry->all_ids(kEnumerateAll);
  FR_CHECK_EQ(all.size(), registry->stats().entities);
  FR_CHECK(std::is_sorted(all.begin(), all.end()));
  FR_CHECK(std::adjacent_find(all.begin(), all.end()) == all.end());

  const std::vector<CanonicalId> bounded_all = registry->all_ids(3);
  FR_CHECK_EQ(bounded_all.size(), 3u);
  FR_CHECK(std::equal(bounded_all.begin(), bounded_all.end(), all.begin()));
}

FR_TEST_CASE(registry, lookup_by_fact_finds_the_exact_canonical_fact) {
  auto registry = frtest::make_registry(91);
  const Registration first = register_device(*registry, "fact-first", "SN-FACT-1");
  const Registration second = register_device(*registry, "fact-second", "SN-FACT-2");
  FR_CHECK(first.outcome.committed());
  FR_CHECK(second.outcome.committed());

  std::vector<CanonicalId> found;
  const Outcome present = registry->lookup_by_fact(frtest::serial_fact("SN-FACT-1"), found);
  FR_CHECK_EQ(present.code, OutcomeCode::Committed);
  FR_CHECK_EQ(found.size(), 1u);
  FR_CHECK_EQ(found.front(), first.id);

  const Outcome absent = registry->lookup_by_fact(frtest::serial_fact("SN-FACT-ABSENT"), found);
  FR_CHECK_EQ(absent.code, OutcomeCode::NotFound);
  FR_CHECK(found.empty());

  // The scope is part of the fact: the same serial in another vendor scope is a
  // different identity input and is not carried by any record.
  const Outcome other_scope =
      registry->lookup_by_fact(frtest::serial_fact("SN-FACT-1", "vendor:0x9999/product:0x0001"), found);
  FR_CHECK_EQ(other_scope.code, OutcomeCode::NotFound);
  FR_CHECK(found.empty());
}

FR_TEST_CASE(registry, validate_reference_tracks_generation_and_authority) {
  auto registry = frtest::make_registry(101);
  const Registration created = register_device(*registry, "reference-create", "SN-REF-1");
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());

  const Outcome current = registry->validate_reference(created.id, RecordGeneration(1));
  FR_CHECK_MSG(current.committed(), current.render());
  FR_CHECK_EQ(generation_of(current), 1u);
  FR_CHECK(registry->is_current(created.id));
  FR_CHECK(registry->is_current(created.id, RecordGeneration(1)));

  const Outcome wrong_generation = registry->validate_reference(created.id, RecordGeneration(2));
  FR_CHECK_MSG(wrong_generation.code == OutcomeCode::StaleGeneration, wrong_generation.render());
  FR_CHECK(!registry->is_current(created.id, RecordGeneration(2)));

  const Outcome unknown = registry->validate_reference(canonical_with(EntityClass::Switch, 0x77), std::nullopt);
  FR_CHECK_MSG(unknown.code == OutcomeCode::NotFound, unknown.render());

  RetireEntityRequest retire;
  retire.attempt = frtest::attempt_from("reference-retire");
  retire.authority = registry->local_authority();
  retire.target = created.id;
  retire.reason = "decommissioned";
  const Outcome retired = registry->retire_entity(retire);
  FR_CHECK_MSG(retired.committed(), retired.render());

  const Outcome not_current = registry->validate_reference(created.id, RecordGeneration(1));
  FR_CHECK_MSG(not_current.code == OutcomeCode::NotCurrent, not_current.render());
  FR_CHECK(!registry->is_current(created.id));
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

FR_TEST_CASE(registry, retire_and_tombstone_close_the_identity) {
  auto registry = frtest::make_registry(111);
  const Registration created = register_device(*registry, "lifecycle-create", "SN-LIFE-1");
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());

  RetireEntityRequest retire;
  retire.attempt = frtest::attempt_from("lifecycle-retire");
  retire.authority = registry->local_authority();
  retire.target = created.id;
  retire.reason = "operator decommissioned the switch";
  const Outcome retired = registry->retire_entity(retire);
  FR_CHECK_MSG(retired.committed(), retired.render());

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Retired);
  FR_CHECK_EQ(record->status_reason, std::string("operator decommissioned the switch"));
  FR_CHECK_EQ(registry->stats().retired_entities, 1u);

  // A retired identity refuses every further mutation attempt.
  const Counters before_register = counters_of(registry->stats());
  const Registration recreated = register_device(*registry, "lifecycle-re-register", "SN-LIFE-1");
  FR_CHECK_MSG(recreated.outcome.code == OutcomeCode::Retired, recreated.outcome.render());
  FR_CHECK_MSG(unchanged(before_register, counters_of(registry->stats())),
               "a retired record was mutated: " + describe(counters_of(registry->stats())));

  UpdateEvidenceRequest update;
  update.attempt = frtest::attempt_from("lifecycle-update");
  update.authority = registry->local_authority();
  update.target = created.id;
  update.facts.push_back(frtest::serial_fact("SN-LIFE-1"));
  update.provenance = frtest::real_provenance();
  update.evidence_class = EvidenceClass::DurableAuthority;
  const Outcome update_outcome = registry->update_evidence(update);
  FR_CHECK_MSG(update_outcome.code == OutcomeCode::Retired, update_outcome.render());
  FR_CHECK_MSG(unchanged(before_register, counters_of(registry->stats())),
               "evidence was updated on a retired record: " + describe(counters_of(registry->stats())));

  TombstoneEntityRequest tombstone;
  tombstone.attempt = frtest::attempt_from("lifecycle-tombstone");
  tombstone.authority = registry->local_authority();
  tombstone.target = created.id;
  tombstone.reason = "identity closed";
  const Outcome tombstoned = registry->tombstone_entity(tombstone);
  FR_CHECK_MSG(tombstoned.committed(), tombstoned.render());
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Tombstoned);
  FR_CHECK(!record->evidence.valid);
  FR_CHECK_EQ(registry->stats().tombstoned_entities, 1u);

  const Counters before_closed = counters_of(registry->stats());
  const Registration after_tombstone = register_device(*registry, "lifecycle-after-tombstone", "SN-LIFE-1");
  FR_CHECK_MSG(after_tombstone.outcome.code == OutcomeCode::Tombstoned, after_tombstone.outcome.render());
  FR_CHECK_MSG(unchanged(before_closed, counters_of(registry->stats())),
               "a tombstoned record was mutated: " + describe(counters_of(registry->stats())));

  tombstone.attempt = frtest::attempt_from("lifecycle-tombstone-again");
  const Outcome again = registry->tombstone_entity(tombstone);
  FR_CHECK_MSG(again.code == OutcomeCode::Idempotent, again.render());
  FR_CHECK_MSG(unchanged(before_closed, counters_of(registry->stats())),
               "a repeated tombstone advanced state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(registry, supersede_moves_aliases_to_the_successor) {
  auto registry = frtest::make_registry(121);
  const FabricId fabric = fabric_with(2);
  const AliasKey host = host_alias_key(registry->limits(), fabric, "supersede-a.example.net");

  RegisterEntityRequest predecessor_request = frtest::device_request(*registry, "supersede-a", "SN-SUP-A");
  predecessor_request.scope.fabric = fabric;
  predecessor_request.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "supersede-a.example.net"));
  const Outcome predecessor = registry->register_entity(predecessor_request);
  FR_CHECK_MSG(predecessor.committed(), predecessor.render());
  const CanonicalId old_id = *predecessor.record;

  const Registration successor = register_device(*registry, "supersede-b", "SN-SUP-B");
  FR_CHECK_MSG(successor.outcome.committed(), successor.outcome.render());

  SupersedeEntityRequest supersede;
  supersede.attempt = frtest::attempt_from("supersede-move");
  supersede.authority = registry->local_authority();
  supersede.target = old_id;
  supersede.successor = successor.id;
  supersede.reason = "hardware replaced";
  const Outcome committed = registry->supersede_entity(supersede);
  FR_CHECK_MSG(committed.committed(), committed.render());

  std::shared_ptr<const EntityRecord> old_record;
  FR_CHECK_EQ(registry->lookup(old_id, old_record).code, OutcomeCode::Committed);
  FR_CHECK(old_record->lifecycle == Lifecycle::Superseded);
  FR_CHECK(old_record->superseded_by.has_value());
  FR_CHECK_EQ(*old_record->superseded_by, successor.id);
  FR_CHECK_EQ(old_record->status_reason, std::string("hardware replaced"));

  std::shared_ptr<const EntityRecord> new_record;
  FR_CHECK_EQ(registry->lookup(successor.id, new_record).code, OutcomeCode::Committed);
  FR_CHECK(new_record->supersedes.has_value());
  FR_CHECK_EQ(*new_record->supersedes, old_id);
  FR_CHECK(holds_alias(new_record, host));
  FR_CHECK(new_record->lifecycle == Lifecycle::Current);

  // A unique alias belongs to exactly one record: once the supersession is
  // committed the transferred alias must be gone from the superseded record.
  FR_CHECK_MSG(!holds_alias(old_record, host),
               "the superseded record still holds the alias that moved to its successor: " + host.to_string());

  std::shared_ptr<const EntityRecord> by_alias;
  FR_CHECK_EQ(registry->lookup_by_alias(host, by_alias).code, OutcomeCode::Committed);
  FR_CHECK_MSG(by_alias->id == successor.id,
               "the transferred alias resolves to " + by_alias->id.to_string() + " instead of " +
                   successor.id.to_string());
  FR_CHECK_EQ(registry->stats().superseded_entities, 1u);
  FR_CHECK_EQ(registry->stats().current_entities, 1u);
  FR_CHECK_EQ(registry->stats().indexed_aliases, 1u);

  std::string report;
  const Outcome validated = registry->validate_state(report);
  FR_CHECK_MSG(validated.committed(), report);
}

FR_TEST_CASE(registry, supersede_rejects_illegal_targets_and_mismatched_successors) {
  auto registry = frtest::make_registry(131);
  RegisterEntityRequest observed_request =
      frtest::device_request(*registry, "supersede-observed", "SN-SUP-DISC");
  observed_request.admission = AdmissionMode::AllowObservation;
  const Outcome observed = registry->register_entity(observed_request);
  FR_CHECK_MSG(observed.committed(), observed.render());
  FR_CHECK_EQ(registry->stats().discovered_entities, 1u);

  const Registration current = register_device(*registry, "supersede-current", "SN-SUP-CUR");
  FR_CHECK_MSG(current.outcome.committed(), current.outcome.render());

  SupersedeEntityRequest illegal;
  illegal.attempt = frtest::attempt_from("supersede-discovered");
  illegal.authority = registry->local_authority();
  illegal.target = *observed.record;
  illegal.successor = current.id;
  const Counters before_illegal = counters_of(registry->stats());
  const Outcome refused = registry->supersede_entity(illegal);
  FR_CHECK_MSG(refused.code == OutcomeCode::IllegalTransition, refused.render());
  FR_CHECK_MSG(unchanged(before_illegal, counters_of(registry->stats())),
               "an illegal supersede advanced state: " + describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> observed_record;
  FR_CHECK_EQ(registry->lookup(*observed.record, observed_record).code, OutcomeCode::Committed);
  FR_CHECK(observed_record->lifecycle == Lifecycle::Discovered);

  const Registration other_class =
      register_device(*registry, "supersede-other-class", "SN-SUP-HOST", EntityClass::Host);
  FR_CHECK_MSG(other_class.outcome.committed(), other_class.outcome.render());

  SupersedeEntityRequest mismatched;
  mismatched.attempt = frtest::attempt_from("supersede-mismatched");
  mismatched.authority = registry->local_authority();
  mismatched.target = current.id;
  mismatched.successor = other_class.id;
  const Counters before_mismatch = counters_of(registry->stats());
  const Outcome mismatch = registry->supersede_entity(mismatched);
  FR_CHECK_MSG(mismatch.code == OutcomeCode::MalformedRequest, mismatch.render());
  FR_CHECK_MSG(unchanged(before_mismatch, counters_of(registry->stats())),
               "a mismatched supersede advanced state: " + describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> still_current;
  FR_CHECK_EQ(registry->lookup(current.id, still_current).code, OutcomeCode::Committed);
  FR_CHECK(still_current->lifecycle == Lifecycle::Current);
}

// ---------------------------------------------------------------------------
// Snapshots and state validation
// ---------------------------------------------------------------------------

FR_TEST_CASE(registry, snapshot_matches_stats_and_is_pure) {
  auto registry = frtest::make_registry(141);
  const Registration first = register_device(*registry, "snapshot-first", "SN-SNAP-1");
  const Registration second = register_device(*registry, "snapshot-second", "SN-SNAP-2");
  FR_CHECK(first.outcome.committed());
  FR_CHECK(second.outcome.committed());

  const RegistryStats stats = registry->stats();
  const Snapshot snapshot = registry->snapshot();
  const Snapshot twin = registry->snapshot();
  FR_CHECK_EQ(snapshot.size(), stats.entities);
  FR_CHECK_EQ(snapshot.size(), registry->all_ids(kEnumerateAll).size());
  FR_CHECK_EQ(snapshot.epoch().value(), stats.epoch.value());
  FR_CHECK_EQ(snapshot.generation().value(), stats.generation.value());
  FR_CHECK(registry->snapshot_current(snapshot));
  FR_CHECK(snapshot_is_current(*registry, twin));

  for (const Snapshot::RecordPtr& record : snapshot.records()) {
    std::shared_ptr<const EntityRecord> live;
    FR_CHECK_EQ(registry->lookup(record->id, live).code, OutcomeCode::Committed);
    FR_CHECK(live != nullptr);
    FR_CHECK_EQ(live->record_generation.value(), record->record_generation.value());
    const Snapshot::RecordPtr found = snapshot.find(record->id);
    FR_CHECK(found != nullptr);
    FR_CHECK_EQ(found->record_generation.value(), record->record_generation.value());
  }

  // The rendering of a record is a pure function of the record value, and the
  // state digest only covers the state, not the snapshot sequence.
  FR_CHECK_EQ(snapshot.records().size(), twin.records().size());
  for (std::size_t index = 0; index < snapshot.records().size(); ++index) {
    FR_CHECK_EQ(render_record(*snapshot.records()[index]), render_record(*twin.records()[index]));
    FR_CHECK_EQ(snapshot.records()[index]->id, twin.records()[index]->id);
  }
  FR_CHECK_EQ(snapshot.digest().to_string(), twin.digest().to_string());
  FR_CHECK_EQ(snapshot.digest().to_string(), registry->state_digest().to_string());
  FR_CHECK_MSG(counters_of(registry->stats()).generation == stats.generation.value(),
               "taking a snapshot must not advance the registry generation");

  const Registration third = register_device(*registry, "snapshot-third", "SN-SNAP-3");
  FR_CHECK_MSG(third.outcome.committed(), third.outcome.render());
  const Snapshot after = registry->snapshot();
  FR_CHECK_EQ(after.size(), stats.entities + 1u);
  FR_CHECK_MSG(after.digest().to_string() != snapshot.digest().to_string(),
               "the state digest must change after a mutation");
  FR_CHECK(!registry->snapshot_current(snapshot));
  FR_CHECK(registry->snapshot_current(after));
  FR_CHECK(!snapshot_is_current(*registry, twin));
}

FR_TEST_CASE(registry, validate_state_after_mixed_operations) {
  auto registry = frtest::make_registry(151);
  const FabricId fabric = fabric_with(3);

  // The superseded record deliberately carries no unique alias here: the alias
  // transfer itself is proven by supersede_moves_aliases_to_the_successor.
  const Outcome first = registry->register_entity(frtest::device_request(*registry, "mixed-first", "SN-MIX-1"));
  FR_CHECK_MSG(first.committed(), first.render());

  RegisterEntityRequest second_request = frtest::device_request(*registry, "mixed-second", "SN-MIX-2");
  second_request.scope.fabric = fabric;
  second_request.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "mixed-second.example.net"));
  second_request.aliases.push_back(frtest::alias_of(AliasNamespace::OperatorLabel, "label-mixed-second"));
  const Outcome second = registry->register_entity(second_request);
  FR_CHECK_MSG(second.committed(), second.render());

  RegisterEntityRequest third_request = frtest::device_request(*registry, "mixed-third", "SN-MIX-3");
  third_request.scope.fabric = fabric;
  third_request.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "mixed-third.example.net"));
  const Outcome third = registry->register_entity(third_request);
  FR_CHECK_MSG(third.committed(), third.render());

  UpdateEvidenceRequest update;
  update.attempt = frtest::attempt_from("mixed-update");
  update.authority = registry->local_authority();
  update.target = *third.record;
  update.facts.push_back(frtest::serial_fact("SN-MIX-3"));
  update.provenance = frtest::real_provenance();
  update.evidence_class = EvidenceClass::DurableAuthority;
  FR_CHECK_MSG(registry->update_evidence(update).committed(), "the evidence update was refused");

  const Outcome attached =
      registry->attach_alias(alias_request(*registry, "mixed-attach", *second.record,
                                           frtest::alias_of(AliasNamespace::HostName, "mixed-second-alt.example.net")));
  FR_CHECK_MSG(attached.committed(), attached.render());
  const Outcome detached =
      registry->detach_alias(alias_request(*registry, "mixed-detach", *second.record,
                                           frtest::alias_of(AliasNamespace::HostName, "mixed-second-alt.example.net")));
  FR_CHECK_MSG(detached.committed(), detached.render());

  SupersedeEntityRequest supersede;
  supersede.attempt = frtest::attempt_from("mixed-supersede");
  supersede.authority = registry->local_authority();
  supersede.target = *first.record;
  supersede.successor = *third.record;
  supersede.reason = "consolidated";
  FR_CHECK_MSG(registry->supersede_entity(supersede).committed(), "the supersede was refused");

  RetireEntityRequest retire;
  retire.attempt = frtest::attempt_from("mixed-retire");
  retire.authority = registry->local_authority();
  retire.target = *second.record;
  retire.reason = "withdrawn";
  FR_CHECK_MSG(registry->retire_entity(retire).committed(), "the retire was refused");

  TombstoneEntityRequest tombstone;
  tombstone.attempt = frtest::attempt_from("mixed-tombstone");
  tombstone.authority = registry->local_authority();
  tombstone.target = *second.record;
  tombstone.reason = "closed";
  FR_CHECK_MSG(registry->tombstone_entity(tombstone).committed(), "the tombstone was refused");

  std::string report;
  const Outcome validated = registry->validate_state(report);
  FR_CHECK_MSG(validated.committed(), report);
  FR_CHECK_MSG(report.find("consistent: true") != std::string::npos, report);

  const RegistryStats stats = registry->stats();
  FR_CHECK_EQ(stats.entities, 3u);
  FR_CHECK_EQ(stats.entities, registry->all_ids(kEnumerateAll).size());
  FR_CHECK_EQ(stats.current_entities, registry->entities_of_lifecycle(Lifecycle::Current, kEnumerateAll).size());
  FR_CHECK_EQ(stats.superseded_entities, 1u);
  FR_CHECK_EQ(stats.tombstoned_entities, 1u);
  FR_CHECK_EQ(stats.current_entities, 1u);
  FR_CHECK_EQ(stats.indexed_aliases, 2u);
  FR_CHECK_EQ(stats.aliases, 3u);
  const std::size_t lifecycle_total = stats.current_entities + stats.discovered_entities + stats.candidate_entities +
                                      stats.revalidation_required_entities + stats.superseded_entities +
                                      stats.retired_entities + stats.tombstoned_entities + stats.conflicted_entities +
                                      stats.rejected_entities;
  FR_CHECK_EQ(lifecycle_total, stats.entities);
  FR_CHECK(stats.lineage_entries >= stats.entities);
  FR_CHECK(stats.idempotency_records >= 1u);
  std::shared_ptr<const EntityRecord> survivor;
  FR_CHECK_EQ(registry->lookup(*third.record, survivor).code, OutcomeCode::Committed);
  FR_CHECK(survivor->supersedes.has_value());
  FR_CHECK_EQ(*survivor->supersedes, *first.record);
}

// ---------------------------------------------------------------------------
// Publishers, epochs and conflicts
// ---------------------------------------------------------------------------

FR_TEST_CASE(registry, publisher_authority_claims_and_fencing) {
  auto registry = frtest::make_registry(161);
  const AuthorityStats authority = registry->authority_stats();
  FR_CHECK_EQ(authority.publishers, 1u);
  FR_CHECK_EQ(authority.active_publishers, 1u);
  FR_CHECK_EQ(authority.fenced_publishers, 0u);
  FR_CHECK_EQ(authority.epoch.value(), registry->epoch().value());

  const AuthorityClaim local = registry->local_authority();
  FR_CHECK(local.is_complete());
  const std::optional<PublisherRecord> local_record = registry->publisher(local.publisher);
  FR_CHECK(local_record.has_value());
  FR_CHECK(local_record->state == PublisherState::Active);
  FR_CHECK(local_record->current_boot == local.worker_boot);

  // A claim that carries an epoch the coordinator has moved past is stale.
  RegisterEntityRequest stale_epoch_request = frtest::device_request(*registry, "publisher-stale-epoch", "SN-PUB-1");
  stale_epoch_request.authority.epoch = *registry->epoch().next();
  const Outcome stale_epoch = registry->register_entity(stale_epoch_request);
  FR_CHECK_MSG(stale_epoch.code == OutcomeCode::StaleEpoch, stale_epoch.render());

  // A null publisher mints a fresh identity; an unknown one is refused.
  PublisherAttachRequest attach;
  attach.name = "test-publisher";
  const PublisherAttachResult attached = registry->attach_publisher(attach);
  FR_CHECK_MSG(attached.outcome.committed(), attached.outcome.render());
  FR_CHECK(!attached.publisher.is_null());
  FR_CHECK(!attached.worker_boot.is_null());
  FR_CHECK_EQ(attached.epoch.value(), registry->epoch().value());
  FR_CHECK(!attached.fenced_previous);
  FR_CHECK_EQ(registry->publishers().size(), 2u);
  FR_CHECK_EQ(registry->authority_stats().active_publishers, 2u);

  PublisherAttachRequest unknown;
  unknown.publisher = publisher_with(0x01);
  unknown.name = "unknown-publisher";
  const PublisherAttachResult unknown_result = registry->attach_publisher(unknown);
  FR_CHECK_MSG(unknown_result.outcome.code == OutcomeCode::StaleAuthority, unknown_result.outcome.render());
  FR_CHECK(unknown_result.publisher.is_null());

  // A foreign worker incarnation is refused even though the publisher is right.
  RegisterEntityRequest foreign_boot_request = frtest::device_request(*registry, "publisher-foreign-boot", "SN-PUB-2");
  foreign_boot_request.authority.worker_boot = attached.worker_boot;
  const Outcome foreign_boot = registry->register_entity(foreign_boot_request);
  FR_CHECK_MSG(foreign_boot.code == OutcomeCode::StaleWorkerBoot, foreign_boot.render());

  // Detaching the embedded authority fences it: mutations stop committing.
  const Outcome detached = registry->detach_publisher(local, FenceReason::ExplicitDetach);
  FR_CHECK_MSG(detached.committed(), detached.render());
  FR_CHECK_EQ(registry->authority_stats().active_publishers, 1u);
  const std::optional<PublisherRecord> fenced = registry->publisher(local.publisher);
  FR_CHECK(fenced.has_value());
  FR_CHECK(fenced->state == PublisherState::Fenced);
  FR_CHECK(fenced->current_boot.is_null());

  RegisterEntityRequest fenced_request = frtest::device_request(*registry, "publisher-fenced", "SN-PUB-3");
  fenced_request.authority = local;
  const Counters before = counters_of(registry->stats());
  const Outcome fenced_outcome = registry->register_entity(fenced_request);
  FR_CHECK_MSG(fenced_outcome.code == OutcomeCode::FencedPublisher, fenced_outcome.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a fenced publisher mutated state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(registry, advance_epoch_demotes_process_bound_evidence) {
  auto registry = frtest::make_registry(171);
  const Registration durable =
      register_device(*registry, "epoch-durable", "SN-EPOCH-D", EntityClass::Switch, "test/namespace-a",
                      EvidenceClass::DurableAuthority);
  const Registration process =
      register_device(*registry, "epoch-process", "SN-EPOCH-P", EntityClass::Switch, "test/namespace-a",
                      EvidenceClass::ProcessBound);
  FR_CHECK_MSG(durable.outcome.committed(), durable.outcome.render());
  FR_CHECK_MSG(process.outcome.committed(), process.outcome.render());
  FR_CHECK_EQ(registry->stats().current_entities, 2u);

  const AuthorityClaim previous = registry->local_authority();
  const CoordinatorEpoch previous_epoch = registry->epoch();
  std::size_t demoted = 0;
  const Outcome advanced = registry->advance_epoch(demoted);
  FR_CHECK_MSG(advanced.committed(), advanced.render());
  FR_CHECK_EQ(demoted, 1u);
  FR_CHECK_EQ(registry->epoch().value(), previous_epoch.value() + 1u);

  // Every publisher was fenced, and the embedded one reattached with a fresh
  // incarnation under the new epoch.
  const AuthorityStats authority = registry->authority_stats();
  FR_CHECK_EQ(authority.publishers, 1u);
  FR_CHECK_EQ(authority.active_publishers, 1u);
  FR_CHECK(authority.fenced_boots >= 1u);
  const AuthorityClaim current = registry->local_authority();
  FR_CHECK(current.epoch == registry->epoch());
  FR_CHECK(current.worker_boot != previous.worker_boot);
  FR_CHECK(current.publisher == previous.publisher);

  std::shared_ptr<const EntityRecord> durable_record;
  FR_CHECK_EQ(registry->lookup(durable.id, durable_record).code, OutcomeCode::Committed);
  FR_CHECK(durable_record->lifecycle == Lifecycle::Current);
  FR_CHECK(durable_record->evidence.valid);

  std::shared_ptr<const EntityRecord> process_record;
  FR_CHECK_EQ(registry->lookup(process.id, process_record).code, OutcomeCode::Committed);
  FR_CHECK(process_record->lifecycle == Lifecycle::RevalidationRequired);
  FR_CHECK(!process_record->evidence.valid);
  FR_CHECK_EQ(registry->stats().revalidation_required_entities, 1u);
  FR_CHECK_EQ(registry->stats().current_entities, 1u);

  // The previous epoch is stale, and so is the incarnation that carried it.
  RegisterEntityRequest stale_request = frtest::device_request(*registry, "epoch-stale", "SN-EPOCH-S");
  stale_request.authority = previous;
  const Counters before = counters_of(registry->stats());
  const Outcome stale = registry->register_entity(stale_request);
  FR_CHECK_MSG(stale.code == OutcomeCode::StaleEpoch, stale.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a stale epoch mutated state: " + describe(counters_of(registry->stats())));

  std::string report;
  const Outcome validated = registry->validate_state(report);
  FR_CHECK_MSG(validated.committed(), report);
}

FR_TEST_CASE(registry, revalidation_restores_current_authority) {
  auto registry = frtest::make_registry(181);
  const Registration process =
      register_device(*registry, "revalidate-process", "SN-REV-1", EntityClass::Switch, "test/namespace-a",
                      EvidenceClass::ProcessBound);
  FR_CHECK_MSG(process.outcome.committed(), process.outcome.render());

  RegisterEntityRequest observed_request =
      frtest::device_request(*registry, "revalidate-observed", "SN-REV-2");
  observed_request.admission = AdmissionMode::AllowObservation;
  const Outcome observed = registry->register_entity(observed_request);
  FR_CHECK_MSG(observed.committed(), observed.render());
  FR_CHECK_EQ(registry->stats().discovered_entities, 1u);

  std::size_t demoted = 0;
  FR_CHECK_MSG(registry->advance_epoch(demoted).committed(), "the epoch advance was refused");
  FR_CHECK_EQ(demoted, 1u);

  RevalidateEntityRequest revalidate;
  revalidate.attempt = frtest::attempt_from("revalidate-process-entity");
  revalidate.authority = registry->local_authority();
  revalidate.target = process.id;
  revalidate.facts.push_back(frtest::serial_fact("SN-REV-1"));
  revalidate.provenance = frtest::real_provenance();
  revalidate.evidence_class = EvidenceClass::DurableAuthority;
  const Outcome restored = registry->revalidate_entity(revalidate);
  FR_CHECK_MSG(restored.committed(), restored.render());

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(process.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Current);
  FR_CHECK(record->evidence.valid);
  FR_CHECK(record->status_reason.empty());
  FR_CHECK(record->evidence.evidence_class == EvidenceClass::DurableAuthority);
  FR_CHECK_EQ(registry->stats().current_entities, 1u);
  FR_CHECK_EQ(registry->stats().discovered_entities, 1u);
  FR_CHECK_EQ(registry->stats().revalidation_required_entities, 0u);

  // A discovered record has never held authority and cannot be revalidated.
  revalidate.attempt = frtest::attempt_from("revalidate-observed-entity");
  revalidate.target = *observed.record;
  const Counters before = counters_of(registry->stats());
  const Outcome refused = registry->revalidate_entity(revalidate);
  FR_CHECK_MSG(refused.code == OutcomeCode::IllegalTransition, refused.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "revalidating a discovered record advanced state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(registry, conflict_raise_and_resolve) {
  auto registry = frtest::make_registry(191);
  const Registration incumbent = register_device(*registry, "conflict-incumbent", "SN-CONF-1");
  FR_CHECK_MSG(incumbent.outcome.committed(), incumbent.outcome.render());

  RegisterEntityRequest contradictory = frtest::device_request(*registry, "conflict-raise", "SN-CONF-2");
  contradictory.canonical_id = incumbent.id;
  contradictory.derivation_namespace.clear();
  contradictory.facts.clear();
  contradictory.facts.push_back(frtest::serial_fact("SN-CONF-CONTRADICTION"));
  contradictory.record_conflict = true;
  const Outcome raised = registry->register_entity(contradictory);
  FR_CHECK_MSG(raised.committed(), raised.render());

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(incumbent.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Conflicted);
  FR_CHECK_EQ(registry->stats().conflicted_entities, 1u);

  ResolveConflictRequest resolve;
  resolve.attempt = frtest::attempt_from("conflict-keep-current");
  resolve.authority = registry->local_authority();
  resolve.target = incumbent.id;
  resolve.resolution = ConflictResolution::KeepCurrent;
  resolve.reason = "the incumbent keeps authority";
  const Outcome kept = registry->resolve_conflict(resolve);
  FR_CHECK_MSG(kept.committed(), kept.render());
  FR_CHECK_EQ(registry->lookup(incumbent.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Current);

  contradictory.attempt = frtest::attempt_from("conflict-raise-again");
  FR_CHECK_MSG(registry->register_entity(contradictory).committed(), "the second conflict was refused");
  FR_CHECK_EQ(registry->lookup(incumbent.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Conflicted);

  resolve.attempt = frtest::attempt_from("conflict-retire");
  resolve.resolution = ConflictResolution::Retire;
  resolve.reason = "the incumbent is withdrawn";
  const Outcome retired = registry->resolve_conflict(resolve);
  FR_CHECK_MSG(retired.committed(), retired.render());
  FR_CHECK_EQ(registry->lookup(incumbent.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Retired);
  FR_CHECK(!record->evidence.valid);

  const Registration rejected_candidate = register_device(*registry, "conflict-reject-candidate", "SN-CONF-3");
  FR_CHECK_MSG(rejected_candidate.outcome.committed(), rejected_candidate.outcome.render());

  contradictory.canonical_id = rejected_candidate.id;
  contradictory.attempt = frtest::attempt_from("conflict-raise-third");
  contradictory.facts.clear();
  contradictory.facts.push_back(frtest::serial_fact("SN-CONF-CONTRADICTION"));
  FR_CHECK_MSG(registry->register_entity(contradictory).committed(), "the third conflict was refused");

  resolve.attempt = frtest::attempt_from("conflict-reject");
  resolve.target = rejected_candidate.id;
  resolve.resolution = ConflictResolution::Reject;
  resolve.reason = "the claim was rejected";
  const Outcome rejected = registry->resolve_conflict(resolve);
  FR_CHECK_MSG(rejected.committed(), rejected.render());
  FR_CHECK_EQ(registry->lookup(rejected_candidate.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Rejected);
  FR_CHECK_EQ(registry->stats().rejected_entities, 1u);

  // Resolving a record that is not conflicted is refused.
  resolve.attempt = frtest::attempt_from("conflict-resolve-unconflicted");
  resolve.target = rejected_candidate.id;
  const Counters before = counters_of(registry->stats());
  const Outcome not_conflicted = registry->resolve_conflict(resolve);
  FR_CHECK_MSG(not_conflicted.code == OutcomeCode::IllegalTransition, not_conflicted.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "resolving an unconflicted record advanced state: " + describe(counters_of(registry->stats())));

  std::string report;
  const Outcome validated = registry->validate_state(report);
  FR_CHECK_MSG(validated.committed(), report);
  FR_CHECK_MSG(report.find("consistent: true") != std::string::npos, report);
}

} // namespace

int main(int argc, char** argv) {
  return frtest::run_all(argc, argv);
}
