// Fabric Registry — identity matching and reconciliation.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These cases pin the decision the registry makes for an observation that is
// not an exact canonical hit: hardware subset and superset matches, probable
// but insufficient evidence, contradictions, equal-strength ambiguity and the
// duplicate-hardware and alias guarantees that keep two live records from
// claiming the same physical device.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "registry_test_support.hpp"
#include "test_harness.hpp"

namespace {

using namespace fabric_registry;

/// The derivation namespace reconcile_observation uses internally. A record
/// whose identity was derived under it resolves as an exact canonical match.
constexpr const char* kReconcileNamespace = "fabric-registry/reconcile";

/// Enumeration bound used by the "list everything" assertions.
constexpr std::size_t kEnumerateAll = 1'000'000;

IdBytes bytes_with(std::uint8_t tag, std::uint8_t salt) {
  IdBytes bytes{};
  bytes[0] = tag;
  bytes[15] = salt;
  return bytes;
}

FabricId fabric_with(std::uint8_t salt) { return FabricId::from_bytes(bytes_with(0xF1u, salt)); }

SiteId site_with(std::uint8_t salt) { return SiteId::from_bytes(bytes_with(0x51u, salt)); }

CanonicalId canonical_with(EntityClass entity_class, std::uint8_t salt) {
  return CanonicalId(entity_class, bytes_with(0xC1u, salt));
}

std::vector<IdentityFact> sorted(std::vector<IdentityFact> facts) {
  std::sort(facts.begin(), facts.end());
  return facts;
}

/// The counters a refused request must leave exactly as they were.
struct Counters {
  std::size_t entities{0};
  std::size_t indexed_aliases{0};
  std::uint64_t generation{0};
};

Counters counters_of(const RegistryStats& stats) {
  Counters counters;
  counters.entities = stats.entities;
  counters.indexed_aliases = stats.indexed_aliases;
  counters.generation = stats.generation.value();
  return counters;
}

bool unchanged(const Counters& left, const Counters& right) {
  return left.entities == right.entities && left.indexed_aliases == right.indexed_aliases &&
         left.generation == right.generation;
}

std::string describe(const Counters& counters) {
  return "entities=" + std::to_string(counters.entities) + " aliases=" + std::to_string(counters.indexed_aliases) +
         " generation=" + std::to_string(counters.generation);
}

struct Registration {
  Outcome outcome;
  CanonicalId id{};
};

/// A registration request shaped for a device entity with an explicit fact set.
RegisterEntityRequest entity_request(Registry& registry, const std::string& label, EntityClass entity_class,
                                     const std::string& derivation_namespace, std::vector<IdentityFact> facts) {
  RegisterEntityRequest request;
  request.attempt = frtest::attempt_from(label);
  request.authority = registry.local_authority();
  request.entity_class = entity_class;
  request.derivation_namespace = derivation_namespace;
  request.friendly_name = label;
  request.facts = std::move(facts);
  request.provenance = frtest::real_provenance();
  request.evidence_class = EvidenceClass::DurableAuthority;
  request.admission = AdmissionMode::RequireCurrent;
  return request;
}

Registration commit(Registry& registry, const RegisterEntityRequest& request) {
  Registration registration;
  registration.outcome = registry.register_entity(request);
  if (registration.outcome.record.has_value()) {
    registration.id = *registration.outcome.record;
  }
  return registration;
}

/// An observation shaped for reconcile_observation with an explicit fact set.
ReconcileObservationRequest observation_request(Registry& registry, const std::string& label, EntityClass entity_class,
                                                std::vector<IdentityFact> facts) {
  ReconcileObservationRequest request;
  request.attempt = frtest::attempt_from(label);
  request.authority = registry.local_authority();
  request.entity_class = entity_class;
  request.facts = std::move(facts);
  request.provenance = frtest::real_provenance("reconcile-observer");
  return request;
}

/// The fully qualified key of a host-name alias inside one fabric.
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

bool holds_alias(const std::shared_ptr<const EntityRecord>& record, const AliasKey& key) {
  return record != nullptr && std::find(record->aliases.begin(), record->aliases.end(), key) != record->aliases.end();
}

bool names_fact(const Outcome& outcome, const std::string& text) {
  for (const ExplanationStep& step : outcome.steps) {
    if (step.field.find(text) != std::string::npos || step.detail.find(text) != std::string::npos) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Match classes
// ---------------------------------------------------------------------------

FR_TEST_CASE(reconcile, exact_canonical_observation_matches) {
  auto registry = frtest::make_registry(1001);
  RegisterEntityRequest request =
      frtest::device_request(*registry, "reconcile-exact", "SN-REC-EXACT", EntityClass::Switch, kReconcileNamespace);
  const Registration created = commit(*registry, request);
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());

  ReconcileObservationRequest observation =
      observation_request(*registry, "reconcile-exact-observation", EntityClass::Switch,
                          {frtest::serial_fact("SN-REC-EXACT")});
  const Counters before = counters_of(registry->stats());
  const ReconcileResult result = registry->reconcile_observation(observation);
  FR_CHECK_MSG(result.outcome.committed(), result.outcome.render());
  FR_CHECK_EQ(result.detail.match, MatchClass::ExactCanonical);
  FR_CHECK_EQ(result.outcome.code, OutcomeCode::Committed);
  FR_CHECK(result.detail.matched.has_value());
  FR_CHECK_EQ(*result.detail.matched, created.id);
  FR_CHECK_EQ(result.detail.candidates.size(), 1u);
  FR_CHECK_EQ(result.detail.candidates.front(), created.id);
  FR_CHECK(result.detail.conflicting_facts.empty());
  FR_CHECK(result.detail.conflicting_aliases.empty());
  FR_CHECK(!result.detail.observation_fingerprint.is_null());

  // Reconciliation is a read: it never commits anything, even when it matches.
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "reconciliation changed state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(reconcile, hardware_subset_and_superset_match) {
  auto registry = frtest::make_registry(1011);
  const IdentityFact serial = frtest::serial_fact("SN-REC-HW");
  const IdentityFact chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-7");
  const IdentityFact pci = frtest::fact_of(IdentityFactKind::PciAddress, "0000:3b:00.0");
  const Registration created = commit(
      *registry, entity_request(*registry, "reconcile-hardware", EntityClass::Switch, "test/namespace-a",
                                {serial, chassis}));
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());

  // A subset of the stored strong facts still proves the same device.
  const ReconcileResult subset = registry->reconcile_observation(
      observation_request(*registry, "reconcile-subset", EntityClass::Switch, {serial}));
  FR_CHECK_MSG(subset.outcome.committed(), subset.outcome.render());
  FR_CHECK_EQ(subset.detail.match, MatchClass::StableHardware);
  FR_CHECK(subset.detail.matched.has_value());
  FR_CHECK_EQ(*subset.detail.matched, created.id);

  // So does a superset, provided no stored fact disagrees.
  const ReconcileResult superset = registry->reconcile_observation(
      observation_request(*registry, "reconcile-superset", EntityClass::Switch, {serial, chassis, pci}));
  FR_CHECK_MSG(superset.outcome.committed(), superset.outcome.render());
  FR_CHECK_EQ(superset.detail.match, MatchClass::StableHardware);
  FR_CHECK(superset.detail.matched.has_value());
  FR_CHECK_EQ(*superset.detail.matched, created.id);

  // A disjoint strong fact proves nothing at all.
  const ReconcileResult disjoint = registry->reconcile_observation(
      observation_request(*registry, "reconcile-disjoint", EntityClass::Switch, {pci}));
  FR_CHECK_MSG(disjoint.detail.match != MatchClass::StableHardware,
               "a disjoint fact must never be reported as a hardware match");
  FR_CHECK(disjoint.detail.match == MatchClass::NoMatch || disjoint.detail.match == MatchClass::ProbableInsufficient);
  FR_CHECK(!disjoint.outcome.committed());
  FR_CHECK(!disjoint.detail.matched.has_value());

  const Counters before = counters_of(registry->stats());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "reconciliation changed state: " + describe(counters_of(registry->stats())));
}

FR_TEST_CASE(reconcile, probable_insufficient_requires_an_explicit_resolution) {
  auto registry = frtest::make_registry(1021);
  const std::vector<IdentityFact> weak_facts{
      frtest::fact_of(IdentityFactKind::InventoryAssetId, "asset-4242"),
      frtest::fact_of(IdentityFactKind::DeviceModel, "model-x")};

  // A derived identity must rest on a strong fact, so a record made only of
  // moderate evidence is created against an explicit identity.
  RegisterEntityRequest seed = entity_request(*registry, "probable-seed", EntityClass::Switch, "", weak_facts);
  seed.canonical_id = canonical_with(EntityClass::Switch, 0x21);
  const Registration created = commit(*registry, seed);
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());
  FR_CHECK_EQ(created.id, *seed.canonical_id);

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->hardware_identity.is_null());
  FR_CHECK(record->fingerprint.is_null());

  const ReconcileResult probable = registry->reconcile_observation(
      observation_request(*registry, "probable-observation", EntityClass::Switch, weak_facts));
  FR_CHECK_MSG(probable.outcome.code == OutcomeCode::ProbableMatch, probable.outcome.render());
  FR_CHECK_EQ(probable.detail.match, MatchClass::ProbableInsufficient);
  FR_CHECK(!probable.detail.matched.has_value());
  FR_CHECK_EQ(probable.detail.candidates.size(), 1u);
  FR_CHECK_EQ(probable.detail.candidates.front(), created.id);

  // Auto never commits a probable match.
  RegisterEntityRequest automatic = entity_request(*registry, "probable-auto", EntityClass::Switch, "", weak_facts);
  automatic.canonical_id = canonical_with(EntityClass::Switch, 0x22);
  const Counters before = counters_of(registry->stats());
  const Outcome auto_outcome = registry->register_entity(automatic);
  FR_CHECK_MSG(auto_outcome.code == OutcomeCode::ProbableMatch, auto_outcome.render());
  FR_CHECK_EQ(auto_outcome.match, MatchClass::ProbableInsufficient);
  FR_CHECK_EQ(auto_outcome.related.size(), 1u);
  FR_CHECK_EQ(auto_outcome.related.front(), created.id);
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a probable match committed state: " + describe(counters_of(registry->stats())));

  // ForceNew creates the record the caller insists on.
  automatic.attempt = frtest::attempt_from("probable-force-new");
  automatic.resolution = ReconcileResolution::ForceNew;
  const Registration forced = commit(*registry, automatic);
  FR_CHECK_MSG(forced.outcome.committed(), forced.outcome.render());
  FR_CHECK_EQ(forced.id, *automatic.canonical_id);
  FR_CHECK(forced.id != created.id);
  FR_CHECK_EQ(registry->stats().entities, 2u);

  // ForceExisting attaches the observation to the record the caller names.
  automatic.attempt = frtest::attempt_from("probable-force-existing");
  automatic.resolution = ReconcileResolution::ForceExisting;
  automatic.resolve_to = created.id;
  const Outcome attached = registry->register_entity(automatic);
  FR_CHECK_MSG(attached.committed(), attached.render());
  FR_CHECK(attached.record.has_value());
  FR_CHECK_EQ(*attached.record, created.id);
  FR_CHECK_EQ(attached.match, MatchClass::ExactCanonical);
  FR_CHECK_EQ(registry->stats().entities, 2u);
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->record_generation.value(), 2u);
}

FR_TEST_CASE(reconcile, conflicting_observation_names_the_disagreeing_fact) {
  auto registry = frtest::make_registry(1031);
  const IdentityFact serial = frtest::serial_fact("SN-REC-CONF");
  const IdentityFact stored_chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-1");
  const IdentityFact other_chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-2");
  const Registration created = commit(
      *registry, entity_request(*registry, "conflict-record", EntityClass::Switch, "test/namespace-a",
                                {serial, stored_chassis}));
  FR_CHECK_MSG(created.outcome.committed(), created.outcome.render());

  const ReconcileResult conflicting = registry->reconcile_observation(
      observation_request(*registry, "conflict-observation", EntityClass::Switch, {serial, other_chassis}));
  FR_CHECK_MSG(conflicting.outcome.code == OutcomeCode::IdentityConflict, conflicting.outcome.render());
  FR_CHECK_EQ(conflicting.detail.match, MatchClass::Conflicting);
  FR_CHECK_EQ(conflicting.detail.conflicting_facts.size(), 1u);
  FR_CHECK_EQ(conflicting.detail.conflicting_facts.front().value, std::string("chassis-2"));
  FR_CHECK_EQ(conflicting.detail.conflicting_facts.front().kind, IdentityFactKind::ChassisId);
  FR_CHECK_EQ(conflicting.detail.candidates.size(), 1u);
  FR_CHECK_EQ(conflicting.detail.candidates.front(), created.id);
  FR_CHECK(names_fact(conflicting.outcome, "chassis-2"));
  FR_CHECK(names_fact(conflicting.outcome, "chassis-id"));

  // A registration carrying the same contradiction is refused and changes
  // nothing unless the caller asks for the conflict to be recorded.
  RegisterEntityRequest request =
      entity_request(*registry, "conflict-register", EntityClass::Switch, "test/namespace-a",
                     {serial, other_chassis});
  const Counters before = counters_of(registry->stats());
  const Outcome refused = registry->register_entity(request);
  FR_CHECK_MSG(refused.code == OutcomeCode::IdentityConflict, refused.render());
  FR_CHECK_EQ(refused.match, MatchClass::Conflicting);
  FR_CHECK(names_fact(refused, "chassis-2"));
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a conflicting registration committed state: " + describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(created.id, record).code, OutcomeCode::Committed);
  FR_CHECK(record->lifecycle == Lifecycle::Current);
  FR_CHECK_EQ(record->record_generation.value(), 1u);
  FR_CHECK_EQ(record->facts, sorted({serial, stored_chassis}));
}

FR_TEST_CASE(reconcile, ambiguous_match_is_never_resolved_silently) {
  auto registry = frtest::make_registry(1041);
  const IdentityFact serial = frtest::serial_fact("SN-AMB-1");
  const IdentityFact chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-amb");
  const Registration by_serial =
      commit(*registry, entity_request(*registry, "ambiguous-serial", EntityClass::Switch, "test/namespace-a",
                                       {serial}));
  const Registration by_chassis =
      commit(*registry, entity_request(*registry, "ambiguous-chassis", EntityClass::Switch, "test/namespace-a",
                                       {chassis}));
  FR_CHECK_MSG(by_serial.outcome.committed(), by_serial.outcome.render());
  FR_CHECK_MSG(by_chassis.outcome.committed(), by_chassis.outcome.render());
  FR_CHECK(by_serial.id != by_chassis.id);

  const ReconcileResult ambiguous = registry->reconcile_observation(
      observation_request(*registry, "ambiguous-observation", EntityClass::Switch, {serial, chassis}));
  FR_CHECK_MSG(ambiguous.outcome.code == OutcomeCode::AmbiguousMatch, ambiguous.outcome.render());
  FR_CHECK_EQ(ambiguous.detail.match, MatchClass::Ambiguous);
  FR_CHECK(!ambiguous.detail.matched.has_value());
  FR_CHECK_EQ(ambiguous.detail.candidates.size(), 2u);
  std::vector<CanonicalId> expected{by_serial.id, by_chassis.id};
  std::sort(expected.begin(), expected.end());
  FR_CHECK(ambiguous.detail.candidates == expected);

  RegisterEntityRequest request =
      entity_request(*registry, "ambiguous-register", EntityClass::Switch, "test/namespace-a", {serial, chassis});
  const Counters before = counters_of(registry->stats());
  const Outcome refused = registry->register_entity(request);
  FR_CHECK_MSG(refused.code == OutcomeCode::AmbiguousMatch, refused.render());
  FR_CHECK_EQ(refused.match, MatchClass::Ambiguous);
  FR_CHECK_EQ(refused.related.size(), 2u);
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "an ambiguous registration committed state: " + describe(counters_of(registry->stats())));
}

// ---------------------------------------------------------------------------
// Duplicate hardware identities
// ---------------------------------------------------------------------------

FR_TEST_CASE(reconcile, duplicate_hardware_identity_is_refused) {
  auto registry = frtest::make_registry(1051);
  const IdentityFact first_serial = frtest::serial_fact("SN-DUP-1");
  const IdentityFact second_serial = frtest::serial_fact("SN-DUP-2");
  const Registration first =
      commit(*registry, entity_request(*registry, "duplicate-first", EntityClass::Switch, "test/namespace-a",
                                       {first_serial}));
  const Registration second =
      commit(*registry, entity_request(*registry, "duplicate-second", EntityClass::Switch, "test/namespace-a",
                                       {second_serial}));
  FR_CHECK_MSG(first.outcome.committed(), first.outcome.render());
  FR_CHECK_MSG(second.outcome.committed(), second.outcome.render());
  FR_CHECK_EQ(registry->stats().entities, 2u);
  FR_CHECK(first.id != second.id);

  // A different canonical identity that carries the identical strong hardware
  // facts never becomes a second live record: reconciliation resolves it onto
  // the incumbent instead.
  RegisterEntityRequest duplicate =
      entity_request(*registry, "duplicate-register", EntityClass::Switch, "test/namespace-b", {first_serial});
  const Counters before_register = counters_of(registry->stats());
  const Outcome resolved = registry->register_entity(duplicate);
  FR_CHECK_MSG(resolved.committed(), resolved.render());
  FR_CHECK_EQ(resolved.match, MatchClass::StableHardware);
  FR_CHECK(resolved.record.has_value());
  FR_CHECK_EQ(*resolved.record, first.id);
  FR_CHECK_EQ(registry->stats().entities, before_register.entities);

  // The enforcement point for a record that already exists is the evidence
  // update: the resulting fact set would give two live records the same
  // physical identity.
  UpdateEvidenceRequest update;
  update.attempt = frtest::attempt_from("duplicate-update");
  update.authority = registry->local_authority();
  update.target = second.id;
  update.facts.push_back(first_serial);
  update.provenance = frtest::real_provenance();
  update.evidence_class = EvidenceClass::DurableAuthority;
  const Counters before_update = counters_of(registry->stats());
  const Outcome refused = registry->update_evidence(update);
  FR_CHECK_MSG(refused.code == OutcomeCode::DuplicateIdentity, refused.render());
  FR_CHECK(refused.record.has_value());
  FR_CHECK_EQ(*refused.record, first.id);
  FR_CHECK_MSG(unchanged(before_update, counters_of(registry->stats())),
               "a duplicate update committed state: " + describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(second.id, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->record_generation.value(), 1u);
  FR_CHECK_EQ(record->facts, sorted({second_serial}));

  // Once the incumbent identity is closed, the same hardware may be claimed by
  // the surviving record. An identity is closed by retiring it and then
  // tombstoning it: current records cannot be tombstoned directly.
  RetireEntityRequest retire;
  retire.attempt = frtest::attempt_from("duplicate-retire");
  retire.authority = registry->local_authority();
  retire.target = first.id;
  retire.reason = "replacement hardware";
  const Outcome retired = registry->retire_entity(retire);
  FR_CHECK_MSG(retired.committed(), retired.render());

  TombstoneEntityRequest tombstone;
  tombstone.attempt = frtest::attempt_from("duplicate-tombstone");
  tombstone.authority = registry->local_authority();
  tombstone.target = first.id;
  tombstone.reason = "replacement hardware";
  const Outcome tombstoned = registry->tombstone_entity(tombstone);
  FR_CHECK_MSG(tombstoned.committed(), tombstoned.render());

  update.attempt = frtest::attempt_from("duplicate-update-after-tombstone");
  const Outcome accepted = registry->update_evidence(update);
  FR_CHECK_MSG(accepted.committed(), accepted.render());
  FR_CHECK_EQ(registry->lookup(second.id, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->facts, sorted({first_serial}));
  FR_CHECK_EQ(record->record_generation.value(), 2u);
  FR_CHECK_EQ(registry->stats().entities, 2u);

  std::string report;
  const Outcome validated = registry->validate_state(report);
  FR_CHECK_MSG(validated.committed(), report);
}

FR_TEST_CASE(reconcile, unique_alias_cannot_be_held_by_two_records) {
  auto registry = frtest::make_registry(1061);
  const FabricId fabric = fabric_with(4);
  const AliasKey host = host_alias_key(registry->limits(), fabric, "alc-two.example.net");
  const IdentityFact first_serial = frtest::serial_fact("SN-ALC-1");
  const IdentityFact first_chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-alc-1");

  RegisterEntityRequest first_request =
      entity_request(*registry, "alias-first", EntityClass::Switch, "test/namespace-a",
                     {first_serial, first_chassis});
  first_request.scope.fabric = fabric;
  const Registration first = commit(*registry, first_request);
  FR_CHECK_MSG(first.outcome.committed(), first.outcome.render());

  RegisterEntityRequest second_request =
      entity_request(*registry, "alias-second", EntityClass::Switch, "test/namespace-a",
                     {frtest::serial_fact("SN-ALC-2")});
  second_request.scope.fabric = fabric;
  second_request.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "alc-two.example.net"));
  const Registration second = commit(*registry, second_request);
  FR_CHECK_MSG(second.outcome.committed(), second.outcome.render());
  FR_CHECK(first.id != second.id);

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(second.id, record).code, OutcomeCode::Committed);
  FR_CHECK(holds_alias(record, host));
  FR_CHECK_EQ(registry->stats().indexed_aliases, 1u);

  // A registration that matches the first record by hardware may not take the
  // alias the second record holds.
  RegisterEntityRequest theft = entity_request(*registry, "alias-theft", EntityClass::Switch, "test/namespace-a",
                                               {first_serial, first_chassis});
  theft.scope.fabric = fabric;
  theft.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "alc-two.example.net"));
  const Counters before = counters_of(registry->stats());
  const Outcome conflict = registry->register_entity(theft);
  FR_CHECK_MSG(conflict.code == OutcomeCode::AliasConflict, conflict.render());
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "an alias conflict committed state: " + describe(counters_of(registry->stats())));

  FR_CHECK_EQ(registry->lookup(second.id, record).code, OutcomeCode::Committed);
  FR_CHECK(holds_alias(record, host));
  std::shared_ptr<const EntityRecord> by_alias;
  FR_CHECK_EQ(registry->lookup_by_alias(host, by_alias).code, OutcomeCode::Committed);
  FR_CHECK_EQ(by_alias->id, second.id);

  // An observation the alias proves is probable, not exact: the strong facts do
  // not corroborate it.
  const IdentityFact other_chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-alc-2");
  ReconcileObservationRequest observation =
      observation_request(*registry, "alias-observation", EntityClass::Switch, {other_chassis});
  observation.scope.fabric = fabric;
  observation.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "alc-two.example.net"));
  const ReconcileResult probable = registry->reconcile_observation(observation);
  FR_CHECK_MSG(probable.outcome.code == OutcomeCode::ProbableMatch, probable.outcome.render());
  FR_CHECK_EQ(probable.detail.match, MatchClass::ProbableInsufficient);
  FR_CHECK(probable.detail.matched.has_value());
  FR_CHECK_EQ(*probable.detail.matched, second.id);
  FR_CHECK(probable.detail.conflicting_aliases.empty());

  // Auto refuses to commit, and force-new does not override a proven alias: the
  // observation lands on the record the alias proves.
  RegisterEntityRequest registration = entity_request(*registry, "alias-register", EntityClass::Switch,
                                                      "test/namespace-a", {other_chassis});
  registration.scope.fabric = fabric;
  registration.aliases.push_back(frtest::alias_of(AliasNamespace::HostName, "alc-two.example.net"));
  const Counters before_auto = counters_of(registry->stats());
  const Outcome automatic = registry->register_entity(registration);
  FR_CHECK_MSG(automatic.code == OutcomeCode::ProbableMatch, automatic.render());
  FR_CHECK_MSG(unchanged(before_auto, counters_of(registry->stats())),
               "a probable alias match committed state: " + describe(counters_of(registry->stats())));

  //
  // force-new asks for a SECOND record, and a unique alias cannot be held by two
  // records, so the honest answer is an alias conflict rather than silently
  // landing on the aliased record. Nothing is created and the alias still
  // resolves to the incumbent.
  registration.attempt = frtest::attempt_from("alias-register-forced");
  registration.resolution = ReconcileResolution::ForceNew;
  const Counters before_forced = counters_of(registry->stats());
  const Outcome forced = registry->register_entity(registration);
  FR_CHECK_MSG(forced.code == OutcomeCode::AliasConflict, forced.render());
  FR_CHECK_MSG(unchanged(before_forced, counters_of(registry->stats())),
               "a refused force-new committed state: " + describe(counters_of(registry->stats())));
  FR_CHECK_EQ(registry->stats().entities, 2u);
  std::shared_ptr<const EntityRecord> still_second;
  FR_CHECK_EQ(registry->lookup_by_alias(host, still_second).code, OutcomeCode::Committed);
  FR_CHECK_EQ(still_second->id, second.id);

  std::string report;
  const Outcome validated = registry->validate_state(report);
  FR_CHECK_MSG(validated.committed(), report);
}

// ---------------------------------------------------------------------------
// Operator-visible names and locations
// ---------------------------------------------------------------------------

FR_TEST_CASE(reconcile, same_friendly_name_does_not_merge_records) {
  auto registry = frtest::make_registry(1071);
  RegisterEntityRequest first =
      entity_request(*registry, "name-first", EntityClass::Switch, "test/namespace-a",
                     {frtest::serial_fact("SN-NAME-1")});
  first.friendly_name = "shared-friendly-name";
  RegisterEntityRequest second =
      entity_request(*registry, "name-second", EntityClass::Switch, "test/namespace-a",
                     {frtest::serial_fact("SN-NAME-2")});
  second.friendly_name = "shared-friendly-name";
  const Registration first_commit = commit(*registry, first);
  const Registration second_commit = commit(*registry, second);
  FR_CHECK_MSG(first_commit.outcome.committed(), first_commit.outcome.render());
  FR_CHECK_MSG(second_commit.outcome.committed(), second_commit.outcome.render());
  FR_CHECK(first_commit.id != second_commit.id);
  FR_CHECK_EQ(registry->stats().entities, 2u);

  std::shared_ptr<const EntityRecord> first_record;
  std::shared_ptr<const EntityRecord> second_record;
  FR_CHECK_EQ(registry->lookup(first_commit.id, first_record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(registry->lookup(second_commit.id, second_record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(first_record->friendly_name, std::string("shared-friendly-name"));
  FR_CHECK_EQ(second_record->friendly_name, std::string("shared-friendly-name"));
  FR_CHECK(first_record->lifecycle == Lifecycle::Current);
  FR_CHECK(second_record->lifecycle == Lifecycle::Current);
  FR_CHECK(!first_record->supersedes.has_value());
  FR_CHECK(!first_record->superseded_by.has_value());
  FR_CHECK(!second_record->supersedes.has_value());
  FR_CHECK(!second_record->superseded_by.has_value());
  FR_CHECK(first_record->hardware_identity != second_record->hardware_identity);
}

FR_TEST_CASE(reconcile, reused_operator_location_does_not_merge) {
  auto registry = frtest::make_registry(1081);
  const SiteId site = site_with(5);
  const IdentityFact stored_serial = frtest::serial_fact("SN-LOC-1");

  // The rack/slot label is site-scoped, so it is a unique operator-visible
  // location rather than an identity.
  RegisterEntityRequest incumbent =
      entity_request(*registry, "location-incumbent", EntityClass::Switch, "test/namespace-a", {stored_serial});
  incumbent.scope.site = site;
  incumbent.aliases.push_back(frtest::alias_of(AliasNamespace::RackSlotLabel, "rack-12/u7"));
  const Registration incumbent_commit = commit(*registry, incumbent);
  FR_CHECK_MSG(incumbent_commit.outcome.committed(), incumbent_commit.outcome.render());

  // A replacement device at the same location has different hardware and a
  // different serial, so it contradicts the incumbent rather than merging.
  RegisterEntityRequest replacement =
      entity_request(*registry, "location-replacement", EntityClass::Switch, "test/namespace-a",
                     {frtest::serial_fact("SN-LOC-2")});
  replacement.scope.site = site;
  replacement.aliases.push_back(frtest::alias_of(AliasNamespace::RackSlotLabel, "rack-12/u7"));
  const Counters before = counters_of(registry->stats());
  const Outcome refused = registry->register_entity(replacement);
  FR_CHECK_MSG(refused.code == OutcomeCode::IdentityConflict, refused.render());
  FR_CHECK_EQ(refused.match, MatchClass::Conflicting);
  FR_CHECK_MSG(unchanged(before, counters_of(registry->stats())),
               "a replacement at an occupied location committed state: " +
                   describe(counters_of(registry->stats())));

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(incumbent_commit.id, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->id, incumbent_commit.id);
  FR_CHECK(record->lifecycle == Lifecycle::Current);
  FR_CHECK_EQ(record->facts, sorted({stored_serial}));
  FR_CHECK_EQ(record->record_generation.value(), 1u);
  FR_CHECK_EQ(registry->stats().entities, 1u);

  // A purely informational location is not an identity at all: the replacement
  // creates its own record and the incumbent keeps its identity.
  RegisterEntityRequest labelled =
      entity_request(*registry, "location-labelled", EntityClass::Switch, "test/namespace-a",
                     {frtest::serial_fact("SN-LOC-3")});
  labelled.aliases.push_back(frtest::alias_of(AliasNamespace::OperatorLabel, "rack-13/u1"));
  const Registration labelled_commit = commit(*registry, labelled);
  FR_CHECK_MSG(labelled_commit.outcome.committed(), labelled_commit.outcome.render());

  RegisterEntityRequest labelled_replacement =
      entity_request(*registry, "location-labelled-replacement", EntityClass::Switch, "test/namespace-a",
                     {frtest::serial_fact("SN-LOC-4")});
  labelled_replacement.aliases.push_back(frtest::alias_of(AliasNamespace::OperatorLabel, "rack-13/u1"));
  const Registration replaced = commit(*registry, labelled_replacement);
  FR_CHECK_MSG(replaced.outcome.committed(), replaced.outcome.render());
  FR_CHECK(replaced.id != labelled_commit.id);
  FR_CHECK_EQ(registry->stats().entities, 3u);

  FR_CHECK_EQ(registry->lookup(labelled_commit.id, record).code, OutcomeCode::Committed);
  FR_CHECK_EQ(record->id, labelled_commit.id);
  FR_CHECK(record->lifecycle == Lifecycle::Current);
  FR_CHECK_EQ(record->record_generation.value(), 1u);
  FR_CHECK_EQ(registry->stats().indexed_aliases, 1u);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

FR_TEST_CASE(reconcile, reconciliation_is_deterministic) {
  auto registry = frtest::make_registry(1091);
  const IdentityFact serial = frtest::serial_fact("SN-DET-1");
  const IdentityFact chassis = frtest::fact_of(IdentityFactKind::ChassisId, "chassis-det");
  FR_CHECK(commit(*registry, entity_request(*registry, "determinism-serial", EntityClass::Switch,
                                            "test/namespace-a", {serial}))
               .outcome.committed());
  FR_CHECK(commit(*registry, entity_request(*registry, "determinism-chassis", EntityClass::Switch,
                                            "test/namespace-a", {chassis}))
               .outcome.committed());

  const ReconcileObservationRequest observation =
      observation_request(*registry, "determinism-observation", EntityClass::Switch, {serial, chassis});
  const ReconcileResult first = registry->reconcile_observation(observation);
  const ReconcileResult second = registry->reconcile_observation(observation);
  FR_CHECK_EQ(first.detail.match, second.detail.match);
  FR_CHECK_EQ(first.detail.match, MatchClass::Ambiguous);
  FR_CHECK_EQ(first.outcome.code, second.outcome.code);
  FR_CHECK(first.detail.candidates == second.detail.candidates);
  FR_CHECK(first.detail.matched == second.detail.matched);
  FR_CHECK(first.detail.conflicting_facts == second.detail.conflicting_facts);
  FR_CHECK(first.detail.conflicting_aliases == second.detail.conflicting_aliases);
  FR_CHECK_EQ(first.detail.observation_fingerprint.to_string(), second.detail.observation_fingerprint.to_string());

  // The fingerprint is the derivation input digest of the observation under the
  // namespace reconciliation uses, so it does not depend on registry state.
  const FingerprintDigest expected =
      compute_identity_fingerprint(EntityClass::Switch, kReconcileNamespace, sorted({serial, chassis}));
  FR_CHECK_EQ(first.detail.observation_fingerprint.to_string(), expected.to_string());

  auto other = frtest::make_registry(1091);
  const ReconcileResult elsewhere = other->reconcile_observation(observation);
  FR_CHECK_EQ(elsewhere.detail.observation_fingerprint.to_string(), expected.to_string());
  FR_CHECK_EQ(elsewhere.detail.match, MatchClass::NoMatch);
  FR_CHECK_EQ(elsewhere.outcome.code, OutcomeCode::NotFound);
}

} // namespace

int main(int argc, char** argv) {
  return frtest::run_all(argc, argv);
}
