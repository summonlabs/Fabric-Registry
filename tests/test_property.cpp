// Fabric Registry — deterministic seeded property and invariant tests.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Nothing in this file depends on wall-clock time, on the operating system or on
// thread scheduling. Every case is driven by a fixed seed, and a failure names
// the seed, the operation index and the operation kind, so a failing run is
// reproduced exactly by re-running the same seed.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/registry_test_support.hpp"
#include "support/test_harness.hpp"

namespace fr = fabric_registry;

namespace {

using RecordPtr = std::shared_ptr<const fr::EntityRecord>;

// ---------------------------------------------------------------------------
// Shared constants and small helpers
// ---------------------------------------------------------------------------

constexpr std::uint64_t kDriverSeeds[] = {1, 2, 3, 5, 8, 13, 21, 34};
constexpr std::size_t kOperationsPerSeed = 4000;
constexpr std::size_t kMaximumDriverRecords = 48;

constexpr std::uint64_t kPersistenceSeeds[] = {101, 211, 307, 401, 503};
constexpr std::size_t kPersistenceRecords = 40;

constexpr std::size_t kCodecRecords = 200;
constexpr std::size_t kReplayRequests = 200;
constexpr std::size_t kGenerationSteps = 200;
constexpr std::size_t kMalformedInputs = 500;

/// Builds the reproducible failure message of the state machine driver.
std::string seed_context(std::uint64_t seed, std::size_t index, const std::string& kind, const std::string& problem) {
  std::string message = "seed=";
  message += std::to_string(seed);
  message += " operation=";
  message += std::to_string(index);
  message += " kind=";
  message += kind;
  message += ": ";
  message += problem;
  return message;
}

/// Compares every field of two records. EntityRecord has no operator== on
/// purpose: a record is compared structurally, field by field, so a codec or a
/// mutation that silently drops a field cannot pass unnoticed.
bool records_equal(const fr::EntityRecord& left, const fr::EntityRecord& right) {
  return left.id == right.id && left.entity_class == right.entity_class && left.lifecycle == right.lifecycle &&
         left.record_generation == right.record_generation && left.creation_generation == right.creation_generation &&
         left.evidence_generation == right.evidence_generation && left.fingerprint == right.fingerprint &&
         left.hardware_identity == right.hardware_identity &&
         left.derivation_namespace == right.derivation_namespace && left.friendly_name == right.friendly_name &&
         left.parent_device == right.parent_device && left.fabric == right.fabric && left.site == right.site &&
         left.control_domain == right.control_domain && left.facts == right.facts && left.aliases == right.aliases &&
         left.metadata == right.metadata && left.evidence.generation == right.evidence.generation &&
         left.evidence.evidence_class == right.evidence.evidence_class &&
         left.evidence.provenance == right.evidence.provenance && left.evidence.epoch == right.evidence.epoch &&
         left.evidence.publisher == right.evidence.publisher &&
         left.evidence.publisher_boot == right.evidence.publisher_boot &&
         left.evidence.accepted_at == right.evidence.accepted_at && left.evidence.valid == right.evidence.valid &&
         left.superseded_by == right.superseded_by && left.supersedes == right.supersedes &&
         left.status_reason == right.status_reason && left.last_modified == right.last_modified &&
         left.created_by == right.created_by && left.created_boot == right.created_boot &&
         left.created_epoch == right.created_epoch;
}

/// Describes everything that makes an Outcome malformed, or an empty string when
/// the outcome is well formed.
std::string outcome_problem(const fr::Outcome& outcome) {
  if (static_cast<std::uint8_t>(outcome.code) >= fr::kOutcomeCodeCount) {
    return "the outcome code is outside the declared enumeration";
  }
  if (fr::to_string(outcome.code) == "unknown") {
    return "the outcome code has no canonical name";
  }
  if (outcome.message.empty()) {
    return "the outcome carries no message";
  }
  if (outcome.record.has_value() && outcome.record->is_null()) {
    return "the outcome names a null canonical identity";
  }
  return std::string();
}

RecordPtr load_record(const fr::Registry& registry, const fr::CanonicalId& id) {
  RecordPtr record;
  if (!registry.lookup(id, record).committed()) {
    return nullptr;
  }
  return record;
}

std::vector<fr::CanonicalId> record_ids(const fr::Registry& registry) {
  return registry.all_ids(registry.limits().max_enumeration);
}

/// Recomputes every invariant the registry promises after every mutation.
std::string invariant_problem(const fr::Registry& registry,
                              std::unordered_map<fr::CanonicalId, std::uint64_t>& highest_generation) {
  std::string report;
  const fr::Outcome validation = registry.validate_state(report);
  if (!validation.committed()) {
    return "validate_state rejected the registry: " + report;
  }
  if (report.find("consistent: true") == std::string::npos) {
    return "validate_state did not report a consistent state: " + report;
  }

  const fr::RegistryStats stats = registry.stats();
  const std::vector<fr::CanonicalId> ids = record_ids(registry);
  if (ids.size() != stats.entities) {
    return "stats().entities disagrees with all_ids(): " + std::to_string(stats.entities) + " versus " +
           std::to_string(ids.size());
  }
  if (!std::is_sorted(ids.begin(), ids.end())) {
    return "all_ids() is not ordered by canonical identity";
  }

  std::size_t indexed_aliases = 0;
  for (const fr::CanonicalId& id : ids) {
    const RecordPtr record = load_record(registry, id);
    if (record == nullptr) {
      return "an identity enumerated by all_ids() does not resolve through lookup: " + id.to_string();
    }
    if (!record->is_well_formed()) {
      return "a record violates its structural invariants: " + id.to_string();
    }
    if (record->record_generation < record->creation_generation) {
      return "a record generation is behind its creation generation: " + id.to_string();
    }
    const auto previous = highest_generation.find(id);
    if (previous != highest_generation.end() && record->record_generation.value() < previous->second) {
      return "a record generation decreased for " + id.to_string();
    }
    highest_generation[id] = record->record_generation.value();

    for (const fr::AliasKey& alias : record->aliases) {
      if (!fr::alias_is_unique(alias.alias_namespace)) {
        continue;
      }
      ++indexed_aliases;
      RecordPtr by_alias;
      const fr::Outcome outcome = registry.lookup_by_alias(alias, by_alias);
      if (!outcome.committed() || by_alias == nullptr) {
        return "a unique alias does not resolve: " + alias.to_string();
      }
      if (!(by_alias->id == record->id)) {
        return "a unique alias resolves to a different record: " + alias.to_string();
      }
    }
  }
  if (indexed_aliases != stats.indexed_aliases) {
    return "the number of indexed aliases disagrees with stats().indexed_aliases: " +
           std::to_string(indexed_aliases) + " versus " + std::to_string(stats.indexed_aliases);
  }
  return std::string();
}

// ---------------------------------------------------------------------------
// The state machine driver
// ---------------------------------------------------------------------------

struct SeedRecord {
  fr::CanonicalId id{};
  std::string serial;
};

enum class Operation : std::uint8_t {
  RegisterNew = 0,
  RegisterExisting,
  AttachAlias,
  DetachAlias,
  UpdateEvidence,
  Revalidate,
  Retire,
  Tombstone,
  Supersede,
  Reconcile,
  Lookup,
  Snapshot,
  AdvanceEpoch,
  FencePublisher,
};

std::string operation_name(Operation operation) {
  switch (operation) {
    case Operation::RegisterNew:
      return "register-new";
    case Operation::RegisterExisting:
      return "register-existing";
    case Operation::AttachAlias:
      return "attach-alias";
    case Operation::DetachAlias:
      return "detach-alias";
    case Operation::UpdateEvidence:
      return "update-evidence";
    case Operation::Revalidate:
      return "revalidate";
    case Operation::Retire:
      return "retire";
    case Operation::Tombstone:
      return "tombstone";
    case Operation::Supersede:
      return "supersede";
    case Operation::Reconcile:
      return "reconcile";
    case Operation::Lookup:
      return "lookup";
    case Operation::Snapshot:
      return "snapshot";
    case Operation::AdvanceEpoch:
      return "advance-epoch";
    case Operation::FencePublisher:
      return "fence-publisher";
  }
  return "unknown";
}

Operation choose_operation(std::uint32_t draw, bool has_records, bool room_for_new, bool recovery_due) {
  if (recovery_due) {
    // The embedded publisher was just fenced; only an epoch advance can bring it
    // back, so the driver performs it immediately instead of idling.
    return Operation::AdvanceEpoch;
  }
  if (!has_records) {
    // No record exists yet: only a registration is meaningful, and a
    // registration of a fresh identity always commits, so the very next draw
    // has records to work with.
    return Operation::RegisterNew;
  }
  if (draw < 100) {
    return room_for_new ? Operation::RegisterNew : Operation::Snapshot;
  }
  if (draw < 200) {
    return has_records ? Operation::RegisterExisting : Operation::RegisterNew;
  }
  if (draw < 300) {
    return has_records ? Operation::AttachAlias : Operation::Snapshot;
  }
  if (draw < 370) {
    return has_records ? Operation::DetachAlias : Operation::Snapshot;
  }
  if (draw < 470) {
    return has_records ? Operation::UpdateEvidence : Operation::Snapshot;
  }
  if (draw < 530) {
    return has_records ? Operation::Revalidate : Operation::Snapshot;
  }
  if (draw < 590) {
    return has_records ? Operation::Retire : Operation::Snapshot;
  }
  if (draw < 620) {
    return has_records ? Operation::Tombstone : Operation::Snapshot;
  }
  if (draw < 670) {
    return has_records ? Operation::Supersede : Operation::Snapshot;
  }
  if (draw < 750) {
    return Operation::Reconcile;
  }
  if (draw < 860) {
    return has_records ? Operation::Lookup : Operation::Snapshot;
  }
  if (draw < 910) {
    return Operation::Snapshot;
  }
  if (draw < 940) {
    return Operation::AdvanceEpoch;
  }
  return Operation::FencePublisher;
}

void run_seed(std::uint64_t seed) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(seed);
  frtest::Rng rng(seed);
  std::vector<SeedRecord> known;
  std::unordered_map<fr::CanonicalId, std::uint64_t> highest_generation;
  std::size_t ordinal = 0;
  bool recovery_due = false;

  for (std::size_t index = 0; index < kOperationsPerSeed; ++index) {
    const std::uint32_t draw = static_cast<std::uint32_t>(rng.below(1000));
    const Operation operation = choose_operation(draw, !known.empty(), known.size() < kMaximumDriverRecords, recovery_due);
    const std::string kind = operation_name(operation);
    recovery_due = false;

    fr::Outcome outcome;
    if (operation == Operation::RegisterNew) {
      const std::string serial = "driver-" + std::to_string(seed) + "-" + std::to_string(ordinal);
      const std::string label = "seed" + std::to_string(seed) + "-new-" + std::to_string(ordinal);
      ++ordinal;
      const fr::RegisterEntityRequest request =
          frtest::device_request(*registry, label, serial, fr::EntityClass::Switch, "driver/namespace");
      outcome = registry->register_entity(request);
      std::vector<fr::CanonicalId> found;
      const fr::Outcome by_fact = registry->lookup_by_fact(frtest::serial_fact(serial), found);
      if (outcome.committed()) {
        FR_CHECK_MSG(by_fact.committed() && found.size() == 1,
                     seed_context(seed, index, kind, "a committed registration must leave exactly one indexed record"));
        known.push_back(SeedRecord{found.front(), serial});
      } else {
        FR_CHECK_MSG(!by_fact.committed(), seed_context(seed, index, kind, "a rejected registration created a record"));
      }
    } else if (operation == Operation::RegisterExisting) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      const std::string label = "seed" + std::to_string(seed) + "-again-" + std::to_string(index);
      const fr::RegisterEntityRequest request =
          frtest::device_request(*registry, label, target.serial, fr::EntityClass::Switch, "driver/namespace");
      outcome = registry->register_entity(request);
      if (outcome.committed()) {
        FR_CHECK_MSG(outcome.record.has_value() && *outcome.record == target.id,
                     seed_context(seed, index, kind, "a committed re-registration must address the existing record"));
      }
    } else if (operation == Operation::AttachAlias) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      const std::string value = "cmdb-" + std::to_string(seed) + "-" + std::to_string(index);
      fr::AliasMutationRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-alias-" + std::to_string(index));
      request.authority = registry->local_authority();
      request.target = target.id;
      request.alias = frtest::alias_of(fr::AliasNamespace::ExternalCmdbId, value);
      outcome = registry->attach_alias(request);
      if (outcome.committed()) {
        fr::AliasKey key;
        key.alias_namespace = fr::AliasNamespace::ExternalCmdbId;
        key.value = value;
        RecordPtr by_alias;
        const fr::Outcome resolved = registry->lookup_by_alias(key, by_alias);
        FR_CHECK_MSG(resolved.committed() && by_alias != nullptr && by_alias->id == target.id,
                     seed_context(seed, index, kind, "an attached alias must resolve to the record it was attached to"));
      }
    } else if (operation == Operation::DetachAlias) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      const RecordPtr record = load_record(*registry, target.id);
      FR_CHECK_MSG(record != nullptr, seed_context(seed, index, kind, "the addressed record disappeared"));
      bool performed = false;
      if (!record->aliases.empty()) {
        const fr::AliasKey key = record->aliases[static_cast<std::size_t>(rng.below(record->aliases.size()))];
        fr::AliasMutationRequest request;
        request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-detach-" + std::to_string(index));
        request.authority = registry->local_authority();
        request.target = target.id;
        request.alias.alias_namespace = key.alias_namespace;
        request.alias.value = key.value;
        outcome = registry->detach_alias(request);
        performed = true;
        if (outcome.committed()) {
          const RecordPtr after = load_record(*registry, target.id);
          FR_CHECK_MSG(after != nullptr &&
                           std::find(after->aliases.begin(), after->aliases.end(), key) == after->aliases.end(),
                       seed_context(seed, index, kind, "a detached alias is still attached"));
        }
      }
      if (!performed) {
        RecordPtr resolved;
        outcome = registry->lookup(target.id, resolved);
      }
    } else if (operation == Operation::UpdateEvidence) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      const RecordPtr record = load_record(*registry, target.id);
      FR_CHECK_MSG(record != nullptr, seed_context(seed, index, kind, "the addressed record disappeared"));
      fr::UpdateEvidenceRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-update-" + std::to_string(index));
      request.authority = registry->local_authority();
      request.target = target.id;
      request.facts = record->facts;
      request.provenance = frtest::real_provenance();
      request.evidence_class = fr::EvidenceClass::DurableAuthority;
      request.merge_facts = true;
      outcome = registry->update_evidence(request);
      if (outcome.committed()) {
        const RecordPtr after = load_record(*registry, target.id);
        FR_CHECK_MSG(after != nullptr && after->record_generation.value() == record->record_generation.value() + 1,
                     seed_context(seed, index, kind, "a committed update must advance the record generation by one"));
      }
    } else if (operation == Operation::Revalidate) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      const RecordPtr record = load_record(*registry, target.id);
      FR_CHECK_MSG(record != nullptr, seed_context(seed, index, kind, "the addressed record disappeared"));
      fr::RevalidateEntityRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-revalidate-" + std::to_string(index));
      request.authority = registry->local_authority();
      request.target = target.id;
      request.facts = record->facts;
      request.provenance = frtest::real_provenance();
      request.evidence_class = fr::EvidenceClass::DurableAuthority;
      request.merge_facts = true;
      outcome = registry->revalidate_entity(request);
      if (outcome.committed()) {
        const RecordPtr after = load_record(*registry, target.id);
        FR_CHECK_MSG(after != nullptr && after->lifecycle == fr::Lifecycle::Current,
                     seed_context(seed, index, kind, "a committed revalidation must leave the record current"));
      }
    } else if (operation == Operation::Retire) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      fr::RetireEntityRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-retire-" + std::to_string(index));
      request.authority = registry->local_authority();
      request.target = target.id;
      request.reason = "driver retirement";
      outcome = registry->retire_entity(request);
      if (outcome.committed()) {
        const RecordPtr after = load_record(*registry, target.id);
        FR_CHECK_MSG(after != nullptr && after->lifecycle == fr::Lifecycle::Retired,
                     seed_context(seed, index, kind, "a committed retirement must retire the record"));
      }
    } else if (operation == Operation::Tombstone) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      fr::TombstoneEntityRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-tombstone-" + std::to_string(index));
      request.authority = registry->local_authority();
      request.target = target.id;
      request.reason = "driver tombstone";
      outcome = registry->tombstone_entity(request);
      if (outcome.committed()) {
        const RecordPtr after = load_record(*registry, target.id);
        FR_CHECK_MSG(after != nullptr && after->lifecycle == fr::Lifecycle::Tombstoned && !after->evidence.valid,
                     seed_context(seed, index, kind, "a committed tombstone must close the identity permanently"));
      }
    } else if (operation == Operation::Supersede) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      fr::SupersedeEntityRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-supersede-" + std::to_string(index));
      request.authority = registry->local_authority();
      request.target = target.id;
      request.reason = "driver supersession";
      outcome = registry->supersede_entity(request);
      if (outcome.committed()) {
        const RecordPtr after = load_record(*registry, target.id);
        FR_CHECK_MSG(after != nullptr && after->lifecycle == fr::Lifecycle::Superseded,
                     seed_context(seed, index, kind, "a committed supersession must supersede the record"));
      }
    } else if (operation == Operation::Reconcile) {
      std::string serial;
      if (!known.empty() && rng.chance(50)) {
        serial = known[static_cast<std::size_t>(rng.below(known.size()))].serial;
      } else {
        serial = "driver-observation-" + std::to_string(seed) + "-" + std::to_string(index);
      }
      fr::ReconcileObservationRequest request;
      request.attempt = frtest::attempt_from("seed" + std::to_string(seed) + "-reconcile-" + std::to_string(index));
      request.entity_class = fr::EntityClass::Switch;
      request.facts.push_back(frtest::serial_fact(serial));
      request.provenance = frtest::real_provenance();
      const fr::ReconcileResult result = registry->reconcile_observation(request);
      outcome = result.outcome;
      if (outcome.committed()) {
        FR_CHECK_MSG(result.detail.matched.has_value(),
                     seed_context(seed, index, kind, "a committed reconciliation must name the record it matched"));
      }
      if (result.detail.matched.has_value()) {
        FR_CHECK_MSG(outcome.code == fr::OutcomeCode::Committed || outcome.code == fr::OutcomeCode::ProbableMatch,
                     seed_context(seed, index, kind, "a named match must be committed or probable"));
      }
    } else if (operation == Operation::Lookup) {
      const SeedRecord& target = known[static_cast<std::size_t>(rng.below(known.size()))];
      RecordPtr record;
      outcome = registry->lookup(target.id, record);
      FR_CHECK_MSG(outcome.committed() && record != nullptr && record->id == target.id,
                   seed_context(seed, index, kind, "every known identity must resolve through lookup"));
    } else if (operation == Operation::Snapshot) {
      const fr::Snapshot snapshot = registry->snapshot();
      outcome = fr::Outcome(fr::OutcomeCode::Committed, "snapshot taken");
      FR_CHECK_MSG(registry->snapshot_current(snapshot),
                   seed_context(seed, index, kind, "a snapshot taken by an idle registry must still be current"));
      FR_CHECK_MSG(snapshot.size() == registry->stats().entities,
                   seed_context(seed, index, kind, "a snapshot must contain every record"));
      for (const RecordPtr& record : snapshot.records()) {
        FR_CHECK_MSG(record != nullptr && snapshot.find(record->id) == record,
                     seed_context(seed, index, kind, "snapshot.find disagrees with the snapshot record list"));
      }
    } else if (operation == Operation::AdvanceEpoch) {
      std::size_t demoted = 0;
      outcome = registry->advance_epoch(demoted);
      FR_CHECK_MSG(outcome.committed(), seed_context(seed, index, kind, "advancing the epoch must commit"));
    } else {
      std::size_t demoted = 0;
      outcome = registry->fence_publisher(registry->local_authority().publisher, fr::FenceReason::Administrative, demoted);
      FR_CHECK_MSG(outcome.committed(), seed_context(seed, index, kind, "fencing the embedded publisher must commit"));
      recovery_due = true;
    }

    const std::string malformed = outcome_problem(outcome);
    FR_CHECK_MSG(malformed.empty(), seed_context(seed, index, kind, malformed));
    const std::string violation = invariant_problem(*registry, highest_generation);
    FR_CHECK_MSG(violation.empty(), seed_context(seed, index, kind, violation));
  }
}

/// Registers one switch entity. Returns false and fills `error` when the
/// registration did not produce exactly one indexed record.
bool register_switch(fr::Registry& registry,
                     const std::string& label,
                     const std::string& serial,
                     fr::CanonicalId& out,
                     std::string& error,
                     const std::string& derivation_namespace = "property/namespace",
                     fr::EvidenceClass evidence_class = fr::EvidenceClass::DurableAuthority) {
  const fr::RegisterEntityRequest request =
      frtest::device_request(registry, label, serial, fr::EntityClass::Switch, derivation_namespace, evidence_class);
  const fr::Outcome outcome = registry.register_entity(request);
  if (!outcome.committed()) {
    error = "a well formed registration must commit: " + outcome.message;
    return false;
  }
  std::vector<fr::CanonicalId> found;
  const fr::Outcome by_fact = registry.lookup_by_fact(frtest::serial_fact(serial), found);
  if (!by_fact.committed() || found.size() != 1) {
    error = "a committed registration must be indexed by its serial fact";
    return false;
  }
  out = found.front();
  return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

FR_TEST_CASE(property, state_machine_invariants) {
  for (const std::uint64_t seed : kDriverSeeds) {
    run_seed(seed);
  }
}

FR_TEST_CASE(property, record_codec_round_trip_and_single_byte_flips) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(20260214);
  for (std::size_t index = 0; index < kCodecRecords; ++index) {
    const std::string tag = std::to_string(index);
    fr::RegisterEntityRequest request = frtest::device_request(*registry, "codec-" + tag, "codec-serial-" + tag);
    request.friendly_name = "codec record " + tag;
    request.aliases.push_back(frtest::alias_of(fr::AliasNamespace::ExternalCmdbId, "codec-cmdb-" + tag));
    request.aliases.push_back(frtest::alias_of(fr::AliasNamespace::SerialNumber, "codec-alias-serial-" + tag));
    request.metadata.push_back(fr::MetadataEntry{"site", "rack-" + tag});
    request.metadata.push_back(fr::MetadataEntry{"owner", "team-" + tag});
    if (index % 2 == 0) {
      fr::IdBytes fabric_bytes{};
      fr::IdBytes site_bytes{};
      fabric_bytes[0] = static_cast<std::uint8_t>(index + 1);
      site_bytes[1] = static_cast<std::uint8_t>(index + 2);
      request.scope.fabric = fr::FabricId::from_bytes(fabric_bytes);
      request.scope.site = fr::SiteId::from_bytes(site_bytes);
    }
    FR_CHECK_MSG(registry->register_entity(request).committed(), "the codec fixture record must register");
  }
  // Lifecycle variety: the encoder must round trip every state a record can
  // reach, not only the state a fresh record starts in.
  std::vector<fr::CanonicalId> ids = record_ids(*registry);
  FR_CHECK_EQ(ids.size(), kCodecRecords);
  const auto retire_record = [&registry](const fr::CanonicalId& target, const std::string& label) {
    fr::RetireEntityRequest request;
    request.attempt = frtest::attempt_from(label);
    request.authority = registry->local_authority();
    request.target = target;
    request.reason = "codec variety";
    return registry->retire_entity(request);
  };
  const auto supersede_record = [&registry](const fr::CanonicalId& target, const std::string& label) {
    fr::SupersedeEntityRequest request;
    request.attempt = frtest::attempt_from(label);
    request.authority = registry->local_authority();
    request.target = target;
    request.reason = "codec variety";
    return registry->supersede_entity(request);
  };
  const auto tombstone_record = [&registry](const fr::CanonicalId& target, const std::string& label) {
    fr::TombstoneEntityRequest request;
    request.attempt = frtest::attempt_from(label);
    request.authority = registry->local_authority();
    request.target = target;
    request.reason = "codec variety";
    return registry->tombstone_entity(request);
  };
  // Only retired and superseded records may be tombstoned, so three records
  // reach that state through each of the two legal paths.
  for (std::size_t index = 0; index < 16; ++index) {
    const fr::CanonicalId target = ids[index];
    const std::string tag = std::to_string(index);
    if (index % 4 == 0) {
      FR_CHECK_MSG(retire_record(target, "codec-retire-" + tag).committed(),
                   "retiring a current record must commit");
    } else if (index % 4 == 1) {
      FR_CHECK_MSG(supersede_record(target, "codec-supersede-" + tag).committed(),
                   "superseding a current record must commit");
    } else if (index % 4 == 2) {
      FR_CHECK_MSG(retire_record(target, "codec-retire-" + tag).committed(),
                   "retiring a current record must commit");
      FR_CHECK_MSG(tombstone_record(target, "codec-tombstone-" + tag).committed(),
                   "tombstoning a retired record must commit");
    } else {
      FR_CHECK_MSG(supersede_record(target, "codec-supersede-" + tag).committed(),
                   "superseding a current record must commit");
      FR_CHECK_MSG(tombstone_record(target, "codec-tombstone-" + tag).committed(),
                   "tombstoning a superseded record must commit");
    }
  }

  const fr::Snapshot snapshot = registry->snapshot();
  FR_CHECK_EQ(snapshot.size(), kCodecRecords);
  const fr::RegistryLimits limits = fr::RegistryLimits::defaults();
  for (const RecordPtr& record : snapshot.records()) {
    const std::vector<std::uint8_t> encoded = fr::encode_record(*record);
    FR_CHECK_MSG(!encoded.empty(), "an encoded record is never empty");
    fr::EntityRecord decoded;
    std::string error;
    FR_CHECK_MSG(fr::decode_record(encoded, limits, decoded, error),
                 "the encoded record did not decode: " + record->id.to_string() + ": " + error);
    FR_CHECK_MSG(records_equal(*record, decoded),
                 "the decoded record differs from the encoded one: " + record->id.to_string());
    for (std::size_t position = 0; position < encoded.size(); ++position) {
      std::vector<std::uint8_t> flipped = encoded;
      flipped[position] = static_cast<std::uint8_t>(flipped[position] ^ 0xFFu);
      fr::EntityRecord other;
      std::string flip_error;
      if (fr::decode_record(flipped, limits, other, flip_error)) {
        FR_CHECK_MSG(!records_equal(*record, other),
                     "flipping byte " + std::to_string(position) + " of " + record->id.to_string() +
                         " produced the same record");
      }
    }
  }
}

FR_TEST_CASE(property, rendering_is_pure_and_distinguishes_every_field) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(4242);
  for (std::size_t index = 0; index < 24; ++index) {
    const std::string tag = std::to_string(index);
    fr::RegisterEntityRequest request = frtest::device_request(*registry, "render-" + tag, "render-serial-" + tag);
    request.aliases.push_back(frtest::alias_of(fr::AliasNamespace::ExternalCmdbId, "render-cmdb-" + tag));
    request.metadata.push_back(fr::MetadataEntry{"owner", "team-" + tag});
    FR_CHECK(registry->register_entity(request).committed());
  }
  const fr::Snapshot snapshot = registry->snapshot();
  FR_CHECK(!snapshot.empty());
  const std::vector<RecordPtr>& records = snapshot.records();
  for (std::size_t index = 0; index < records.size(); ++index) {
    const fr::EntityRecord& record = *records[index];
    const std::string text = fr::render_record(record);
    const std::string json = fr::render_record_json(record);
    FR_CHECK_MSG(text == fr::render_record(record), "render_record is not a pure function");
    FR_CHECK_MSG(json == fr::render_record_json(record), "render_record_json is not a pure function");
    FR_CHECK_MSG(!text.empty() && !json.empty(), "a rendered record is never empty");

    fr::EntityRecord changed = record;
    switch (index % 12) {
      case 0:
        changed.friendly_name += "-other";
        break;
      case 1:
        changed.record_generation = fr::RecordGeneration(record.record_generation.value() + 1);
        break;
      case 2:
        changed.status_reason = "changed";
        break;
      case 3:
        changed.lifecycle = record.lifecycle == fr::Lifecycle::Current ? fr::Lifecycle::Retired : fr::Lifecycle::Current;
        break;
      case 4:
        changed.facts.push_back(frtest::fact_of(fr::IdentityFactKind::OperatorLabel, "extra"));
        break;
      case 5:
        changed.metadata.push_back(fr::MetadataEntry{"zeta", "1"});
        break;
      case 6:
        changed.evidence.valid = !record.evidence.valid;
        break;
      case 7:
        changed.aliases.push_back(fr::AliasKey{fr::AliasNamespace::ExternalCmdbId, std::string(), "extra"});
        break;
      case 8:
        changed.derivation_namespace += "-other";
        break;
      case 9: {
        fr::DigestBytes digest = record.hardware_identity.bytes();
        digest[0] = static_cast<std::uint8_t>(digest[0] ^ 0x01u);
        changed.hardware_identity = fr::StableHardwareIdentity::from_bytes(digest);
        break;
      }
      case 10:
        changed.superseded_by = fr::CanonicalId(fr::EntityClass::Switch, fr::IdBytes{});
        break;
      default:
        changed.created_epoch = fr::CoordinatorEpoch(record.created_epoch.value() + 1);
        break;
    }
    FR_CHECK_MSG(fr::render_record(changed) != text,
                 "two records differing in one field render identically as text: " + record.id.to_string());
    FR_CHECK_MSG(fr::render_record_json(changed) != json,
                 "two records differing in one field render identically as JSON: " + record.id.to_string());
  }
}

FR_TEST_CASE(property, persistence_round_trip_preserves_identity) {
  for (const std::uint64_t seed : kPersistenceSeeds) {
    const std::unique_ptr<fr::Registry> registry = frtest::make_registry(seed);
    std::size_t aliases = 0;
    for (std::size_t index = 0; index < kPersistenceRecords; ++index) {
      const std::string tag = std::to_string(seed) + "-" + std::to_string(index);
      fr::RegisterEntityRequest request =
          frtest::device_request(*registry, "persist-" + tag, "persist-serial-" + tag);
      request.aliases.push_back(frtest::alias_of(fr::AliasNamespace::ExternalCmdbId, "persist-cmdb-" + tag));
      if (index % 4 == 0) {
        request.aliases.push_back(frtest::alias_of(fr::AliasNamespace::DnsName, "persist-" + tag + ".example.test"));
      }
      FR_CHECK_MSG(registry->register_entity(request).committed(), "the persistence fixture record must register");
      aliases += request.aliases.size();
    }
    // One committed mutation per record, so the round trip has to preserve a
    // generation that is not the creation generation.
    std::vector<fr::CanonicalId> ids = record_ids(*registry);
    for (std::size_t index = 0; index < ids.size(); index += 3) {
      const RecordPtr record = load_record(*registry, ids[index]);
      FR_CHECK(record != nullptr);
      fr::UpdateEvidenceRequest update;
      update.attempt = frtest::attempt_from("persist-update-" + std::to_string(seed) + "-" + std::to_string(index));
      update.authority = registry->local_authority();
      update.target = ids[index];
      update.facts = record->facts;
      update.provenance = frtest::real_provenance();
      update.evidence_class = fr::EvidenceClass::DurableAuthority;
      update.merge_facts = true;
      FR_CHECK(registry->update_evidence(update).committed());
    }

    const std::filesystem::path path = frtest::temporary_state_path("property-" + std::to_string(seed));
    frtest::remove_state(path);
    const fr::Outcome saved = registry->save(path, true);
    const std::string save_problem = "saving durable state must commit: " + saved.message + " at " + path.string();
    FR_CHECK_MSG(saved.committed(), save_problem);

    const std::unique_ptr<fr::Registry> loaded = frtest::make_registry(seed + 1000);
    fr::RecoveryReport report;
    const fr::Outcome outcome = loaded->load(path, report);
    FR_CHECK_MSG(outcome.committed(), "loading durable state must commit: " + outcome.message);
    FR_CHECK_EQ(report.records_loaded, kPersistenceRecords);
    FR_CHECK_EQ(report.aliases_loaded, aliases);
    std::string validation;
    FR_CHECK_MSG(loaded->validate_state(validation).committed(), "the recovered registry is inconsistent");
    // Publishers are never restored as live: every saved publisher other than
    // the loader's own is restored fenced.
    FR_CHECK_EQ(report.publishers_loaded, registry->publishers().size());
    FR_CHECK_EQ(report.publishers_fenced, report.publishers_loaded);

    const std::vector<fr::CanonicalId> before_ids = record_ids(*registry);
    const std::vector<fr::CanonicalId> after_ids = record_ids(*loaded);
    FR_CHECK_MSG(before_ids == after_ids, "the recovered identity set differs from the saved one");
    for (const fr::CanonicalId& id : before_ids) {
      const RecordPtr before = load_record(*registry, id);
      const RecordPtr after = load_record(*loaded, id);
      FR_CHECK_MSG(before != nullptr && after != nullptr, "an identity did not survive recovery: " + id.to_string());
      FR_CHECK_MSG(before->aliases == after->aliases, "the alias set of " + id.to_string() + " changed across recovery");
      FR_CHECK_MSG(before->record_generation == after->record_generation &&
                       before->creation_generation == after->creation_generation &&
                       before->evidence_generation == after->evidence_generation,
                   "the generations of " + id.to_string() + " changed across recovery");
      FR_CHECK_MSG(before->facts == after->facts && before->lifecycle == after->lifecycle,
                   "the recovered record differs from the saved one: " + id.to_string());
    }
    frtest::remove_state(path);
  }
}

FR_TEST_CASE(property, record_generation_is_monotonic_across_two_hundred_mutations) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(777);
  fr::CanonicalId target;
  std::string registration_error;
  FR_CHECK_MSG(register_switch(*registry, "monotonic-base", "monotonic-serial", target, registration_error),
               registration_error);
  const RecordPtr created = load_record(*registry, target);
  FR_CHECK(created != nullptr);
  FR_CHECK_EQ(created->record_generation.value(), std::uint64_t{1});
  FR_CHECK_EQ(created->creation_generation.value(), std::uint64_t{1});

  std::uint64_t previous_registry_generation = registry->stats().generation.value();
  for (std::size_t step = 0; step < kGenerationSteps; ++step) {
    const RecordPtr before = load_record(*registry, target);
    FR_CHECK(before != nullptr);
    fr::UpdateEvidenceRequest request;
    request.attempt = frtest::attempt_from("monotonic-" + std::to_string(step));
    request.authority = registry->local_authority();
    request.target = target;
    request.facts = before->facts;
    request.provenance = frtest::real_provenance();
    request.evidence_class = fr::EvidenceClass::DurableAuthority;
    request.merge_facts = true;
    const fr::Outcome outcome = registry->update_evidence(request);
    FR_CHECK_MSG(outcome.committed(), "mutation " + std::to_string(step) + " was rejected: " + outcome.message);
    const RecordPtr after = load_record(*registry, target);
    FR_CHECK(after != nullptr);
    FR_CHECK_MSG(after->record_generation.value() == before->record_generation.value() + 1,
                 "the record generation did not advance by exactly one at step " + std::to_string(step));
    FR_CHECK_MSG(after->creation_generation == before->creation_generation,
                 "the creation generation changed at step " + std::to_string(step));
    const std::uint64_t registry_generation = registry->stats().generation.value();
    FR_CHECK_MSG(registry_generation > previous_registry_generation,
                 "the registry generation did not advance at step " + std::to_string(step));
    previous_registry_generation = registry_generation;
  }
  const RecordPtr final_record = load_record(*registry, target);
  FR_CHECK(final_record != nullptr);
  FR_CHECK_EQ(final_record->record_generation.value(), static_cast<std::uint64_t>(kGenerationSteps) + 1u);
}

FR_TEST_CASE(property, idempotent_replay_does_not_advance_the_registry) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(31337);
  std::vector<fr::RegisterEntityRequest> requests;
  requests.reserve(kReplayRequests);
  for (std::size_t index = 0; index < kReplayRequests; ++index) {
    const std::string tag = std::to_string(index);
    fr::RegisterEntityRequest request =
        frtest::device_request(*registry, "replay-" + tag, "replay-serial-" + tag);
    request.aliases.push_back(frtest::alias_of(fr::AliasNamespace::ExternalCmdbId, "replay-cmdb-" + tag));
    FR_CHECK_MSG(registry->register_entity(request).committed(), "the replay fixture record must register");
    requests.push_back(std::move(request));
  }
  const fr::RegistryStats before = registry->stats();
  for (std::size_t index = 0; index < requests.size(); ++index) {
    const fr::Outcome outcome = registry->register_entity(requests[index]);
    FR_CHECK_MSG(outcome.code == fr::OutcomeCode::Idempotent,
                 "replaying request " + std::to_string(index) + " returned " + std::string(fr::to_string(outcome.code)));
    FR_CHECK_MSG(outcome.record.has_value(), "an idempotent replay must name the record it produced");
  }
  const fr::RegistryStats after = registry->stats();
  FR_CHECK_MSG(before.generation == after.generation, "an idempotent replay advanced the registry generation");
  FR_CHECK_EQ(before.entities, after.entities);
  FR_CHECK_EQ(before.idempotency_records, after.idempotency_records);
}

FR_TEST_CASE(property, stale_generation_is_rejected_without_state_change) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(90210);
  std::vector<fr::CanonicalId> ids;
  for (std::size_t index = 0; index < kReplayRequests; ++index) {
    const std::string tag = std::to_string(index);
    fr::CanonicalId id;
    std::string registration_error;
    FR_CHECK_MSG(register_switch(*registry, "stale-" + tag, "stale-serial-" + tag, id, registration_error),
                 registration_error);
    ids.push_back(id);
  }
  // Bring every record to generation two so that "one below" is a real,
  // previously current generation.
  for (std::size_t index = 0; index < ids.size(); ++index) {
    const RecordPtr record = load_record(*registry, ids[index]);
    FR_CHECK(record != nullptr);
    fr::UpdateEvidenceRequest update;
    update.attempt = frtest::attempt_from("stale-bump-" + std::to_string(index));
    update.authority = registry->local_authority();
    update.target = ids[index];
    update.facts = record->facts;
    update.provenance = frtest::real_provenance();
    update.evidence_class = fr::EvidenceClass::DurableAuthority;
    update.merge_facts = true;
    FR_CHECK(registry->update_evidence(update).committed());
  }
  for (std::size_t index = 0; index < ids.size(); ++index) {
    const RecordPtr record = load_record(*registry, ids[index]);
    FR_CHECK(record != nullptr);
    FR_CHECK_EQ(record->record_generation.value(), std::uint64_t{2});
    const fr::StateDigest before = registry->state_digest();
    const std::uint64_t entities = registry->stats().entities;

    fr::UpdateEvidenceRequest update;
    update.attempt = frtest::attempt_from("stale-attempt-" + std::to_string(index));
    update.authority = registry->local_authority();
    update.target = ids[index];
    update.expected_generation = fr::RecordGeneration(record->record_generation.value() - 1u);
    update.facts = record->facts;
    update.provenance = frtest::real_provenance();
    update.evidence_class = fr::EvidenceClass::DurableAuthority;
    update.merge_facts = true;
    const fr::Outcome outcome = registry->update_evidence(update);
    FR_CHECK_MSG(outcome.code == fr::OutcomeCode::StaleGeneration,
                 "record " + std::to_string(index) + " returned " + std::string(fr::to_string(outcome.code)));
    FR_CHECK_MSG(registry->state_digest() == before, "a stale request changed the state digest");
    FR_CHECK_EQ(registry->stats().entities, entities);
    const RecordPtr after = load_record(*registry, ids[index]);
    FR_CHECK(after != nullptr && after->record_generation == record->record_generation);
  }
}

FR_TEST_CASE(property, malformed_canonical_identifiers_never_round_trip_wrongly) {
  // A handful of inputs whose classification is fixed by the contract.
  FR_CHECK(!fr::CanonicalId::parse("").has_value());
  FR_CHECK(!fr::CanonicalId::parse("switch").has_value());
  FR_CHECK(!fr::CanonicalId::parse("switch:").has_value());
  FR_CHECK(!fr::CanonicalId::parse("switch:00000000000000000000000000000000").has_value());
  FR_CHECK(!fr::CanonicalId::parse("switch:0123456789abcdef0123456789abcde").has_value());
  FR_CHECK(!fr::CanonicalId::parse("switch:0123456789abcdef0123456789abcdeg").has_value());
  FR_CHECK(!fr::CanonicalId::parse("unknown:0123456789abcdef0123456789abcdef").has_value());
  const std::optional<fr::CanonicalId> known = fr::CanonicalId::parse("switch:0123456789abcdef0123456789abcdef");
  FR_CHECK(known.has_value());
  FR_CHECK_EQ(known->to_string(), std::string("switch:0123456789abcdef0123456789abcdef"));

  frtest::Rng rng(13579);
  const char* kHexDigits = "0123456789abcdef";
  for (std::size_t index = 0; index < kMalformedInputs; ++index) {
    std::string text;
    switch (index % 10) {
      case 0:
        break;
      case 1:
        text = frtest::random_text(rng, static_cast<std::size_t>(rng.below(64)));
        break;
      case 2:
        text = "switch:";
        text += frtest::random_text(rng, 32);
        break;
      case 3: {
        text = "switch:";
        for (std::size_t digit = 0; digit < 32; ++digit) {
          text.push_back(kHexDigits[static_cast<std::size_t>(rng.below(16))]);
        }
        if (text[7] == '0') {
          text[7] = 'a';
        }
        break;
      }
      case 4:
        text = "port:";
        text += frtest::random_text(rng, 31);
        text.push_back('\0');
        break;
      case 5:
        text = frtest::random_text(rng, 4096);
        break;
      case 6: {
        text = "nic:";
        for (std::size_t digit = 0; digit < 32; ++digit) {
          const char value = kHexDigits[static_cast<std::size_t>(rng.below(16))];
          text.push_back((digit % 2 == 0) ? static_cast<char>(value - 32) : value);
        }
        break;
      }
      case 7: {
        const std::size_t length = static_cast<std::size_t>(rng.below(40));
        for (std::size_t byte = 0; byte < length; ++byte) {
          text.push_back(static_cast<char>(static_cast<std::uint8_t>(rng.below(256))));
        }
        break;
      }
      case 8:
        text = std::string("host\0name:", 10);
        text += "0123456789abcdef0123456789abcdef";
        break;
      default:
        text = frtest::random_text(rng, static_cast<std::size_t>(rng.below(8)));
        text += ":0123456789abcdef0123456789abcdef";
        break;
    }

    const std::optional<fr::CanonicalId> parsed = fr::CanonicalId::parse(text);
    if (index % 10 == 3) {
      FR_CHECK_MSG(parsed.has_value(), "a well formed canonical identity must parse");
    }
    if (!parsed.has_value()) {
      continue;
    }
    FR_CHECK_MSG(!parsed->is_null(), "a parsed canonical identity is never null");
    const std::optional<fr::CanonicalId> again = fr::CanonicalId::parse(parsed->to_string());
    FR_CHECK_MSG(again.has_value() && *again == *parsed,
                 "a parsed canonical identity did not round trip through to_string at input " + std::to_string(index));
    FR_CHECK_EQ(parsed->to_string().size(), fr::kOpaqueIdTextLength + std::string(fr::to_string(parsed->entity_class())).size() + 1u);
  }
}

int main(int argc, char** argv) {
  return frtest::run_all(argc, argv);
}
