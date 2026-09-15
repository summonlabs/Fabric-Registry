// Fabric Registry — entity records and lifecycle.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FABRIC_REGISTRY_ENTITY_HPP
#define FABRIC_REGISTRY_ENTITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/errors.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/ids.hpp"

namespace fabric_registry {

/// The lifecycle of a registry record.
///
/// Enumerator values are part of the persisted format and must never be
/// renumbered.
enum class Lifecycle : std::uint8_t {
  /// Observed by a non-authoritative source. The registry knows of it; it is
  /// not and has never been authoritative.
  Discovered = 0,
  /// A registration carrying a valid authority claim that has not yet been
  /// promoted to current.
  Candidate = 1,
  /// Authoritative and current.
  Current = 2,
  /// Was current; its evidence is no longer acceptable as current (the
  /// publisher died, the coordinator epoch advanced, or the evidence aged out).
  RevalidationRequired = 3,
  /// Replaced by a different record. Cannot become current again.
  Superseded = 4,
  /// Withdrawn by an authorized publisher. Cannot become current again.
  Retired = 5,
  /// Permanently closed. The identity may never be re-registered.
  Tombstoned = 6,
  /// Competing claims were detected. Frozen until explicitly resolved.
  Conflicted = 7,
  /// A candidate that failed validation or was explicitly rejected.
  Rejected = 8,
};

inline constexpr std::uint8_t kLifecycleCount = 9;

FABRIC_REGISTRY_API std::string_view to_string(Lifecycle value) noexcept;
FABRIC_REGISTRY_API std::optional<Lifecycle> lifecycle_from_string(std::string_view text) noexcept;

/// True when no further transition out of this state exists.
FABRIC_REGISTRY_API bool is_terminal_lifecycle(Lifecycle value) noexcept;

/// True when a record in this state may be treated as authoritative right now.
FABRIC_REGISTRY_API bool holds_current_authority(Lifecycle value) noexcept;

/// True only for the transitions the registry will perform. Every other
/// transition fails with OutcomeCode::IllegalTransition.
///
/// Legal transitions:
///   Discovered            -> Candidate, Conflicted, Rejected
///   Candidate             -> Current, Conflicted, Rejected
///   Current               -> RevalidationRequired, Superseded, Retired,
///                            Conflicted
///   RevalidationRequired  -> Current, Superseded, Retired, Conflicted
///   Conflicted            -> Current, Retired, Rejected
///   Superseded            -> Retired, Tombstoned
///   Retired               -> Tombstoned
///   Tombstoned            -> (none)
///   Rejected              -> (none)
FABRIC_REGISTRY_API bool lifecycle_transition_allowed(Lifecycle from, Lifecycle to) noexcept;

/// Why a record changed. Recorded in the lineage.
enum class ReasonCode : std::uint8_t {
  Registration = 0,
  EvidenceUpdate = 1,
  AliasAttach = 2,
  AliasDetach = 3,
  Revalidation = 4,
  Supersede = 5,
  Retire = 6,
  Tombstone = 7,
  ConflictRaised = 8,
  ConflictResolved = 9,
  Promotion = 10,
  RecoveryDemotion = 11,
  PublisherFenced = 12,
  EpochAdvance = 13,
};

inline constexpr std::uint8_t kReasonCodeCount = 14;

FABRIC_REGISTRY_API std::string_view to_string(ReasonCode value) noexcept;

/// A stable metadata entry. Metadata is bounded, validated and never
/// interpreted by the registry.
struct MetadataEntry {
  std::string key;
  std::string value;

  friend bool operator==(const MetadataEntry&, const MetadataEntry&) = default;
  friend auto operator<=>(const MetadataEntry&, const MetadataEntry&) = default;
};

/// The evidence currently backing a record.
struct EvidenceState {
  /// Increments every time evidence is accepted or renewed. Independent of the
  /// record generation: renewing evidence does not change identity, and
  /// changing identity does not renew evidence.
  EvidenceGeneration generation{};
  EvidenceClass evidence_class{EvidenceClass::Unspecified};
  Provenance provenance;
  /// The coordinator epoch under which the evidence was accepted.
  CoordinatorEpoch epoch{};
  /// The publisher incarnation that supplied the evidence. Null for durable
  /// administrative evidence that is not bound to a live process.
  PublisherId publisher{};
  WorkerBootId publisher_boot{};
  /// The registry generation at which the evidence was accepted. Used to order
  /// recovery decisions deterministically.
  RegistryGeneration accepted_at{};
  /// False once the evidence has been invalidated, e.g. by publisher loss.
  bool valid{false};
};

/// One entry of a record's lineage. Bounded per record.
struct LineageEntry {
  ReasonCode reason{ReasonCode::Registration};
  RecordGeneration resulting_generation{};
  std::optional<RecordGeneration> previous_generation;
  CoordinatorEpoch epoch{};
  PublisherId publisher{};
  RegistrationId attempt{};
  std::string detail;

  friend bool operator==(const LineageEntry&, const LineageEntry&) = default;
};

/// A canonical registry record.
///
/// Records are immutable once committed: a mutation produces a new record
/// value, which replaces the previous one atomically. Consumers therefore hold
/// plain values or shared pointers to immutable records and can never observe a
/// partially updated record.
struct FABRIC_REGISTRY_API EntityRecord {
  CanonicalId id{};
  /// Always equal to id.entity_class(); stored explicitly so a corrupted or
  /// hand-built record is detectable.
  EntityClass entity_class{EntityClass::Unknown};
  Lifecycle lifecycle{Lifecycle::Discovered};

  /// Increments on every committed change to this record.
  RecordGeneration record_generation{};
  /// Value of record_generation at creation (always 1 for a created record).
  RecordGeneration creation_generation{};
  /// Increments whenever evidence is accepted or renewed.
  EvidenceGeneration evidence_generation{};

  /// Digest of the identity inputs when the id was derived; null for records
  /// created with an explicitly supplied canonical id.
  FingerprintDigest fingerprint{};
  /// Digest over the strong facts. Detects derived-id collisions and drives
  /// hardware matching.
  StableHardwareIdentity hardware_identity{};
  /// Administrative namespace the identity was derived in. Empty for explicit
  /// ids.
  std::string derivation_namespace;

  std::string friendly_name;
  std::optional<CanonicalId> parent_device;
  std::optional<FabricId> fabric;
  std::optional<SiteId> site;
  std::optional<ControlDomainId> control_domain;

  std::vector<IdentityFact> facts;
  std::vector<AliasKey> aliases;
  std::vector<MetadataEntry> metadata;

  EvidenceState evidence;

  std::optional<CanonicalId> superseded_by;
  std::optional<CanonicalId> supersedes;
  /// Set when the record is Retired/Tombstoned/Superseded/Rejected to record
  /// the administrative reason.
  std::string status_reason;

  /// Registry generation at which this record value was installed.
  RegistryGeneration last_modified{};
  PublisherId created_by{};
  WorkerBootId created_boot{};
  CoordinatorEpoch created_epoch{};

  /// True when the record has a real entity class and non-null id.
  bool is_well_formed() const noexcept;
};

/// A retained idempotency record for one completed registration attempt.
///
/// Keyed by (publisher, attempt). A replay whose request digest matches returns
/// Idempotent without producing a new generation; a replay of the same attempt
/// with different content returns ConflictingReplay.
struct IdempotencyEntry {
  PublisherId publisher{};
  /// The incarnation that produced the original result. Diagnostic only: the
  /// key deliberately survives publisher reincarnation and coordinator restart.
  WorkerBootId producer_boot{};
  RegistrationId attempt{};
  RequestDigest digest{};
  OutcomeCode code{OutcomeCode::InternalFailure};
  CanonicalId record{};
  RecordGeneration record_generation{};
  RegistryGeneration accepted_at{};
  std::string message;

  friend bool operator==(const IdempotencyEntry&, const IdempotencyEntry&) = default;
};

/// A bounded lineage history for one record.
struct RecordHistory {
  CanonicalId id{};
  std::vector<LineageEntry> entries;
  /// True when entries were dropped because the per-record bound was reached.
  bool truncated{false};
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_ENTITY_HPP
