// Fabric Registry — the registry runtime.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Thread safety
// -------------
// One Registry instance may be shared by any number of threads. Reads
// (lookup, snapshot, enumeration, statistics) take a shared lock; mutations
// take an exclusive lock. Records are immutable once committed and are held by
// std::shared_ptr, so a value returned by a read stays valid and unchanged
// forever, independently of later mutations. The library never invokes a
// caller-supplied callback while holding its lock, and never returns a
// reference into guarded state. There is exactly one authoritative commit per
// expected generation transition: the compare-and-commit check and the commit
// happen inside the same exclusive critical section.
//
// Ownership and lifetime
// ----------------------
// Registry is neither copyable nor movable. A Registry is the sole owner of its
// mutable state; the objects it hands out (Snapshot, shared_ptr<const
// EntityRecord>, PublisherRecord copies) are independent values whose lifetime
// is not tied to the Registry.

#ifndef FABRIC_REGISTRY_REGISTRY_HPP
#define FABRIC_REGISTRY_REGISTRY_HPP

#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fabric_registry/authority.hpp"
#include "fabric_registry/entity.hpp"
#include "fabric_registry/errors.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/ids.hpp"
#include "fabric_registry/limits.hpp"
#include "fabric_registry/snapshot.hpp"

namespace fabric_registry {

/// How a registration is admitted.
enum class AdmissionMode : std::uint8_t {
  /// The evidence must be authoritative. The record becomes Current.
  RequireCurrent = 0,
  /// The evidence is an observation by a non-authoritative source. A new record
  /// becomes Discovered; an existing record is left untouched.
  AllowObservation = 1,
  /// The registration carries authority but the evidence is not yet strong
  /// enough. A new record becomes Candidate.
  AllowCandidate = 2,
};

FABRIC_REGISTRY_API std::string_view to_string(AdmissionMode value) noexcept;

/// How an observation that did not match exactly is resolved.
enum class ReconcileResolution : std::uint8_t {
  /// Decide from evidence alone. Probable, ambiguous and conflicting outcomes
  /// are returned without committing anything.
  Auto = 0,
  /// Create a new record even though a probable match exists. The new record
  /// carries the conflicting evidence explicitly.
  ForceNew = 1,
  /// Attach the observation to a named existing record. The caller takes
  /// responsibility; the registry still enforces alias and fact conflicts.
  ForceExisting = 2,
};

FABRIC_REGISTRY_API std::string_view to_string(ReconcileResolution value) noexcept;

/// Administrative placement of a record.
struct ScopeRef {
  std::optional<FabricId> fabric;
  std::optional<SiteId> site;
  std::optional<ControlDomainId> control_domain;
  std::optional<CanonicalId> parent_device;
};

/// Create or update a canonical entity.
struct RegisterEntityRequest {
  /// Idempotency key for this attempt. Must be non-null and unique per attempt.
  RegistrationId attempt{};
  AuthorityClaim authority{};

  EntityClass entity_class{EntityClass::Unknown};

  /// Explicit canonical identifier. When absent the identifier is derived from
  /// (derivation_namespace, entity_class, strong facts).
  std::optional<CanonicalId> canonical_id;
  /// Administrative namespace used for derivation. Must be non-empty when
  /// canonical_id is absent and must not be supplied when it is present.
  std::string derivation_namespace;

  std::string friendly_name;
  std::vector<IdentityFact> facts;
  std::vector<AliasInput> aliases;
  std::vector<MetadataEntry> metadata;
  ScopeRef scope;

  Provenance provenance;
  EvidenceClass evidence_class{EvidenceClass::Unspecified};
  AdmissionMode admission{AdmissionMode::RequireCurrent};

  /// When set, the mutation is applied only if the addressed record is exactly
  /// at this generation.
  std::optional<RecordGeneration> expected_generation;

  /// How a non-exact match is resolved.
  ReconcileResolution resolution{ReconcileResolution::Auto};
  /// Target of ForceExisting. Required for that resolution, rejected otherwise.
  std::optional<CanonicalId> resolve_to;
  /// When true, a conflicting observation freezes the record as Conflicted
  /// instead of being rejected.
  bool record_conflict{false};
};

/// Replace or extend the evidence of an existing record.
struct UpdateEvidenceRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  std::vector<IdentityFact> facts;
  Provenance provenance;
  EvidenceClass evidence_class{EvidenceClass::Unspecified};
  /// When true the supplied facts extend the record; when false they replace it.
  bool merge_facts{false};
};

/// Attach or detach one alias on an existing record.
struct AliasMutationRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  AliasInput alias;
};

/// Supersede a record with a successor identity.
struct SupersedeEntityRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  /// The successor record. When absent the target is superseded without a
  /// named successor.
  std::optional<CanonicalId> successor;
  std::string reason;
};

/// Retire a record.
struct RetireEntityRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  std::string reason;
};

/// Tombstone a record. The identity is closed permanently.
struct TombstoneEntityRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  std::string reason;
};

/// Re-establish current authority for a record whose evidence lapsed.
struct RevalidateEntityRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  std::vector<IdentityFact> facts;
  Provenance provenance;
  EvidenceClass evidence_class{EvidenceClass::Unspecified};
  bool merge_facts{false};
};

/// How a conflict is resolved.
enum class ConflictResolution : std::uint8_t {
  /// The current claimant keeps authority and the record returns to Current.
  KeepCurrent = 0,
  /// The record is retired.
  Retire = 1,
  /// The record is rejected.
  Reject = 2,
};

FABRIC_REGISTRY_API std::string_view to_string(ConflictResolution value) noexcept;

struct ResolveConflictRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  CanonicalId target{};
  std::optional<RecordGeneration> expected_generation;
  ConflictResolution resolution{ConflictResolution::KeepCurrent};
  std::string reason;
};

/// Reconcile one observation against the registry without necessarily
/// committing anything.
struct ReconcileObservationRequest {
  RegistrationId attempt{};
  AuthorityClaim authority{};
  EntityClass entity_class{EntityClass::Unknown};
  std::vector<IdentityFact> facts;
  std::vector<AliasInput> aliases;
  ScopeRef scope;
  Provenance provenance;
  ReconcileResolution resolution{ReconcileResolution::Auto};
  std::optional<CanonicalId> resolve_to;
};

/// The detailed result of a reconciliation.
struct ReconcileDetail {
  MatchClass match{MatchClass::NoMatch};
  std::optional<CanonicalId> matched;
  /// Every record that matched at the decided strength, in identity order.
  std::vector<CanonicalId> candidates;
  /// Facts that contradicted an existing record, in canonical order.
  std::vector<IdentityFact> conflicting_facts;
  /// Aliases that point at a different record, in canonical order.
  std::vector<AliasKey> conflicting_aliases;
  /// Recomputed digest of the observation, so two runs can be compared.
  FingerprintDigest observation_fingerprint{};
};

struct ReconcileResult {
  Outcome outcome;
  ReconcileDetail detail;
};

/// What loading a persisted state did.
struct FABRIC_REGISTRY_API RecoveryReport {
  std::uint32_t format_version{0};
  RegistryGeneration stored_generation{};
  CoordinatorEpoch stored_epoch{};
  CoordinatorEpoch new_epoch{};
  std::size_t records_loaded{0};
  std::size_t records_restored_current{0};
  std::size_t records_demoted{0};
  std::size_t aliases_loaded{0};
  std::size_t publishers_loaded{0};
  std::size_t publishers_fenced{0};
  std::size_t lineage_entries_loaded{0};
  StateDigest stored_digest{};
  StateDigest recomputed_digest{};
  std::string detail;

  std::string render() const;
};

/// Aggregate counters describing a registry.
struct RegistryStats {
  std::size_t entities{0};
  std::size_t current_entities{0};
  std::size_t discovered_entities{0};
  std::size_t candidate_entities{0};
  std::size_t revalidation_required_entities{0};
  std::size_t superseded_entities{0};
  std::size_t retired_entities{0};
  std::size_t tombstoned_entities{0};
  std::size_t conflicted_entities{0};
  std::size_t rejected_entities{0};
  std::size_t aliases{0};
  std::size_t indexed_aliases{0};
  std::size_t publishers{0};
  std::size_t active_publishers{0};
  std::size_t lineage_entries{0};
  std::size_t idempotency_records{0};
  RegistryGeneration generation{};
  CoordinatorEpoch epoch{};
};

/// Construction options.
struct RegistryOptions {
  RegistryLimits limits{};
  /// Coordinator epoch the registry starts at. Must not be zero.
  CoordinatorEpoch initial_epoch{CoordinatorEpoch::first()};
  /// Entropy source used to mint publisher identities and worker incarnations.
  /// Defaults to the operating system CSPRNG. Tests inject a deterministic
  /// source; production code must leave it empty.
  std::function<void(std::uint8_t*, std::size_t)> entropy_source;
  /// Whether to create the embedded local publisher at construction.
  bool create_local_publisher{true};
  /// Name of the embedded local publisher.
  std::string local_publisher_name{"registry-local"};

  ValidationResult validate() const;
};

class FABRIC_REGISTRY_API Registry {
public:
  /// Constructs a registry.
  ///
  /// Throws std::invalid_argument when the options are not valid; callers that
  /// must not see an exception can check RegistryOptions::validate() first.
  /// Every other operation reports failure through its Outcome and never
  /// throws.
  explicit Registry(RegistryOptions options = RegistryOptions{});
  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;
  ~Registry();

  const RegistryLimits& limits() const noexcept;

  // ----- coordinator epoch and publishers -----

  CoordinatorEpoch epoch() const noexcept;

  /// Advances the coordinator epoch by one, fences every attached publisher,
  /// invalidates process-bound evidence and moves affected records to
  /// REVALIDATION_REQUIRED. Durable administrative evidence is preserved.
  /// `demoted` receives the number of records moved to REVALIDATION_REQUIRED.
  Outcome advance_epoch(std::size_t& demoted);

  /// Binds a fresh worker incarnation to a publisher. Any previous incarnation
  /// is fenced first. A null request.publisher mints a new publisher identity.
  PublisherAttachResult attach_publisher(const PublisherAttachRequest& request);

  /// Fences the claiming incarnation and records an explicit detach.
  Outcome detach_publisher(const AuthorityClaim& claim, FenceReason reason);

  /// Fences a publisher unconditionally. `demoted` receives the number of
  /// records moved to REVALIDATION_REQUIRED.
  Outcome fence_publisher(const PublisherId& publisher, FenceReason reason, std::size_t& demoted);

  /// Authority claim of the embedded local publisher.
  AuthorityClaim local_authority() const noexcept;

  std::optional<PublisherRecord> publisher(const PublisherId& id) const;
  std::vector<PublisherRecord> publishers() const;
  AuthorityStats authority_stats() const;

  // ----- mutations -----

  Outcome register_entity(const RegisterEntityRequest& request);
  Outcome update_evidence(const UpdateEvidenceRequest& request);
  Outcome attach_alias(const AliasMutationRequest& request);
  Outcome detach_alias(const AliasMutationRequest& request);
  Outcome supersede_entity(const SupersedeEntityRequest& request);
  Outcome retire_entity(const RetireEntityRequest& request);
  Outcome tombstone_entity(const TombstoneEntityRequest& request);
  Outcome revalidate_entity(const RevalidateEntityRequest& request);
  Outcome resolve_conflict(const ResolveConflictRequest& request);
  ReconcileResult reconcile_observation(const ReconcileObservationRequest& request);

  // ----- queries -----

  /// Looks a record up by canonical identity.
  Outcome lookup(const CanonicalId& id, std::shared_ptr<const EntityRecord>& out) const;
  /// Looks a record up by fully qualified unique alias.
  Outcome lookup_by_alias(const AliasKey& key, std::shared_ptr<const EntityRecord>& out) const;
  /// Looks records up by one identity fact (kind, scope, value).
  Outcome lookup_by_fact(const IdentityFact& fact, std::vector<CanonicalId>& out) const;
  /// Looks records up by stable hardware identity digest.
  Outcome lookup_by_hardware_identity(const StableHardwareIdentity& identity, std::vector<CanonicalId>& out) const;

  std::vector<CanonicalId> entities_of_class(EntityClass entity_class, std::size_t limit) const;
  std::vector<CanonicalId> entities_of_lifecycle(Lifecycle lifecycle, std::size_t limit) const;
  std::vector<CanonicalId> all_ids(std::size_t limit) const;

  Outcome history(const CanonicalId& id, RecordHistory& out) const;

  /// Decides whether a record reference is still current. Returns Committed
  /// with the current generation when it is, NotCurrent when the record exists
  /// at another generation or no longer holds current authority, and NotFound
  /// when it does not exist.
  Outcome validate_reference(const CanonicalId& id, std::optional<RecordGeneration> expected_generation) const;

  /// True when the record exists, is Current, and (when supplied) is at the
  /// expected generation.
  bool is_current(const CanonicalId& id, std::optional<RecordGeneration> expected_generation = std::nullopt) const;

  // ----- snapshots -----

  Snapshot snapshot() const;

  /// True when the snapshot still matches the live registry generation and
  /// coordinator epoch. Both are compared under one lock acquisition, so the
  /// answer is never a blend of two different states.
  bool snapshot_current(const Snapshot& snapshot) const;

  // ----- persistence -----

  /// Writes the durable state atomically. The authoritative file is never
  /// written in place: a temporary file in the same directory is written,
  /// flushed, read back and validated, and only then does it replace the
  /// authoritative file.
  Outcome save(const std::filesystem::path& path, bool flush_to_disk = true) const;

  /// Loads durable state into an empty registry. The coordinator epoch is
  /// advanced, publishers are not restored as live, and process-bound evidence
  /// is not restored as current.
  Outcome load(const std::filesystem::path& path, RecoveryReport& report);

  // ----- diagnostics -----

  RegistryStats stats() const;

  /// Recomputes every index and verifies that it agrees with the record table
  /// and with every record's internal invariants. `report` receives a
  /// deterministic description; the outcome is Committed when the state is
  /// consistent.
  Outcome validate_state(std::string& report) const;

  /// Deterministic digest over the canonical encoding of every record, the
  /// coordinator epoch and the publisher table.
  StateDigest state_digest() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_REGISTRY_HPP
