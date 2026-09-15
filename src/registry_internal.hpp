// Fabric Registry — internal state shared by the registry translation units.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// This header is not installed and is not part of the public surface. It exists
// so that the registry engine can be implemented across two translation units
// without exposing any of it to consumers.

#ifndef FABRIC_REGISTRY_SRC_REGISTRY_INTERNAL_HPP
#define FABRIC_REGISTRY_SRC_REGISTRY_INTERNAL_HPP

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "fabric_registry/registry.hpp"

namespace fabric_registry {

using RecordPtr = std::shared_ptr<const EntityRecord>;

struct IdempotencyKey {
  PublisherId publisher{};
  RegistrationId attempt{};

  friend bool operator==(const IdempotencyKey&, const IdempotencyKey&) = default;
};

struct IdempotencyKeyHash {
  std::size_t operator()(const IdempotencyKey& key) const noexcept;
};

struct IdentityFactHash {
  std::size_t operator()(const IdentityFact& fact) const noexcept;
};

struct AliasKeyHash {
  std::size_t operator()(const AliasKey& key) const noexcept;
};

/// Everything a live registry owns. All access is serialised by \`mutex\`.
class RegistryState {
public:
  RegistryState(const RegistryOptions& options_in, const RegistryLimits& limits_in);

  RegistryOptions options;
  RegistryLimits limits;

  mutable std::shared_mutex mutex;

  CoordinatorEpoch epoch{};
  RegistryGeneration generation{};
  /// Monotonic snapshot sequence. Atomic so taking a snapshot only needs the
  /// shared lock.
  std::atomic<std::uint64_t> snapshot_sequence{0};

  PublisherId local_publisher{};
  WorkerBootId local_boot{};

  /// Canonical record table.
  std::unordered_map<CanonicalId, RecordPtr> records;
  /// Secondary indexes. Every one of them must agree with \`records\` at all
  /// times; Registry::validate_state() recomputes them and compares.
  std::unordered_map<EntityClass, std::unordered_set<CanonicalId>> by_class;
  std::unordered_map<Lifecycle, std::unordered_set<CanonicalId>> by_lifecycle;
  std::unordered_map<AliasKey, CanonicalId, AliasKeyHash> alias_index;
  std::unordered_map<IdentityFact, std::vector<CanonicalId>, IdentityFactHash> fact_index;
  std::unordered_map<StableHardwareIdentity, std::vector<CanonicalId>> hardware_index;
  std::unordered_map<FabricId, std::unordered_set<CanonicalId>> by_fabric;
  std::unordered_map<SiteId, std::unordered_set<CanonicalId>> by_site;
  std::unordered_map<PublisherId, std::unordered_set<CanonicalId>> evidence_by_publisher;

  std::unordered_map<PublisherId, PublisherRecord> publishers;
  std::unordered_map<CanonicalId, RecordHistory> history;
  std::unordered_map<IdempotencyKey, IdempotencyEntry, IdempotencyKeyHash> idempotency;
  std::unordered_map<PublisherId, std::deque<RegistrationId>> idempotency_order;

  /// Monotonic counter mixed into minted identifiers so two mints inside the
  /// same clock tick still differ.
  std::uint64_t mint_counter{0};
};

/// Fills \`out\` with \`size\` bytes of entropy. Uses the configured source when
/// one was supplied, otherwise the operating system CSPRNG mixed with a
/// monotonic counter so two calls can never return the same bytes.
void fill_entropy(RegistryState& state, std::uint8_t* out, std::size_t size);

PublisherId mint_publisher_id(RegistryState& state);
WorkerBootId mint_worker_boot_id(RegistryState& state);

/// Verifies that the claim may act right now. Must be called with the mutex
/// held in at least shared mode.
Outcome check_authority(const RegistryState& state, const AuthorityClaim& claim, const RegistrationId& attempt);

/// True when the publisher identity exists and is not retired.
bool publisher_known(const RegistryState& state, const PublisherId& id);

/// Adds every index entry a record contributes. The record must not already be
/// indexed.
void index_add(RegistryState& state, const EntityRecord& record);

/// Removes every index entry a record contributes.
void index_remove(RegistryState& state, const EntityRecord& record);

/// Replaces \`previous\` (when present) with \`current\` in every index.
void index_apply(RegistryState& state, const RecordPtr* previous, const EntityRecord& current);

/// Bounded insertion into a sorted unique vector used by the fact and hardware
/// indexes.
void sorted_insert(std::vector<CanonicalId>& values, const CanonicalId& id);
void sorted_erase(std::vector<CanonicalId>& values, const CanonicalId& id);

/// What produced a committed revision. Recorded in the lineage.
struct CommitContext {
  ReasonCode reason{ReasonCode::Registration};
  RegistrationId attempt{};
  PublisherId publisher{};
  WorkerBootId boot{};
  std::string detail;
};

/// Installs a new record revision (or a new record). Advances the registry
/// generation, assigns record generations, maintains every index, appends the
/// lineage entry and stores the immutable record. Returns false when the
/// registry generation space is exhausted.
///
/// When `preserve_generation` is true the record keeps the generations it
/// already carries instead of receiving fresh ones. Recovery uses this so that a
/// caller holding a record generation from before a restart still recognizes it.
bool install_record(RegistryState& state,
                    const RecordPtr* previous,
                    EntityRecord next,
                    const CommitContext& context,
                    bool preserve_generation = false);

/// Stores a publisher record and advances the registry generation.
bool install_publisher(RegistryState& state, PublisherRecord next);

/// Appends a lineage entry, honouring the per-record bound.
void append_lineage(RegistryState& state, const CanonicalId& id, const LineageEntry& entry);

/// Records an idempotency entry and evicts the oldest entry of that publisher
/// when the per-publisher bound is reached.
void record_idempotency(RegistryState& state, const IdempotencyEntry& entry);

/// Looks an idempotency entry up.
const IdempotencyEntry* find_idempotency(const RegistryState& state, const PublisherId& publisher, const RegistrationId& attempt);

/// Moves every attached publisher to Fenced and invalidates the process-bound
/// evidence it supplied, demoting affected current records to
/// REVALIDATION_REQUIRED. Returns the number of demoted records.
std::size_t fence_all_publishers(RegistryState& state, FenceReason reason, const std::string& detail);

/// Fences one publisher and demotes the records whose current evidence came
/// from it. Returns the number of demoted records.
std::size_t fence_publisher_internal(RegistryState& state, const PublisherId& publisher, FenceReason reason, const std::string& detail);

/// Computes the canonical state digest. Must be called with the mutex held.
StateDigest compute_state_digest(const RegistryState& state);

/// Canonical encoding of one publisher record, used by the state digest and by
/// persistence.
void write_publisher(ByteWriter& writer, const PublisherRecord& publisher);
bool read_publisher(ByteReader& reader, const RegistryLimits& limits, PublisherRecord& out, std::string& error);

/// Canonical encoding of one lineage entry.
void write_lineage(ByteWriter& writer, const LineageEntry& entry);
bool read_lineage(ByteReader& reader, const RegistryLimits& limits, LineageEntry& out, std::string& error);

/// Canonical encoding of one idempotency entry.
void write_idempotency(ByteWriter& writer, const IdempotencyEntry& entry);
bool read_idempotency(ByteReader& reader, const RegistryLimits& limits, IdempotencyEntry& out, std::string& error);

/// Normalises the metadata vector: trims keys, rejects empties and duplicates,
/// sorts by key and enforces every metadata bound.
ValidationResult normalize_metadata(const std::vector<MetadataEntry>& input,
                                   const RegistryLimits& limits,
                                   std::vector<MetadataEntry>& out);

/// Builds the alias scope of a record-shaped request.
AliasScopeInput scope_input_for(const ScopeRef& scope, EntityClass entity_class);

/// Canonicalises and qualifies every requested alias. Returns the first issue
/// encountered.
AliasIssue build_alias_keys(const std::vector<AliasInput>& inputs,
                            const AliasScopeInput& scope,
                            std::size_t max_string_bytes,
                            std::vector<AliasKey>& out);

/// Human-readable rendering of a digest set, used in explanations.
std::string describe_facts(const std::vector<IdentityFact>& facts);

/// Deterministic SHA-256 over the canonical encoding of a registration request.
RequestDigest digest_registration_request(const RegisterEntityRequest& request);
RequestDigest digest_update_evidence_request(const UpdateEvidenceRequest& request);
RequestDigest digest_alias_request(const AliasMutationRequest& request);
RequestDigest digest_supersede_request(const SupersedeEntityRequest& request);
RequestDigest digest_retire_request(const RetireEntityRequest& request);
RequestDigest digest_tombstone_request(const TombstoneEntityRequest& request);
RequestDigest digest_revalidate_request(const RevalidateEntityRequest& request);
RequestDigest digest_resolve_conflict_request(const ResolveConflictRequest& request);
RequestDigest digest_reconcile_request(const ReconcileObservationRequest& request);

} // namespace fabric_registry

/// The private nested implementation type of Registry. Declared in the public
/// header, defined here so every registry translation unit sees the same
/// definition; no internal detail leaks into the installed surface.
struct fabric_registry::Registry::Impl {
  fabric_registry::RegistryState state;

  Impl(const fabric_registry::RegistryOptions& options_in, const fabric_registry::RegistryLimits& limits_in)
      : state(options_in, limits_in) {}
};

#endif // FABRIC_REGISTRY_SRC_REGISTRY_INTERNAL_HPP
