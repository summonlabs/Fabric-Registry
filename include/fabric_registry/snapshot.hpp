// Fabric Registry — immutable read snapshots.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A snapshot is an immutable view of the complete registry at one registry
// generation. It binds the registry generation, the coordinator epoch, a
// monotonic snapshot sequence and a state digest computed over the canonical
// encoding of every record it contains. A snapshot can always be asked whether
// it is still current relative to a live registry.

#ifndef FABRIC_REGISTRY_SNAPSHOT_HPP
#define FABRIC_REGISTRY_SNAPSHOT_HPP

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "fabric_registry/entity.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/ids.hpp"

namespace fabric_registry {

class Registry;

class FABRIC_REGISTRY_API Snapshot {
public:
  using RecordPtr = std::shared_ptr<const EntityRecord>;

  Snapshot() = default;

  /// Registry generation this snapshot was taken at.
  RegistryGeneration generation() const noexcept { return generation_; }
  /// Coordinator epoch in force when the snapshot was taken.
  CoordinatorEpoch epoch() const noexcept { return epoch_; }
  /// Monotonic per-process snapshot sequence. Not part of the state digest.
  SnapshotSequence sequence() const noexcept { return sequence_; }
  /// Digest over the canonical encoding of every record in the snapshot.
  const StateDigest& digest() const noexcept { return digest_; }
  /// Number of records.
  std::size_t size() const noexcept { return records_.size(); }
  bool empty() const noexcept { return records_.empty(); }
  /// Number of unique aliases indexed in this snapshot.
  std::size_t alias_count() const noexcept { return alias_index_.size(); }

  /// Records ordered by (entity class, identifier bytes).
  const std::vector<RecordPtr>& records() const noexcept { return records_; }

  /// Binary search lookup by canonical identity.
  RecordPtr find(const CanonicalId& id) const noexcept;

  /// Lookup by a fully qualified unique alias.
  std::optional<CanonicalId> find_by_alias(const AliasKey& key) const noexcept;

  /// Records of one class, in identifier order.
  std::vector<RecordPtr> of_class(EntityClass entity_class) const;

  /// Deterministic canonical text rendering.
  std::string render() const;
  /// Deterministic canonical JSON rendering.
  std::string render_json() const;

private:
  friend class Registry;

  std::vector<RecordPtr> records_;
  std::unordered_map<AliasKey, CanonicalId> alias_index_;
  RegistryGeneration generation_{};
  CoordinatorEpoch epoch_{};
  SnapshotSequence sequence_{};
  StateDigest digest_{};
};

/// True when the snapshot's generation and epoch still match the live registry.
FABRIC_REGISTRY_API bool snapshot_is_current(const Registry& registry, const Snapshot& snapshot);

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_SNAPSHOT_HPP
