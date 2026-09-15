// Fabric Registry — resource bounds.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every externally influenced resource is bounded before it is allocated. The
// values below are the defaults; RegistryLimits::validate() rejects
// configurations that are internally inconsistent or above the hard ceilings
// compiled into the library.

#ifndef FABRIC_REGISTRY_LIMITS_HPP
#define FABRIC_REGISTRY_LIMITS_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include "fabric_registry/export.hpp"
#include "fabric_registry/ids.hpp"

namespace fabric_registry {

/// Outcome of validating caller-supplied configuration.
struct ValidationResult {
  bool ok{true};
  std::string message;

  static ValidationResult success() { return ValidationResult{}; }
  static ValidationResult failure(std::string text) { return ValidationResult{false, std::move(text)}; }

  explicit operator bool() const noexcept { return ok; }
};

/// Hard ceilings compiled into the library. Configuration may lower these but
/// can never raise them; a request that would exceed one is rejected before any
/// allocation proportional to the declared size takes place.
namespace hard_limits {

inline constexpr std::size_t kMaxEntities = 4'000'000;
inline constexpr std::size_t kMaxAliasEntries = 16'000'000;
inline constexpr std::size_t kMaxFactsPerEntity = 256;
inline constexpr std::size_t kMaxAliasesPerEntity = 256;
inline constexpr std::size_t kMaxMetadataEntries = 256;
inline constexpr std::size_t kMaxStringBytes = kIdentityValueHardLimit;
inline constexpr std::size_t kMaxMetadataValueBytes = 16'384;
inline constexpr std::size_t kMaxMetadataBytesPerEntity = 65'536;
inline constexpr std::size_t kMaxRecordBytes = 262'144;
inline constexpr std::size_t kMaxBatchSize = 4'096;
inline constexpr std::size_t kMaxIdempotencyEntriesPerPublisher = 65'536;
inline constexpr std::size_t kMaxHistoryEntriesPerEntity = 1'024;
inline constexpr std::size_t kMaxFencedBootsPerPublisher = 1'024;
inline constexpr std::size_t kMaxFramePayloadBytes = 4u * 1024u * 1024u;
inline constexpr std::size_t kMaxSessions = 4'096;
inline constexpr std::size_t kMaxPendingWorkItems = 65'536;
inline constexpr std::size_t kMaxPublishers = 65'536;
inline constexpr std::size_t kMaxWorkerThreads = 64;

} // namespace hard_limits

/// Bounds enforced by one Registry instance.
struct RegistryLimits {
  /// Maximum number of entity records the registry will hold.
  std::size_t max_entities{1'000'000};
  /// Maximum number of entries in the unique alias index.
  std::size_t max_alias_entries{4'000'000};
  /// Maximum identity facts attached to one entity.
  std::size_t max_facts_per_entity{64};
  /// Maximum aliases attached to one entity.
  std::size_t max_aliases_per_entity{64};
  /// Maximum metadata entries attached to one entity.
  std::size_t max_metadata_entries{32};
  /// Maximum length in bytes of any single identity string, name, alias value
  /// or scope string.
  std::size_t max_string_bytes{1024};
  /// Maximum length in bytes of one metadata value.
  std::size_t max_metadata_value_bytes{4096};
  /// Maximum total metadata bytes attached to one entity.
  std::size_t max_metadata_bytes_per_entity{16'384};
  /// Maximum encoded size of one entity record in bytes.
  std::size_t max_record_bytes{65'536};
  /// Maximum number of requests accepted in one batch call.
  std::size_t max_batch_size{1024};
  /// Maximum retained idempotency records per publisher.
  std::size_t max_idempotency_entries_per_publisher{4096};
  /// Maximum retained lineage entries per entity.
  std::size_t max_history_entries_per_entity{64};
  /// Maximum retained fenced worker-boot ids per publisher.
  std::size_t max_fenced_boots_per_publisher{64};
  /// Maximum number of publishers the registry will hold.
  std::size_t max_publishers{4096};
  /// Maximum number of history entries returned by one lineage query.
  std::size_t max_history_query{256};
  /// Maximum number of records returned by one enumeration call.
  std::size_t max_enumeration{1'000'000};

  static RegistryLimits defaults() noexcept { return RegistryLimits{}; }

  /// Returns a failure result describing the first problem found. The message
  /// names the exact field so an operator can fix it without guessing.
  ValidationResult validate() const;
};

/// Bounds enforced by the framed transport.
struct FrameLimits {
  /// Maximum payload bytes in one frame. Frames declaring more are rejected
  /// before a buffer is allocated.
  std::size_t max_payload_bytes{1024 * 1024};
  /// Maximum number of frames a single connection may have in flight in the
  /// coordinator's bounded work queue.
  std::size_t max_pending_frames{64};
  /// Maximum number of simultaneous sessions.
  std::size_t max_sessions{256};
  /// Number of worker threads the coordinator runs for request handling.
  std::size_t worker_threads{4};

  static FrameLimits defaults() noexcept { return FrameLimits{}; }

  ValidationResult validate() const;
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_LIMITS_HPP
