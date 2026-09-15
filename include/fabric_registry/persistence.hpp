// Fabric Registry — versioned, integrity-checked durable state.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// File layout
// -----------
//   offset 0    magic[8]            "FABRICRG"
//   offset 8    format_version u32  FABRIC_REGISTRY_STATE_FORMAT_VERSION
//   offset 12   reserved u32        must be zero
//   offset 16   payload_length u64  exact payload byte count
//   offset 24   payload             canonical encoding of DurableState
//   offset 24+L integrity[32]       SHA-256 over the payload bytes
//
// The payload itself opens with the format version again and closes with a
// StateDigest recomputed from the records it contains. Loading therefore
// validates: magic, format version, declared length against the actual file
// size, payload bounds, the SHA-256 integrity digest, every per-record
// length, every enum value, every string bound, duplicate identities, duplicate
// aliases and the recomputed state digest.
//
// Replacement is transactional. The authoritative file is never opened for
// writing. A single fixed temporary file "<target>.tmp" in the same directory is
// created exclusively, written, flushed to the device, closed, read back and
// validated, and only then does it atomically replace the target. If the process
// dies at any point before the replacement, the authoritative file still holds
// the previous complete state. One writer per state path is required; this is
// enforced by creating the temporary file with create-new semantics.

#ifndef FABRIC_REGISTRY_PERSISTENCE_HPP
#define FABRIC_REGISTRY_PERSISTENCE_HPP

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "fabric_registry/authority.hpp"
#include "fabric_registry/entity.hpp"
#include "fabric_registry/errors.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/limits.hpp"

namespace fabric_registry {
namespace persistence {

/// Magic bytes at the head of every state file.
inline constexpr char kMagic[8] = {'F', 'A', 'B', 'R', 'I', 'C', 'R', 'G'};

/// Header bytes preceding the payload.
inline constexpr std::size_t kHeaderBytes = 24;

/// Trailing integrity digest bytes.
inline constexpr std::size_t kIntegrityBytes = 32;

/// Suffix appended to the target path to form the temporary file name.
inline constexpr const char* kTemporarySuffix = ".tmp";

/// Everything a Fabric Registry persists.
struct DurableState {
  RegistryGeneration generation{};
  CoordinatorEpoch epoch{};
  std::vector<EntityRecord> records;
  std::vector<PublisherRecord> publishers;
  std::vector<RecordHistory> lineage;
  std::vector<IdempotencyEntry> idempotency;
  /// Digest recomputed from the content above. Written into the payload and
  /// verified on load.
  StateDigest digest{};

  /// Recomputes the state digest from the current content.
  StateDigest recompute_digest() const;
};

/// Encodes durable state into a complete, self-describing file image.
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_state(const DurableState& state, const RegistryLimits& limits);

/// Decodes a complete file image. Every validation listed in the file header
/// comment is applied; the first failure is reported with a specific step.
FABRIC_REGISTRY_API Outcome decode_state(std::span<const std::uint8_t> image,
                                         const RegistryLimits& limits,
                                         DurableState& out);

/// Writes `state` to `path` transactionally.
FABRIC_REGISTRY_API Outcome write_state_file(const std::filesystem::path& path,
                                             const DurableState& state,
                                             const RegistryLimits& limits,
                                             bool flush_to_disk);

/// Reads `path` and decodes it.
FABRIC_REGISTRY_API Outcome read_state_file(const std::filesystem::path& path,
                                            const RegistryLimits& limits,
                                            DurableState& out);

/// Removes a leftover temporary file for `path` when one exists. Safe to call
/// when no writer is running; used by recovery and by the CLI.
FABRIC_REGISTRY_API Outcome remove_temporary_file(const std::filesystem::path& path);

/// Path of the temporary file used for `path`.
FABRIC_REGISTRY_API std::filesystem::path temporary_path_for(const std::filesystem::path& path);

} // namespace persistence
} // namespace fabric_registry

#endif // FABRIC_REGISTRY_PERSISTENCE_HPP
