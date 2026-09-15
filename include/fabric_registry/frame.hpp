// Fabric Registry — the wire protocol.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Frame layout (all integers little-endian)
// -----------------------------------------
//   offset 0   magic[4]        'F','R','G','1'
//   offset 4   version u16     FABRIC_REGISTRY_PROTOCOL_VERSION
//   offset 6   type u16        MessageType
//   offset 8   flags u32       reserved, must be zero
//   offset 12  request_id u64  echoed in the response
//   offset 20  payload_length u32
//   offset 24  payload
//   offset 24+payload_length  checksum u64 = first 8 bytes of SHA-256 over
//                             bytes [0, 24 + payload_length)
//
// A frame declaring a payload larger than the configured maximum is rejected
// before any buffer is sized from it. Unknown message types, unknown protocol
// versions, non-zero flags, truncated frames and checksum mismatches are
// rejected with a specific status. Payload bodies are decoded with
// bounds-checked readers that reject trailing bytes: a message that is not
// exactly consumed is malformed.

#ifndef FABRIC_REGISTRY_FRAME_HPP
#define FABRIC_REGISTRY_FRAME_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/authority.hpp"
#include "fabric_registry/entity.hpp"
#include "fabric_registry/errors.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/limits.hpp"
#include "fabric_registry/record_codec.hpp"
#include "fabric_registry/registry.hpp"

namespace fabric_registry {

inline constexpr std::size_t kFrameHeaderBytes = 24;
inline constexpr std::size_t kFrameChecksumBytes = 8;
inline constexpr std::size_t kFrameOverheadBytes = kFrameHeaderBytes + kFrameChecksumBytes;

/// Message type identifiers. Values are part of the protocol and must never be
/// renumbered.
enum class MessageType : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  HelloAck = 2,
  AttachPublisher = 3,
  AttachPublisherAck = 4,
  DetachPublisher = 5,
  RegisterEntity = 6,
  UpdateEvidence = 7,
  AttachAlias = 8,
  DetachAlias = 9,
  SupersedeEntity = 10,
  RetireEntity = 11,
  TombstoneEntity = 12,
  RevalidateEntity = 13,
  ResolveConflict = 14,
  ReconcileObservation = 15,
  LookupEntity = 16,
  SnapshotRequest = 17,
  StatsRequest = 18,
  Heartbeat = 19,
  HeartbeatAck = 20,
  OperationAck = 21,
  ReconcileAck = 22,
  LookupAck = 23,
  SnapshotAck = 24,
  StatsAck = 25,
  Shutdown = 26,
  Error = 27,
};

/// Number of defined message types. Every value in [1, kMessageTypeCount] is
/// known; everything else is rejected.
inline constexpr std::uint16_t kMessageTypeCount = 27;

FABRIC_REGISTRY_API std::string_view to_string(MessageType value) noexcept;
FABRIC_REGISTRY_API bool is_known_message_type(std::uint16_t raw) noexcept;

/// Builds one complete frame. Returns an empty vector and fills `error` when
/// the payload exceeds the configured bound.
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_frame(MessageType type,
                                                          std::uint64_t request_id,
                                                          std::span<const std::uint8_t> payload,
                                                          const FrameLimits& limits,
                                                          std::string& error);

enum class FrameDecodeStatus : std::uint8_t {
  /// A complete, validated frame was produced.
  Complete = 0,
  /// The buffer does not yet hold a whole frame; read more and retry.
  NeedMoreData = 1,
  /// Magic, version, flags or type is invalid.
  Malformed = 2,
  /// The declared payload length exceeds the configured maximum.
  PayloadTooLarge = 3,
  /// The trailing checksum does not match the frame contents.
  ChecksumMismatch = 4,
  /// Structurally valid, but the message type is not known.
  UnknownMessageType = 5,
};

FABRIC_REGISTRY_API std::string_view to_string(FrameDecodeStatus value) noexcept;

struct Frame {
  MessageType type{MessageType::Invalid};
  std::uint32_t flags{0};
  std::uint64_t request_id{0};
  std::vector<std::uint8_t> payload;
};

struct FrameDecodeResult {
  FrameDecodeStatus status{FrameDecodeStatus::NeedMoreData};
  /// Bytes consumed from the front of the buffer. Zero when the status is
  /// NeedMoreData or Malformed.
  std::size_t consumed{0};
  Frame frame;
  std::string detail;
};

/// Decodes one frame from the front of `buffer`. Never reads past the end.
FABRIC_REGISTRY_API FrameDecodeResult decode_frame(std::span<const std::uint8_t> buffer, const FrameLimits& limits);

// ---------------------------------------------------------------------------
// Message payload codecs
// ---------------------------------------------------------------------------

struct HelloRequest {
  std::uint16_t protocol_version{0};
  std::string client_name;
};

struct HelloResponse {
  bool accepted{false};
  std::uint16_t protocol_version{0};
  CoordinatorEpoch coordinator_epoch{};
  RegistryGeneration registry_generation{};
  std::string server_name;
  std::string reason;
};

struct LookupRequest {
  CanonicalId target{};
};

struct SnapshotSummary {
  RegistryGeneration generation{};
  CoordinatorEpoch epoch{};
  SnapshotSequence sequence{};
  StateDigest digest{};
  std::uint64_t record_count{0};
  std::uint64_t alias_count{0};
};

struct StatsPayload {
  RegistryStats stats;
};

struct ErrorPayload {
  OutcomeCode code{OutcomeCode::InternalFailure};
  std::string message;
};

// Encoders return the payload bytes only.
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_hello_request(const HelloRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_hello_response(const HelloResponse& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_attach_request(const PublisherAttachRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_attach_response(const PublisherAttachResult& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_detach_request(const AuthorityClaim& value, FenceReason reason);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_authority(const AuthorityClaim& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_outcome(const Outcome& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_register_request(const RegisterEntityRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_update_evidence_request(const UpdateEvidenceRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_alias_request(const AliasMutationRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_supersede_request(const SupersedeEntityRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_retire_request(const RetireEntityRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_tombstone_request(const TombstoneEntityRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_revalidate_request(const RevalidateEntityRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_resolve_conflict_request(const ResolveConflictRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_reconcile_request(const ReconcileObservationRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_lookup_request(const LookupRequest& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_reconcile_detail(const ReconcileDetail& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_lookup_response(const Outcome& outcome, const std::shared_ptr<const EntityRecord>& record);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_snapshot_summary(const SnapshotSummary& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_stats(const StatsPayload& value);
FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_error(const ErrorPayload& value);

// Decoders return false when the payload is malformed and fill `error` with a
// specific reason.
FABRIC_REGISTRY_API bool decode_hello_request(std::span<const std::uint8_t> payload, HelloRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_hello_response(std::span<const std::uint8_t> payload, HelloResponse& out, std::string& error);
FABRIC_REGISTRY_API bool decode_attach_request(std::span<const std::uint8_t> payload, PublisherAttachRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_attach_response(std::span<const std::uint8_t> payload, PublisherAttachResult& out, std::string& error);
FABRIC_REGISTRY_API bool decode_detach_request(std::span<const std::uint8_t> payload, AuthorityClaim& out, FenceReason& reason, std::string& error);
FABRIC_REGISTRY_API bool decode_authority(std::span<const std::uint8_t> payload, AuthorityClaim& out, std::string& error);
FABRIC_REGISTRY_API bool decode_outcome(std::span<const std::uint8_t> payload, Outcome& out, std::string& error);
FABRIC_REGISTRY_API bool decode_register_request(std::span<const std::uint8_t> payload, RegisterEntityRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_update_evidence_request(std::span<const std::uint8_t> payload, UpdateEvidenceRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_alias_request(std::span<const std::uint8_t> payload, AliasMutationRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_supersede_request(std::span<const std::uint8_t> payload, SupersedeEntityRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_retire_request(std::span<const std::uint8_t> payload, RetireEntityRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_tombstone_request(std::span<const std::uint8_t> payload, TombstoneEntityRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_revalidate_request(std::span<const std::uint8_t> payload, RevalidateEntityRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_resolve_conflict_request(std::span<const std::uint8_t> payload, ResolveConflictRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_reconcile_request(std::span<const std::uint8_t> payload, ReconcileObservationRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_lookup_request(std::span<const std::uint8_t> payload, LookupRequest& out, std::string& error);
FABRIC_REGISTRY_API bool decode_reconcile_detail(std::span<const std::uint8_t> payload, ReconcileDetail& out, std::string& error);
FABRIC_REGISTRY_API bool decode_lookup_response(std::span<const std::uint8_t> payload, Outcome& outcome, std::shared_ptr<const EntityRecord>& record, std::string& error);
FABRIC_REGISTRY_API bool decode_snapshot_summary(std::span<const std::uint8_t> payload, SnapshotSummary& out, std::string& error);
FABRIC_REGISTRY_API bool decode_stats(std::span<const std::uint8_t> payload, StatsPayload& out, std::string& error);
FABRIC_REGISTRY_API bool decode_error(std::span<const std::uint8_t> payload, ErrorPayload& out, std::string& error);

/// Largest encoded record the protocol will carry.
FABRIC_REGISTRY_API std::size_t encoded_record_size_bound(const RegistryLimits& limits) noexcept;

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_FRAME_HPP
