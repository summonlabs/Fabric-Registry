// Fabric Registry - the wire protocol.
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
// A frame is validated from the front of the buffer outwards: the fixed header,
// then the declared payload length against both the configured bound and the
// bytes actually available, then the trailing checksum. Nothing is read past the
// end of the buffer and no buffer is sized from a length that has not already
// been validated against the bytes on hand.
//
// Payload bodies are written with ByteWriter and read with ByteReader. Every
// string carries a 32-bit length and is bounded before it is read, every
// sequence carries a 32-bit count and is bounded before it is reserved, and
// every enum value is validated against its defined range. A decoder rejects a
// message that is not exactly consumed: trailing bytes are malformed.

#include "fabric_registry/frame.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fabric_registry/codec.hpp"
#include "fabric_registry/digest.hpp"
#include "fabric_registry/version.hpp"

namespace fabric_registry {
namespace {

constexpr std::array<std::uint8_t, 4> kFrameMagic{'F', 'R', 'G', '1'};
constexpr std::uint16_t kWireProtocolVersion = static_cast<std::uint16_t>(FABRIC_REGISTRY_PROTOCOL_VERSION);

/// Largest payload length the 32-bit header field can express.
constexpr std::size_t kMaxPayloadLength = 0xFFFFFFFFull;

/// Hard ceiling on any identity string carried by a payload. Record payloads
/// are encoded by the record codec, which applies its own configured bounds.
constexpr std::size_t kTextBound = kIdentityValueHardLimit;

/// Hard ceiling on one record carried inside a payload. A payload decoder has no
/// registry configuration to consult, so the compiled-in ceiling applies.
constexpr std::size_t kMaxRecordPayloadBytes = hard_limits::kMaxRecordBytes + 64u;

// Sequence bounds. A declared count is validated against one of these before
// anything is reserved for it.
constexpr std::uint32_t kMaxFactCount = static_cast<std::uint32_t>(hard_limits::kMaxFactsPerEntity);
constexpr std::uint32_t kMaxAliasCount = static_cast<std::uint32_t>(hard_limits::kMaxAliasesPerEntity);
constexpr std::uint32_t kMaxMetadataCount = static_cast<std::uint32_t>(hard_limits::kMaxMetadataEntries);
constexpr std::uint32_t kMaxStepCount = static_cast<std::uint32_t>(hard_limits::kMaxBatchSize);
constexpr std::uint32_t kMaxRelatedCount = static_cast<std::uint32_t>(hard_limits::kMaxBatchSize);

// Enum ranges. A value outside its range is rejected, never coerced.
constexpr std::uint8_t kMaxEntityClass = kEntityClassCount;
constexpr std::uint8_t kMaxOutcomeCode = static_cast<std::uint8_t>(kOutcomeCodeCount - 1u);
constexpr std::uint8_t kMaxMatchClass = static_cast<std::uint8_t>(MatchClass::Ambiguous);
constexpr std::uint8_t kMaxIdentityFactKind = kIdentityFactKindCount;
constexpr std::uint8_t kMaxAliasNamespace = kAliasNamespaceCount;
constexpr std::uint8_t kMaxObservationSource = kObservationSourceCount;
constexpr std::uint8_t kMaxProvenanceClass = static_cast<std::uint8_t>(ProvenanceClass::Unsupported);
constexpr std::uint8_t kMaxEvidenceClass = static_cast<std::uint8_t>(EvidenceClass::DurableAuthority);
constexpr std::uint8_t kMaxAdmissionMode = static_cast<std::uint8_t>(AdmissionMode::AllowCandidate);
constexpr std::uint8_t kMaxReconcileResolution = static_cast<std::uint8_t>(ReconcileResolution::ForceExisting);
constexpr std::uint8_t kMaxConflictResolution = static_cast<std::uint8_t>(ConflictResolution::Reject);
constexpr std::uint8_t kMaxFenceReason = static_cast<std::uint8_t>(FenceReason::Administrative);

// ---------------------------------------------------------------------------
// Shared decode helpers
// ---------------------------------------------------------------------------

/// "<stage> <reason>" - the exact field that failed and why.
std::string stage_error(std::string_view stage, std::string_view reason) {
  std::string message;
  message.reserve(stage.size() + reason.size() + 1u);
  message.append(stage);
  message.push_back(' ');
  message.append(reason);
  return message;
}

/// Renders the four magic bytes for a diagnostic. Bytes that are not printable
/// ASCII are shown as '.' so the detail is always readable.
std::string render_magic(const std::array<std::uint8_t, 4>& magic) {
  std::string text;
  text.reserve(magic.size());
  for (std::uint8_t byte : magic) {
    const bool printable = byte >= 0x20u && byte < 0x7Fu;
    text.push_back(printable ? static_cast<char>(byte) : '.');
  }
  return text;
}

/// The first eight bytes of a digest as the little-endian integer the frame
/// trailer carries.
std::uint64_t load_le64(const std::uint8_t* data) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < kFrameChecksumBytes; ++index) {
    value |= static_cast<std::uint64_t>(data[index]) << (8u * static_cast<unsigned>(index));
  }
  return value;
}

/// Frame checksum: the first 8 bytes of SHA-256 over the frame prefix.
std::uint64_t frame_checksum(std::span<const std::uint8_t> bytes) noexcept {
  const DigestBytes digest = Sha256::hash(bytes.data(), bytes.size());
  return load_le64(digest.data());
}

bool take_u16(ByteReader& reader, std::uint16_t& out, std::string_view stage, std::string& error) {
  if (!reader.u16(out)) {
    error = stage_error(stage, "is truncated");
    return false;
  }
  return true;
}

bool take_u64(ByteReader& reader, std::uint64_t& out, std::string_view stage, std::string& error) {
  if (!reader.u64(out)) {
    error = stage_error(stage, "is truncated");
    return false;
  }
  return true;
}

bool take_raw(ByteReader& reader, std::uint8_t* out, std::size_t size, std::string_view stage, std::string& error) {
  if (!reader.raw(out, size)) {
    error = stage_error(stage, "is truncated");
    return false;
  }
  return true;
}

bool take_text(ByteReader& reader, std::string& out, std::string_view stage, std::string& error) {
  if (!reader.text(out, kTextBound)) {
    error = stage_error(stage, "is out of bounds");
    return false;
  }
  return true;
}

/// Reads a 0/1 marker. Anything else is malformed, never coerced to true.
bool take_presence(ByteReader& reader, bool& present, std::string_view stage, std::string& error) {
  std::uint8_t raw = 0;
  if (!reader.u8(raw)) {
    error = stage_error(stage, "presence marker is truncated");
    return false;
  }
  if (raw > 1u) {
    error = stage_error(stage, "presence marker is not 0 or 1");
    return false;
  }
  present = raw != 0;
  return true;
}

bool take_bool(ByteReader& reader, bool& out, std::string_view stage, std::string& error) {
  std::uint8_t raw = 0;
  if (!reader.u8(raw)) {
    error = stage_error(stage, "is truncated");
    return false;
  }
  if (raw > 1u) {
    error = stage_error(stage, "is not a boolean");
    return false;
  }
  out = raw != 0;
  return true;
}

/// Reads one enum byte and rejects any value above max_value.
bool take_enum(ByteReader& reader, std::uint8_t& out, std::uint8_t max_value, std::string_view stage, std::string& error) {
  std::uint8_t raw = 0;
  if (!reader.u8(raw)) {
    error = stage_error(stage, "is truncated");
    return false;
  }
  if (raw > max_value) {
    error = stage_error(stage, "is not a defined value");
    return false;
  }
  out = raw;
  return true;
}

/// Reads a sequence count and validates it before anything is reserved for it.
bool take_count(ByteReader& reader, std::uint32_t& count, std::uint32_t bound, std::string_view stage, std::string& error) {
  std::uint32_t declared = 0;
  if (!reader.u32(declared)) {
    error = stage_error(stage, "count is truncated");
    return false;
  }
  if (declared > bound) {
    error = stage_error(stage, "count exceeds the configured bound");
    return false;
  }
  count = declared;
  return true;
}

template <class Element, class ReadElement>
bool take_sequence(ByteReader& reader,
                   std::vector<Element>& out,
                   std::uint32_t bound,
                   std::string_view stage,
                   std::string& error,
                   ReadElement read_element) {
  std::uint32_t count = 0;
  if (!take_count(reader, count, bound, stage, error)) {
    return false;
  }
  std::vector<Element> elements;
  elements.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    Element element;
    if (!read_element(reader, element, error)) {
      if (error.empty()) {
        error = stage_error(stage, "element is malformed");
      }
      return false;
    }
    elements.push_back(std::move(element));
  }
  out = std::move(elements);
  return true;
}

template <class Element, class WriteElement>
void write_sequence(ByteWriter& writer, const std::vector<Element>& elements, WriteElement write_element) {
  writer.u32(static_cast<std::uint32_t>(elements.size()));
  for (const Element& element : elements) {
    write_element(writer, element);
  }
}

/// Consumes the decoder tail: trailing bytes mean the message was not exactly
/// consumed, which is malformed.
template <class Value>
bool finish_payload(ByteReader& reader, Value& value, Value& out, std::string& error, std::string_view stage) {
  if (!reader.at_end()) {
    error = stage_error(stage, "payload has trailing bytes");
    return false;
  }
  out = std::move(value);
  return true;
}

/// The most permissive record bounds a payload can carry. A payload decoder has
/// no registry configuration, so a record is validated against the compiled-in
/// ceilings; a record the registry itself could have produced always fits.
RegistryLimits wire_record_limits() {
  RegistryLimits limits;
  limits.max_facts_per_entity = hard_limits::kMaxFactsPerEntity;
  limits.max_aliases_per_entity = hard_limits::kMaxAliasesPerEntity;
  limits.max_metadata_entries = hard_limits::kMaxMetadataEntries;
  limits.max_string_bytes = hard_limits::kMaxStringBytes;
  limits.max_metadata_value_bytes = hard_limits::kMaxMetadataValueBytes;
  limits.max_metadata_bytes_per_entity = hard_limits::kMaxMetadataBytesPerEntity;
  limits.max_record_bytes = hard_limits::kMaxRecordBytes;
  return limits;
}

// ---------------------------------------------------------------------------
// Repeated payload shapes
// ---------------------------------------------------------------------------

void write_bool(ByteWriter& writer, bool value) {
  writer.u8(static_cast<std::uint8_t>(value ? 1 : 0));
}

template <class IdType>
void write_typed_id(ByteWriter& writer, const IdType& value) {
  writer.raw(value.bytes().data(), kOpaqueIdBytes);
}

template <class IdType>
bool take_typed_id(ByteReader& reader, IdType& out, std::string_view stage, std::string& error) {
  IdBytes bytes{};
  if (!take_raw(reader, bytes.data(), bytes.size(), stage, error)) {
    return false;
  }
  out = IdType::from_bytes(bytes);
  return true;
}

template <class IdType>
void write_optional_typed_id(ByteWriter& writer, const std::optional<IdType>& value) {
  if (!value.has_value()) {
    writer.u8(0);
    return;
  }
  writer.u8(1);
  write_typed_id(writer, *value);
}

template <class IdType>
bool take_optional_typed_id(ByteReader& reader, std::optional<IdType>& out, std::string_view stage, std::string& error) {
  bool present = false;
  if (!take_presence(reader, present, stage, error)) {
    return false;
  }
  if (!present) {
    out.reset();
    return true;
  }
  IdType value{};
  if (!take_typed_id(reader, value, stage, error)) {
    return false;
  }
  if (value.is_null()) {
    error = stage_error(stage, "is a null identity");
    return false;
  }
  out = value;
  return true;
}

template <class CounterType>
void write_counter(ByteWriter& writer, CounterType value) {
  writer.u64(value.value());
}

template <class CounterType>
bool take_counter(ByteReader& reader, CounterType& out, std::string_view stage, std::string& error) {
  std::uint64_t raw = 0;
  if (!take_u64(reader, raw, stage, error)) {
    return false;
  }
  out = CounterType(raw);
  return true;
}

template <class CounterType>
void write_optional_counter(ByteWriter& writer, const std::optional<CounterType>& value) {
  if (!value.has_value()) {
    writer.u8(0);
    return;
  }
  writer.u8(1);
  write_counter(writer, *value);
}

template <class CounterType>
bool take_optional_counter(ByteReader& reader, std::optional<CounterType>& out, std::string_view stage, std::string& error) {
  bool present = false;
  if (!take_presence(reader, present, stage, error)) {
    return false;
  }
  if (!present) {
    out.reset();
    return true;
  }
  CounterType value;
  if (!take_counter(reader, value, stage, error)) {
    return false;
  }
  out = value;
  return true;
}

template <class DigestType>
void write_digest(ByteWriter& writer, const DigestType& value) {
  writer.raw(value.data(), kDigestBytes);
}

template <class DigestType>
bool take_digest(ByteReader& reader, DigestType& out, std::string_view stage, std::string& error) {
  DigestBytes bytes{};
  if (!take_raw(reader, bytes.data(), bytes.size(), stage, error)) {
    return false;
  }
  out = DigestType::from_bytes(bytes);
  return true;
}

template <class DigestType>
void write_optional_digest(ByteWriter& writer, const std::optional<DigestType>& value) {
  if (!value.has_value()) {
    writer.u8(0);
    return;
  }
  writer.u8(1);
  write_digest(writer, *value);
}

template <class DigestType>
bool take_optional_digest(ByteReader& reader, std::optional<DigestType>& out, std::string_view stage, std::string& error) {
  bool present = false;
  if (!take_presence(reader, present, stage, error)) {
    return false;
  }
  if (!present) {
    out.reset();
    return true;
  }
  DigestType value;
  if (!take_digest(reader, value, stage, error)) {
    return false;
  }
  out = value;
  return true;
}

void write_canonical_id(ByteWriter& writer, const CanonicalId& value) {
  writer.u8(static_cast<std::uint8_t>(value.entity_class()));
  writer.raw(value.bytes().data(), kOpaqueIdBytes);
}

/// A canonical identity is required wherever it appears: a null id or an
/// unknown class is rejected rather than accepted as "no identity".
bool take_canonical_id(ByteReader& reader, CanonicalId& out, std::string_view stage, std::string& error) {
  std::uint8_t raw_class = 0;
  if (!reader.u8(raw_class)) {
    error = stage_error(stage, "entity class is truncated");
    return false;
  }
  const EntityClass entity_class = static_cast<EntityClass>(raw_class);
  if (!is_valid_entity_class(entity_class)) {
    error = stage_error(stage, "entity class is not a real class");
    return false;
  }
  IdBytes bytes{};
  if (!take_raw(reader, bytes.data(), bytes.size(), stage, error)) {
    return false;
  }
  const CanonicalId value(entity_class, bytes);
  if (value.is_null()) {
    error = stage_error(stage, "is a null canonical identity");
    return false;
  }
  out = value;
  return true;
}

void write_optional_canonical_id(ByteWriter& writer, const std::optional<CanonicalId>& value) {
  if (!value.has_value()) {
    writer.u8(0);
    return;
  }
  writer.u8(1);
  write_canonical_id(writer, *value);
}

bool take_optional_canonical_id(ByteReader& reader, std::optional<CanonicalId>& out, std::string_view stage, std::string& error) {
  bool present = false;
  if (!take_presence(reader, present, stage, error)) {
    return false;
  }
  if (!present) {
    out.reset();
    return true;
  }
  CanonicalId value;
  if (!take_canonical_id(reader, value, stage, error)) {
    return false;
  }
  out = value;
  return true;
}

void write_optional_match(ByteWriter& writer, const std::optional<MatchClass>& value) {
  if (!value.has_value()) {
    writer.u8(0);
    return;
  }
  writer.u8(1);
  writer.u8(static_cast<std::uint8_t>(*value));
}

bool take_optional_match(ByteReader& reader, std::optional<MatchClass>& out, std::string_view stage, std::string& error) {
  bool present = false;
  if (!take_presence(reader, present, stage, error)) {
    return false;
  }
  if (!present) {
    out.reset();
    return true;
  }
  std::uint8_t raw = 0;
  if (!take_enum(reader, raw, kMaxMatchClass, stage, error)) {
    return false;
  }
  out = static_cast<MatchClass>(raw);
  return true;
}

void write_identity_fact(ByteWriter& writer, const IdentityFact& fact) {
  writer.u8(static_cast<std::uint8_t>(fact.kind));
  writer.text(fact.scope);
  writer.text(fact.value);
}

bool take_identity_fact(ByteReader& reader, IdentityFact& out, std::string_view stage, std::string& error) {
  std::uint8_t raw_kind = 0;
  if (!take_enum(reader, raw_kind, kMaxIdentityFactKind, stage, error)) {
    return false;
  }
  IdentityFact fact;
  fact.kind = static_cast<IdentityFactKind>(raw_kind);
  if (!take_text(reader, fact.scope, stage, error) || !take_text(reader, fact.value, stage, error)) {
    return false;
  }
  out = std::move(fact);
  return true;
}

void write_alias_input(ByteWriter& writer, const AliasInput& alias) {
  writer.u8(static_cast<std::uint8_t>(alias.alias_namespace));
  writer.text(alias.value);
}

bool take_alias_input(ByteReader& reader, AliasInput& out, std::string_view stage, std::string& error) {
  std::uint8_t raw_namespace = 0;
  if (!take_enum(reader, raw_namespace, kMaxAliasNamespace, stage, error)) {
    return false;
  }
  AliasInput alias;
  alias.alias_namespace = static_cast<AliasNamespace>(raw_namespace);
  if (!take_text(reader, alias.value, stage, error)) {
    return false;
  }
  out = std::move(alias);
  return true;
}

void write_alias_key(ByteWriter& writer, const AliasKey& key) {
  writer.u8(static_cast<std::uint8_t>(key.alias_namespace));
  writer.text(key.scope);
  writer.text(key.value);
}

bool take_alias_key(ByteReader& reader, AliasKey& out, std::string_view stage, std::string& error) {
  std::uint8_t raw_namespace = 0;
  if (!take_enum(reader, raw_namespace, kMaxAliasNamespace, stage, error)) {
    return false;
  }
  AliasKey key;
  key.alias_namespace = static_cast<AliasNamespace>(raw_namespace);
  if (!take_text(reader, key.scope, stage, error) || !take_text(reader, key.value, stage, error)) {
    return false;
  }
  out = std::move(key);
  return true;
}

void write_metadata_entry(ByteWriter& writer, const MetadataEntry& entry) {
  writer.text(entry.key);
  writer.text(entry.value);
}

bool take_metadata_entry(ByteReader& reader, MetadataEntry& out, std::string_view stage, std::string& error) {
  MetadataEntry entry;
  if (!take_text(reader, entry.key, stage, error) || !take_text(reader, entry.value, stage, error)) {
    return false;
  }
  out = std::move(entry);
  return true;
}

void write_scope_ref(ByteWriter& writer, const ScopeRef& scope) {
  write_optional_typed_id(writer, scope.fabric);
  write_optional_typed_id(writer, scope.site);
  write_optional_typed_id(writer, scope.control_domain);
  write_optional_canonical_id(writer, scope.parent_device);
}

bool take_scope_ref(ByteReader& reader, ScopeRef& out, std::string_view stage, std::string& error) {
  ScopeRef scope;
  if (!take_optional_typed_id(reader, scope.fabric, stage, error) ||
      !take_optional_typed_id(reader, scope.site, stage, error) ||
      !take_optional_typed_id(reader, scope.control_domain, stage, error) ||
      !take_optional_canonical_id(reader, scope.parent_device, stage, error)) {
    return false;
  }
  out = std::move(scope);
  return true;
}

void write_provenance(ByteWriter& writer, const Provenance& provenance) {
  writer.u8(static_cast<std::uint8_t>(provenance.source));
  writer.u8(static_cast<std::uint8_t>(provenance.validity_class));
  writer.text(provenance.mechanism);
  writer.text(provenance.source_identity);
}

bool take_provenance(ByteReader& reader, Provenance& out, std::string_view stage, std::string& error) {
  std::uint8_t raw_source = 0;
  std::uint8_t raw_class = 0;
  if (!take_enum(reader, raw_source, kMaxObservationSource, stage, error) ||
      !take_enum(reader, raw_class, kMaxProvenanceClass, stage, error)) {
    return false;
  }
  Provenance provenance;
  provenance.source = static_cast<ObservationSource>(raw_source);
  provenance.validity_class = static_cast<ProvenanceClass>(raw_class);
  if (!take_text(reader, provenance.mechanism, stage, error) ||
      !take_text(reader, provenance.source_identity, stage, error)) {
    return false;
  }
  out = std::move(provenance);
  return true;
}

void write_authority(ByteWriter& writer, const AuthorityClaim& claim) {
  write_typed_id(writer, claim.publisher);
  write_typed_id(writer, claim.worker_boot);
  write_counter(writer, claim.epoch);
}

bool take_authority(ByteReader& reader, AuthorityClaim& out, std::string_view stage, std::string& error) {
  AuthorityClaim claim;
  if (!take_typed_id(reader, claim.publisher, stage, error) ||
      !take_typed_id(reader, claim.worker_boot, stage, error) ||
      !take_counter(reader, claim.epoch, stage, error)) {
    return false;
  }
  out = claim;
  return true;
}

void write_explanation_step(ByteWriter& writer, const ExplanationStep& step) {
  writer.text(step.stage);
  writer.text(step.field);
  writer.text(step.value);
  writer.text(step.detail);
}

bool take_explanation_step(ByteReader& reader, ExplanationStep& out, std::string_view stage, std::string& error) {
  ExplanationStep step;
  if (!take_text(reader, step.stage, stage, error) || !take_text(reader, step.field, stage, error) ||
      !take_text(reader, step.value, stage, error) || !take_text(reader, step.detail, stage, error)) {
    return false;
  }
  out = std::move(step);
  return true;
}

void write_outcome(ByteWriter& writer, const Outcome& outcome) {
  writer.u8(static_cast<std::uint8_t>(outcome.code));
  writer.text(outcome.message);
  write_optional_canonical_id(writer, outcome.record);
  write_optional_counter(writer, outcome.record_generation);
  write_optional_counter(writer, outcome.evidence_generation);
  write_optional_counter(writer, outcome.epoch);
  write_optional_match(writer, outcome.match);
  write_optional_digest(writer, outcome.request_digest);
  write_optional_counter(writer, outcome.state_generation);
  write_sequence(writer, outcome.steps,
                 [](ByteWriter& target, const ExplanationStep& step) { write_explanation_step(target, step); });
  write_sequence(writer, outcome.related,
                 [](ByteWriter& target, const CanonicalId& id) { write_canonical_id(target, id); });
}

bool take_outcome(ByteReader& reader, Outcome& out, std::string_view stage, std::string& error) {
  std::uint8_t raw_code = 0;
  if (!take_enum(reader, raw_code, kMaxOutcomeCode, stage, error)) {
    return false;
  }
  Outcome outcome;
  outcome.code = static_cast<OutcomeCode>(raw_code);
  if (!take_text(reader, outcome.message, stage, error) ||
      !take_optional_canonical_id(reader, outcome.record, stage, error) ||
      !take_optional_counter(reader, outcome.record_generation, stage, error) ||
      !take_optional_counter(reader, outcome.evidence_generation, stage, error) ||
      !take_optional_counter(reader, outcome.epoch, stage, error) ||
      !take_optional_match(reader, outcome.match, stage, error) ||
      !take_optional_digest(reader, outcome.request_digest, stage, error) ||
      !take_optional_counter(reader, outcome.state_generation, stage, error) ||
      !take_sequence(reader, outcome.steps, kMaxStepCount, stage, error,
                     [](ByteReader& source, ExplanationStep& element, std::string& failure) {
                       return take_explanation_step(source, element, "explanation step", failure);
                     }) ||
      !take_sequence(reader, outcome.related, kMaxRelatedCount, stage, error,
                     [](ByteReader& source, CanonicalId& element, std::string& failure) {
                       return take_canonical_id(source, element, "outcome related record", failure);
                     })) {
    return false;
  }
  out = std::move(outcome);
  return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Message type identity
// ---------------------------------------------------------------------------

std::string_view to_string(MessageType value) noexcept {
  switch (value) {
    case MessageType::Invalid:
      return "invalid";
    case MessageType::Hello:
      return "hello";
    case MessageType::HelloAck:
      return "hello-ack";
    case MessageType::AttachPublisher:
      return "attach-publisher";
    case MessageType::AttachPublisherAck:
      return "attach-publisher-ack";
    case MessageType::DetachPublisher:
      return "detach-publisher";
    case MessageType::RegisterEntity:
      return "register-entity";
    case MessageType::UpdateEvidence:
      return "update-evidence";
    case MessageType::AttachAlias:
      return "attach-alias";
    case MessageType::DetachAlias:
      return "detach-alias";
    case MessageType::SupersedeEntity:
      return "supersede-entity";
    case MessageType::RetireEntity:
      return "retire-entity";
    case MessageType::TombstoneEntity:
      return "tombstone-entity";
    case MessageType::RevalidateEntity:
      return "revalidate-entity";
    case MessageType::ResolveConflict:
      return "resolve-conflict";
    case MessageType::ReconcileObservation:
      return "reconcile-observation";
    case MessageType::LookupEntity:
      return "lookup-entity";
    case MessageType::SnapshotRequest:
      return "snapshot-request";
    case MessageType::StatsRequest:
      return "stats-request";
    case MessageType::Heartbeat:
      return "heartbeat";
    case MessageType::HeartbeatAck:
      return "heartbeat-ack";
    case MessageType::OperationAck:
      return "operation-ack";
    case MessageType::ReconcileAck:
      return "reconcile-ack";
    case MessageType::LookupAck:
      return "lookup-ack";
    case MessageType::SnapshotAck:
      return "snapshot-ack";
    case MessageType::StatsAck:
      return "stats-ack";
    case MessageType::Shutdown:
      return "shutdown";
    case MessageType::Error:
      return "error";
  }
  return "unknown";
}

bool is_known_message_type(std::uint16_t raw) noexcept {
  return raw != 0u && raw <= kMessageTypeCount;
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> encode_frame(MessageType type,
                                       std::uint64_t request_id,
                                       std::span<const std::uint8_t> payload,
                                       const FrameLimits& limits,
                                       std::string& error) {
  error.clear();
  if (payload.size() > limits.max_payload_bytes || payload.size() > kMaxPayloadLength) {
    error = "payload exceeds the configured frame bound";
    return {};
  }
  const std::uint16_t raw_type = static_cast<std::uint16_t>(type);
  if (!is_known_message_type(raw_type)) {
    error = "message type is not known";
    return {};
  }
  ByteWriter writer(kFrameOverheadBytes + payload.size());
  writer.raw(kFrameMagic.data(), kFrameMagic.size());
  writer.u16(kWireProtocolVersion);
  writer.u16(raw_type);
  writer.u32(0);
  writer.u64(request_id);
  writer.u32(static_cast<std::uint32_t>(payload.size()));
  writer.raw(payload);
  writer.u64(frame_checksum(writer.bytes()));
  return std::move(writer.bytes());
}

std::string_view to_string(FrameDecodeStatus value) noexcept {
  switch (value) {
    case FrameDecodeStatus::Complete:
      return "complete";
    case FrameDecodeStatus::NeedMoreData:
      return "need-more-data";
    case FrameDecodeStatus::Malformed:
      return "malformed";
    case FrameDecodeStatus::PayloadTooLarge:
      return "payload-too-large";
    case FrameDecodeStatus::ChecksumMismatch:
      return "checksum-mismatch";
    case FrameDecodeStatus::UnknownMessageType:
      return "unknown-message-type";
  }
  return "unknown";
}

FrameDecodeResult decode_frame(std::span<const std::uint8_t> buffer, const FrameLimits& limits) {
  FrameDecodeResult result;
  if (buffer.size() < kFrameHeaderBytes) {
    result.status = FrameDecodeStatus::NeedMoreData;
    return result;
  }

  ByteReader reader(buffer);
  std::array<std::uint8_t, kFrameMagic.size()> magic{};
  std::uint16_t version = 0;
  std::uint16_t raw_type = 0;
  std::uint32_t flags = 0;
  std::uint64_t request_id = 0;
  std::uint32_t payload_length = 0;
  if (!reader.raw(magic.data(), magic.size()) || !reader.u16(version) || !reader.u16(raw_type) ||
      !reader.u32(flags) || !reader.u64(request_id) || !reader.u32(payload_length)) {
    // Unreachable: the header size was checked above. Kept so that no read can
    // ever run past the end of the buffer.
    result.status = FrameDecodeStatus::NeedMoreData;
    return result;
  }

  if (magic != kFrameMagic) {
    result.status = FrameDecodeStatus::Malformed;
    result.detail = "frame magic mismatch: expected \"FRG1\", found \"" + render_magic(magic) + "\"";
    return result;
  }
  if (version != kWireProtocolVersion) {
    result.status = FrameDecodeStatus::Malformed;
    result.detail = "frame protocol version mismatch: the frame declares " + std::to_string(version) +
                    " but this build speaks " + std::to_string(kWireProtocolVersion);
    return result;
  }
  if (flags != 0u) {
    result.status = FrameDecodeStatus::Malformed;
    result.detail = "frame flags are reserved and must be zero: " + std::to_string(flags);
    return result;
  }
  if (!is_known_message_type(raw_type)) {
    result.status = FrameDecodeStatus::UnknownMessageType;
    result.detail = "message type is not known: " + std::to_string(raw_type);
    return result;
  }

  const std::size_t declared = payload_length;
  if (declared > limits.max_payload_bytes) {
    result.status = FrameDecodeStatus::PayloadTooLarge;
    result.detail = "the frame declares " + std::to_string(declared) +
                    " payload bytes, above the configured bound of " + std::to_string(limits.max_payload_bytes);
    return result;
  }
  const std::size_t total = kFrameHeaderBytes + declared + kFrameChecksumBytes;
  if (buffer.size() < total) {
    result.status = FrameDecodeStatus::NeedMoreData;
    return result;
  }

  const std::size_t prefix_bytes = kFrameHeaderBytes + declared;
  if (frame_checksum(buffer.first(prefix_bytes)) != load_le64(buffer.data() + prefix_bytes)) {
    result.status = FrameDecodeStatus::ChecksumMismatch;
    result.consumed = total;
    result.detail = "the frame checksum does not match the frame contents";
    return result;
  }

  result.status = FrameDecodeStatus::Complete;
  result.consumed = total;
  result.frame.type = static_cast<MessageType>(raw_type);
  result.frame.flags = flags;
  result.frame.request_id = request_id;
  const std::span<const std::uint8_t> body = buffer.subspan(kFrameHeaderBytes, declared);
  result.frame.payload.assign(body.begin(), body.end());
  return result;
}

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> encode_hello_request(const HelloRequest& value) {
  ByteWriter writer(32);
  writer.u16(value.protocol_version);
  writer.text(value.client_name);
  return std::move(writer.bytes());
}

bool decode_hello_request(std::span<const std::uint8_t> payload, HelloRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  HelloRequest value;
  if (!take_u16(reader, value.protocol_version, "hello request protocol version", error) ||
      !take_text(reader, value.client_name, "hello request client name", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "hello request");
}

std::vector<std::uint8_t> encode_hello_response(const HelloResponse& value) {
  ByteWriter writer(64);
  write_bool(writer, value.accepted);
  writer.u16(value.protocol_version);
  write_counter(writer, value.coordinator_epoch);
  write_counter(writer, value.registry_generation);
  writer.text(value.server_name);
  writer.text(value.reason);
  return std::move(writer.bytes());
}

bool decode_hello_response(std::span<const std::uint8_t> payload, HelloResponse& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  HelloResponse value;
  if (!take_bool(reader, value.accepted, "hello response accepted flag", error) ||
      !take_u16(reader, value.protocol_version, "hello response protocol version", error) ||
      !take_counter(reader, value.coordinator_epoch, "hello response coordinator epoch", error) ||
      !take_counter(reader, value.registry_generation, "hello response registry generation", error) ||
      !take_text(reader, value.server_name, "hello response server name", error) ||
      !take_text(reader, value.reason, "hello response reason", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "hello response");
}

std::vector<std::uint8_t> encode_attach_request(const PublisherAttachRequest& value) {
  ByteWriter writer(48);
  write_typed_id(writer, value.publisher);
  writer.text(value.name);
  writer.u16(value.protocol_version);
  return std::move(writer.bytes());
}

bool decode_attach_request(std::span<const std::uint8_t> payload, PublisherAttachRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  PublisherAttachRequest value;
  if (!take_typed_id(reader, value.publisher, "attach request publisher", error) ||
      !take_text(reader, value.name, "attach request name", error) ||
      !take_u16(reader, value.protocol_version, "attach request protocol version", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "attach request");
}

std::vector<std::uint8_t> encode_attach_response(const PublisherAttachResult& value) {
  ByteWriter writer(96);
  write_outcome(writer, value.outcome);
  write_typed_id(writer, value.publisher);
  write_typed_id(writer, value.worker_boot);
  write_counter(writer, value.epoch);
  write_bool(writer, value.fenced_previous);
  return std::move(writer.bytes());
}

bool decode_attach_response(std::span<const std::uint8_t> payload, PublisherAttachResult& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  PublisherAttachResult value;
  if (!take_outcome(reader, value.outcome, "attach response outcome", error) ||
      !take_typed_id(reader, value.publisher, "attach response publisher", error) ||
      !take_typed_id(reader, value.worker_boot, "attach response worker boot", error) ||
      !take_counter(reader, value.epoch, "attach response epoch", error) ||
      !take_bool(reader, value.fenced_previous, "attach response fenced-previous flag", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "attach response");
}

std::vector<std::uint8_t> encode_detach_request(const AuthorityClaim& value, FenceReason reason) {
  ByteWriter writer(48);
  write_authority(writer, value);
  writer.u8(static_cast<std::uint8_t>(reason));
  return std::move(writer.bytes());
}

bool decode_detach_request(std::span<const std::uint8_t> payload,
                           AuthorityClaim& out,
                           FenceReason& reason,
                           std::string& error) {
  error.clear();
  ByteReader reader(payload);
  AuthorityClaim value;
  std::uint8_t raw_reason = 0;
  if (!take_authority(reader, value, "detach request authority", error) ||
      !take_enum(reader, raw_reason, kMaxFenceReason, "detach request reason", error)) {
    return false;
  }
  if (!reader.at_end()) {
    error = "detach request payload has trailing bytes";
    return false;
  }
  out = value;
  reason = static_cast<FenceReason>(raw_reason);
  return true;
}

std::vector<std::uint8_t> encode_authority(const AuthorityClaim& value) {
  ByteWriter writer(48);
  write_authority(writer, value);
  return std::move(writer.bytes());
}

bool decode_authority(std::span<const std::uint8_t> payload, AuthorityClaim& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  AuthorityClaim value;
  if (!take_authority(reader, value, "authority claim", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "authority claim");
}

std::vector<std::uint8_t> encode_outcome(const Outcome& value) {
  ByteWriter writer(256);
  write_outcome(writer, value);
  return std::move(writer.bytes());
}

bool decode_outcome(std::span<const std::uint8_t> payload, Outcome& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  Outcome value;
  if (!take_outcome(reader, value, "outcome", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "outcome");
}

std::vector<std::uint8_t> encode_register_request(const RegisterEntityRequest& value) {
  ByteWriter writer(512);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  writer.u8(static_cast<std::uint8_t>(value.entity_class));
  write_optional_canonical_id(writer, value.canonical_id);
  writer.text(value.derivation_namespace);
  writer.text(value.friendly_name);
  write_sequence(writer, value.facts,
                 [](ByteWriter& target, const IdentityFact& fact) { write_identity_fact(target, fact); });
  write_sequence(writer, value.aliases,
                 [](ByteWriter& target, const AliasInput& alias) { write_alias_input(target, alias); });
  write_sequence(writer, value.metadata,
                 [](ByteWriter& target, const MetadataEntry& entry) { write_metadata_entry(target, entry); });
  write_scope_ref(writer, value.scope);
  write_provenance(writer, value.provenance);
  writer.u8(static_cast<std::uint8_t>(value.evidence_class));
  writer.u8(static_cast<std::uint8_t>(value.admission));
  write_optional_counter(writer, value.expected_generation);
  writer.u8(static_cast<std::uint8_t>(value.resolution));
  write_optional_canonical_id(writer, value.resolve_to);
  write_bool(writer, value.record_conflict);
  return std::move(writer.bytes());
}

bool decode_register_request(std::span<const std::uint8_t> payload, RegisterEntityRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  RegisterEntityRequest value;
  std::uint8_t raw_class = 0;
  std::uint8_t raw_evidence = 0;
  std::uint8_t raw_admission = 0;
  std::uint8_t raw_resolution = 0;
  if (!take_typed_id(reader, value.attempt, "register request attempt", error) ||
      !take_authority(reader, value.authority, "register request authority", error) ||
      !take_enum(reader, raw_class, kMaxEntityClass, "register request entity class", error) ||
      !take_optional_canonical_id(reader, value.canonical_id, "register request canonical id", error) ||
      !take_text(reader, value.derivation_namespace, "register request derivation namespace", error) ||
      !take_text(reader, value.friendly_name, "register request friendly name", error) ||
      !take_sequence(reader, value.facts, kMaxFactCount, "register request facts", error,
                     [](ByteReader& source, IdentityFact& element, std::string& failure) {
                       return take_identity_fact(source, element, "register request fact", failure);
                     }) ||
      !take_sequence(reader, value.aliases, kMaxAliasCount, "register request aliases", error,
                     [](ByteReader& source, AliasInput& element, std::string& failure) {
                       return take_alias_input(source, element, "register request alias", failure);
                     }) ||
      !take_sequence(reader, value.metadata, kMaxMetadataCount, "register request metadata", error,
                     [](ByteReader& source, MetadataEntry& element, std::string& failure) {
                       return take_metadata_entry(source, element, "register request metadata entry", failure);
                     }) ||
      !take_scope_ref(reader, value.scope, "register request scope", error) ||
      !take_provenance(reader, value.provenance, "register request provenance", error) ||
      !take_enum(reader, raw_evidence, kMaxEvidenceClass, "register request evidence class", error) ||
      !take_enum(reader, raw_admission, kMaxAdmissionMode, "register request admission mode", error) ||
      !take_optional_counter(reader, value.expected_generation, "register request expected generation", error) ||
      !take_enum(reader, raw_resolution, kMaxReconcileResolution, "register request resolution", error) ||
      !take_optional_canonical_id(reader, value.resolve_to, "register request resolution target", error) ||
      !take_bool(reader, value.record_conflict, "register request record-conflict flag", error)) {
    return false;
  }
  value.entity_class = static_cast<EntityClass>(raw_class);
  value.evidence_class = static_cast<EvidenceClass>(raw_evidence);
  value.admission = static_cast<AdmissionMode>(raw_admission);
  value.resolution = static_cast<ReconcileResolution>(raw_resolution);
  return finish_payload(reader, value, out, error, "register request");
}

std::vector<std::uint8_t> encode_update_evidence_request(const UpdateEvidenceRequest& value) {
  ByteWriter writer(256);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  write_sequence(writer, value.facts,
                 [](ByteWriter& target, const IdentityFact& fact) { write_identity_fact(target, fact); });
  write_provenance(writer, value.provenance);
  writer.u8(static_cast<std::uint8_t>(value.evidence_class));
  write_bool(writer, value.merge_facts);
  return std::move(writer.bytes());
}

bool decode_update_evidence_request(std::span<const std::uint8_t> payload,
                                    UpdateEvidenceRequest& out,
                                    std::string& error) {
  error.clear();
  ByteReader reader(payload);
  UpdateEvidenceRequest value;
  std::uint8_t raw_evidence = 0;
  if (!take_typed_id(reader, value.attempt, "update evidence request attempt", error) ||
      !take_authority(reader, value.authority, "update evidence request authority", error) ||
      !take_canonical_id(reader, value.target, "update evidence request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "update evidence request expected generation", error) ||
      !take_sequence(reader, value.facts, kMaxFactCount, "update evidence request facts", error,
                     [](ByteReader& source, IdentityFact& element, std::string& failure) {
                       return take_identity_fact(source, element, "update evidence request fact", failure);
                     }) ||
      !take_provenance(reader, value.provenance, "update evidence request provenance", error) ||
      !take_enum(reader, raw_evidence, kMaxEvidenceClass, "update evidence request evidence class", error) ||
      !take_bool(reader, value.merge_facts, "update evidence request merge-facts flag", error)) {
    return false;
  }
  value.evidence_class = static_cast<EvidenceClass>(raw_evidence);
  return finish_payload(reader, value, out, error, "update evidence request");
}

std::vector<std::uint8_t> encode_alias_request(const AliasMutationRequest& value) {
  ByteWriter writer(128);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  write_alias_input(writer, value.alias);
  return std::move(writer.bytes());
}

bool decode_alias_request(std::span<const std::uint8_t> payload, AliasMutationRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  AliasMutationRequest value;
  if (!take_typed_id(reader, value.attempt, "alias request attempt", error) ||
      !take_authority(reader, value.authority, "alias request authority", error) ||
      !take_canonical_id(reader, value.target, "alias request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "alias request expected generation", error) ||
      !take_alias_input(reader, value.alias, "alias request alias", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "alias request");
}

std::vector<std::uint8_t> encode_supersede_request(const SupersedeEntityRequest& value) {
  ByteWriter writer(192);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  write_optional_canonical_id(writer, value.successor);
  writer.text(value.reason);
  return std::move(writer.bytes());
}

bool decode_supersede_request(std::span<const std::uint8_t> payload, SupersedeEntityRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  SupersedeEntityRequest value;
  if (!take_typed_id(reader, value.attempt, "supersede request attempt", error) ||
      !take_authority(reader, value.authority, "supersede request authority", error) ||
      !take_canonical_id(reader, value.target, "supersede request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "supersede request expected generation", error) ||
      !take_optional_canonical_id(reader, value.successor, "supersede request successor", error) ||
      !take_text(reader, value.reason, "supersede request reason", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "supersede request");
}

std::vector<std::uint8_t> encode_retire_request(const RetireEntityRequest& value) {
  ByteWriter writer(160);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  writer.text(value.reason);
  return std::move(writer.bytes());
}

bool decode_retire_request(std::span<const std::uint8_t> payload, RetireEntityRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  RetireEntityRequest value;
  if (!take_typed_id(reader, value.attempt, "retire request attempt", error) ||
      !take_authority(reader, value.authority, "retire request authority", error) ||
      !take_canonical_id(reader, value.target, "retire request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "retire request expected generation", error) ||
      !take_text(reader, value.reason, "retire request reason", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "retire request");
}

std::vector<std::uint8_t> encode_tombstone_request(const TombstoneEntityRequest& value) {
  ByteWriter writer(160);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  writer.text(value.reason);
  return std::move(writer.bytes());
}

bool decode_tombstone_request(std::span<const std::uint8_t> payload, TombstoneEntityRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  TombstoneEntityRequest value;
  if (!take_typed_id(reader, value.attempt, "tombstone request attempt", error) ||
      !take_authority(reader, value.authority, "tombstone request authority", error) ||
      !take_canonical_id(reader, value.target, "tombstone request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "tombstone request expected generation", error) ||
      !take_text(reader, value.reason, "tombstone request reason", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "tombstone request");
}

std::vector<std::uint8_t> encode_revalidate_request(const RevalidateEntityRequest& value) {
  ByteWriter writer(256);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  write_sequence(writer, value.facts,
                 [](ByteWriter& target, const IdentityFact& fact) { write_identity_fact(target, fact); });
  write_provenance(writer, value.provenance);
  writer.u8(static_cast<std::uint8_t>(value.evidence_class));
  write_bool(writer, value.merge_facts);
  return std::move(writer.bytes());
}

bool decode_revalidate_request(std::span<const std::uint8_t> payload, RevalidateEntityRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  RevalidateEntityRequest value;
  std::uint8_t raw_evidence = 0;
  if (!take_typed_id(reader, value.attempt, "revalidate request attempt", error) ||
      !take_authority(reader, value.authority, "revalidate request authority", error) ||
      !take_canonical_id(reader, value.target, "revalidate request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "revalidate request expected generation", error) ||
      !take_sequence(reader, value.facts, kMaxFactCount, "revalidate request facts", error,
                     [](ByteReader& source, IdentityFact& element, std::string& failure) {
                       return take_identity_fact(source, element, "revalidate request fact", failure);
                     }) ||
      !take_provenance(reader, value.provenance, "revalidate request provenance", error) ||
      !take_enum(reader, raw_evidence, kMaxEvidenceClass, "revalidate request evidence class", error) ||
      !take_bool(reader, value.merge_facts, "revalidate request merge-facts flag", error)) {
    return false;
  }
  value.evidence_class = static_cast<EvidenceClass>(raw_evidence);
  return finish_payload(reader, value, out, error, "revalidate request");
}

std::vector<std::uint8_t> encode_resolve_conflict_request(const ResolveConflictRequest& value) {
  ByteWriter writer(176);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  write_canonical_id(writer, value.target);
  write_optional_counter(writer, value.expected_generation);
  writer.u8(static_cast<std::uint8_t>(value.resolution));
  writer.text(value.reason);
  return std::move(writer.bytes());
}

bool decode_resolve_conflict_request(std::span<const std::uint8_t> payload,
                                     ResolveConflictRequest& out,
                                     std::string& error) {
  error.clear();
  ByteReader reader(payload);
  ResolveConflictRequest value;
  std::uint8_t raw_resolution = 0;
  if (!take_typed_id(reader, value.attempt, "resolve conflict request attempt", error) ||
      !take_authority(reader, value.authority, "resolve conflict request authority", error) ||
      !take_canonical_id(reader, value.target, "resolve conflict request target", error) ||
      !take_optional_counter(reader, value.expected_generation, "resolve conflict request expected generation", error) ||
      !take_enum(reader, raw_resolution, kMaxConflictResolution, "resolve conflict request resolution", error) ||
      !take_text(reader, value.reason, "resolve conflict request reason", error)) {
    return false;
  }
  value.resolution = static_cast<ConflictResolution>(raw_resolution);
  return finish_payload(reader, value, out, error, "resolve conflict request");
}

std::vector<std::uint8_t> encode_reconcile_request(const ReconcileObservationRequest& value) {
  ByteWriter writer(384);
  write_typed_id(writer, value.attempt);
  write_authority(writer, value.authority);
  writer.u8(static_cast<std::uint8_t>(value.entity_class));
  write_sequence(writer, value.facts,
                 [](ByteWriter& target, const IdentityFact& fact) { write_identity_fact(target, fact); });
  write_sequence(writer, value.aliases,
                 [](ByteWriter& target, const AliasInput& alias) { write_alias_input(target, alias); });
  write_scope_ref(writer, value.scope);
  write_provenance(writer, value.provenance);
  writer.u8(static_cast<std::uint8_t>(value.resolution));
  write_optional_canonical_id(writer, value.resolve_to);
  return std::move(writer.bytes());
}

bool decode_reconcile_request(std::span<const std::uint8_t> payload,
                              ReconcileObservationRequest& out,
                              std::string& error) {
  error.clear();
  ByteReader reader(payload);
  ReconcileObservationRequest value;
  std::uint8_t raw_class = 0;
  std::uint8_t raw_resolution = 0;
  if (!take_typed_id(reader, value.attempt, "reconcile request attempt", error) ||
      !take_authority(reader, value.authority, "reconcile request authority", error) ||
      !take_enum(reader, raw_class, kMaxEntityClass, "reconcile request entity class", error) ||
      !take_sequence(reader, value.facts, kMaxFactCount, "reconcile request facts", error,
                     [](ByteReader& source, IdentityFact& element, std::string& failure) {
                       return take_identity_fact(source, element, "reconcile request fact", failure);
                     }) ||
      !take_sequence(reader, value.aliases, kMaxAliasCount, "reconcile request aliases", error,
                     [](ByteReader& source, AliasInput& element, std::string& failure) {
                       return take_alias_input(source, element, "reconcile request alias", failure);
                     }) ||
      !take_scope_ref(reader, value.scope, "reconcile request scope", error) ||
      !take_provenance(reader, value.provenance, "reconcile request provenance", error) ||
      !take_enum(reader, raw_resolution, kMaxReconcileResolution, "reconcile request resolution", error) ||
      !take_optional_canonical_id(reader, value.resolve_to, "reconcile request resolution target", error)) {
    return false;
  }
  value.entity_class = static_cast<EntityClass>(raw_class);
  value.resolution = static_cast<ReconcileResolution>(raw_resolution);
  return finish_payload(reader, value, out, error, "reconcile request");
}

std::vector<std::uint8_t> encode_lookup_request(const LookupRequest& value) {
  ByteWriter writer(24);
  write_canonical_id(writer, value.target);
  return std::move(writer.bytes());
}

bool decode_lookup_request(std::span<const std::uint8_t> payload, LookupRequest& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  LookupRequest value;
  if (!take_canonical_id(reader, value.target, "lookup request target", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "lookup request");
}

std::vector<std::uint8_t> encode_reconcile_detail(const ReconcileDetail& value) {
  ByteWriter writer(256);
  writer.u8(static_cast<std::uint8_t>(value.match));
  write_optional_canonical_id(writer, value.matched);
  write_sequence(writer, value.candidates,
                 [](ByteWriter& target, const CanonicalId& id) { write_canonical_id(target, id); });
  write_sequence(writer, value.conflicting_facts,
                 [](ByteWriter& target, const IdentityFact& fact) { write_identity_fact(target, fact); });
  write_sequence(writer, value.conflicting_aliases,
                 [](ByteWriter& target, const AliasKey& key) { write_alias_key(target, key); });
  write_digest(writer, value.observation_fingerprint);
  return std::move(writer.bytes());
}

bool decode_reconcile_detail(std::span<const std::uint8_t> payload, ReconcileDetail& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  ReconcileDetail value;
  std::uint8_t raw_match = 0;
  if (!take_enum(reader, raw_match, kMaxMatchClass, "reconcile detail match", error) ||
      !take_optional_canonical_id(reader, value.matched, "reconcile detail matched record", error) ||
      !take_sequence(reader, value.candidates, kMaxRelatedCount, "reconcile detail candidates", error,
                     [](ByteReader& source, CanonicalId& element, std::string& failure) {
                       return take_canonical_id(source, element, "reconcile detail candidate", failure);
                     }) ||
      !take_sequence(reader, value.conflicting_facts, kMaxFactCount, "reconcile detail conflicting facts", error,
                     [](ByteReader& source, IdentityFact& element, std::string& failure) {
                       return take_identity_fact(source, element, "reconcile detail conflicting fact", failure);
                     }) ||
      !take_sequence(reader, value.conflicting_aliases, kMaxAliasCount, "reconcile detail conflicting aliases", error,
                     [](ByteReader& source, AliasKey& element, std::string& failure) {
                       return take_alias_key(source, element, "reconcile detail conflicting alias", failure);
                     }) ||
      !take_digest(reader, value.observation_fingerprint, "reconcile detail observation fingerprint", error)) {
    return false;
  }
  value.match = static_cast<MatchClass>(raw_match);
  return finish_payload(reader, value, out, error, "reconcile detail");
}

std::vector<std::uint8_t> encode_lookup_response(const Outcome& outcome,
                                                 const std::shared_ptr<const EntityRecord>& record) {
  ByteWriter writer(256);
  write_outcome(writer, outcome);
  if (record == nullptr) {
    writer.u8(0);
    return std::move(writer.bytes());
  }
  writer.u8(1);
  const std::vector<std::uint8_t> encoded = encode_record(*record);
  writer.blob(encoded);
  return std::move(writer.bytes());
}

bool decode_lookup_response(std::span<const std::uint8_t> payload,
                            Outcome& outcome,
                            std::shared_ptr<const EntityRecord>& record,
                            std::string& error) {
  error.clear();
  ByteReader reader(payload);
  Outcome parsed_outcome;
  if (!take_outcome(reader, parsed_outcome, "lookup response outcome", error)) {
    return false;
  }
  bool present = false;
  if (!take_presence(reader, present, "lookup response record", error)) {
    return false;
  }
  std::shared_ptr<const EntityRecord> parsed_record;
  if (present) {
    std::vector<std::uint8_t> encoded;
    if (!reader.blob(encoded, kMaxRecordPayloadBytes)) {
      error = "lookup response record is out of bounds";
      return false;
    }
    EntityRecord value;
    if (!decode_record(encoded, wire_record_limits(), value, error)) {
      if (error.empty()) {
        error = "lookup response record is malformed";
      }
      return false;
    }
    parsed_record = std::make_shared<const EntityRecord>(std::move(value));
  }
  if (!reader.at_end()) {
    error = "lookup response payload has trailing bytes";
    return false;
  }
  outcome = std::move(parsed_outcome);
  record = std::move(parsed_record);
  return true;
}

std::vector<std::uint8_t> encode_snapshot_summary(const SnapshotSummary& value) {
  ByteWriter writer(96);
  write_counter(writer, value.generation);
  write_counter(writer, value.epoch);
  write_counter(writer, value.sequence);
  write_digest(writer, value.digest);
  writer.u64(value.record_count);
  writer.u64(value.alias_count);
  return std::move(writer.bytes());
}

bool decode_snapshot_summary(std::span<const std::uint8_t> payload, SnapshotSummary& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  SnapshotSummary value;
  if (!take_counter(reader, value.generation, "snapshot summary generation", error) ||
      !take_counter(reader, value.epoch, "snapshot summary epoch", error) ||
      !take_counter(reader, value.sequence, "snapshot summary sequence", error) ||
      !take_digest(reader, value.digest, "snapshot summary digest", error) ||
      !take_u64(reader, value.record_count, "snapshot summary record count", error) ||
      !take_u64(reader, value.alias_count, "snapshot summary alias count", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "snapshot summary");
}

std::vector<std::uint8_t> encode_stats(const StatsPayload& value) {
  const RegistryStats& stats = value.stats;
  ByteWriter writer(160);
  writer.u64(static_cast<std::uint64_t>(stats.entities));
  writer.u64(static_cast<std::uint64_t>(stats.current_entities));
  writer.u64(static_cast<std::uint64_t>(stats.discovered_entities));
  writer.u64(static_cast<std::uint64_t>(stats.candidate_entities));
  writer.u64(static_cast<std::uint64_t>(stats.revalidation_required_entities));
  writer.u64(static_cast<std::uint64_t>(stats.superseded_entities));
  writer.u64(static_cast<std::uint64_t>(stats.retired_entities));
  writer.u64(static_cast<std::uint64_t>(stats.tombstoned_entities));
  writer.u64(static_cast<std::uint64_t>(stats.conflicted_entities));
  writer.u64(static_cast<std::uint64_t>(stats.rejected_entities));
  writer.u64(static_cast<std::uint64_t>(stats.aliases));
  writer.u64(static_cast<std::uint64_t>(stats.indexed_aliases));
  writer.u64(static_cast<std::uint64_t>(stats.publishers));
  writer.u64(static_cast<std::uint64_t>(stats.active_publishers));
  writer.u64(static_cast<std::uint64_t>(stats.lineage_entries));
  writer.u64(static_cast<std::uint64_t>(stats.idempotency_records));
  write_counter(writer, stats.generation);
  write_counter(writer, stats.epoch);
  return std::move(writer.bytes());
}

bool decode_stats(std::span<const std::uint8_t> payload, StatsPayload& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  StatsPayload value;
  const auto take_size = [&reader, &error](std::size_t& target, std::string_view stage) {
    std::uint64_t raw = 0;
    if (!take_u64(reader, raw, stage, error)) {
      return false;
    }
    target = static_cast<std::size_t>(raw);
    return true;
  };
  if (!take_size(value.stats.entities, "stats entity count") ||
      !take_size(value.stats.current_entities, "stats current entity count") ||
      !take_size(value.stats.discovered_entities, "stats discovered entity count") ||
      !take_size(value.stats.candidate_entities, "stats candidate entity count") ||
      !take_size(value.stats.revalidation_required_entities, "stats revalidation-required entity count") ||
      !take_size(value.stats.superseded_entities, "stats superseded entity count") ||
      !take_size(value.stats.retired_entities, "stats retired entity count") ||
      !take_size(value.stats.tombstoned_entities, "stats tombstoned entity count") ||
      !take_size(value.stats.conflicted_entities, "stats conflicted entity count") ||
      !take_size(value.stats.rejected_entities, "stats rejected entity count") ||
      !take_size(value.stats.aliases, "stats alias count") ||
      !take_size(value.stats.indexed_aliases, "stats indexed alias count") ||
      !take_size(value.stats.publishers, "stats publisher count") ||
      !take_size(value.stats.active_publishers, "stats active publisher count") ||
      !take_size(value.stats.lineage_entries, "stats lineage entry count") ||
      !take_size(value.stats.idempotency_records, "stats idempotency record count") ||
      !take_counter(reader, value.stats.generation, "stats registry generation", error) ||
      !take_counter(reader, value.stats.epoch, "stats coordinator epoch", error)) {
    return false;
  }
  return finish_payload(reader, value, out, error, "stats");
}

std::vector<std::uint8_t> encode_error(const ErrorPayload& value) {
  ByteWriter writer(32);
  writer.u8(static_cast<std::uint8_t>(value.code));
  writer.text(value.message);
  return std::move(writer.bytes());
}

bool decode_error(std::span<const std::uint8_t> payload, ErrorPayload& out, std::string& error) {
  error.clear();
  ByteReader reader(payload);
  ErrorPayload value;
  std::uint8_t raw_code = 0;
  if (!take_enum(reader, raw_code, kMaxOutcomeCode, "error payload code", error) ||
      !take_text(reader, value.message, "error payload message", error)) {
    return false;
  }
  value.code = static_cast<OutcomeCode>(raw_code);
  return finish_payload(reader, value, out, error, "error payload");
}

std::size_t encoded_record_size_bound(const RegistryLimits& limits) noexcept {
  return limits.max_record_bytes + 64u;
}

} // namespace fabric_registry
