// Fabric Registry — canonical binary encoding of a record.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/record_codec.hpp"

#include <string>

#include "fabric_registry/identity.hpp"

namespace fabric_registry {
namespace {

void write_id_bytes(ByteWriter& writer, const IdBytes& bytes) {
  writer.raw(bytes.data(), bytes.size());
}

bool read_id_bytes(ByteReader& reader, IdBytes& out) noexcept {
  return reader.raw(out.data(), out.size());
}

void write_uuid(ByteWriter& writer, const std::uint8_t* bytes, std::size_t size) {
  writer.raw(bytes, size);
}

void write_canonical_id(ByteWriter& writer, const CanonicalId& id) {
  writer.u8(static_cast<std::uint8_t>(id.entity_class()));
  write_id_bytes(writer, id.bytes());
}

bool read_canonical_id(ByteReader& reader, CanonicalId& out, std::string& error) {
  std::uint8_t raw_class = 0;
  if (!reader.u8(raw_class)) {
    return false;
  }
  const EntityClass entity_class = static_cast<EntityClass>(raw_class);
  if (!is_valid_entity_class(entity_class)) {
    error = "record contains an invalid entity class";
    return false;
  }
  IdBytes bytes{};
  if (!read_id_bytes(reader, bytes)) {
    return false;
  }
  CanonicalId id(entity_class, bytes);
  if (id.is_null()) {
    error = "record contains a null canonical identity";
    return false;
  }
  out = id;
  return true;
}

void write_optional_canonical_id(ByteWriter& writer, const std::optional<CanonicalId>& id) {
  if (!id.has_value()) {
    writer.u8(0);
    return;
  }
  writer.u8(1);
  write_canonical_id(writer, *id);
}

bool read_optional_canonical_id(ByteReader& reader, std::optional<CanonicalId>& out, std::string& error) {
  std::uint8_t present = 0;
  if (!reader.u8(present)) {
    return false;
  }
  if (present == 0) {
    out.reset();
    return true;
  }
  if (present != 1) {
    error = "optional canonical identity has an invalid presence marker";
    return false;
  }
  CanonicalId id;
  if (!read_canonical_id(reader, id, error)) {
    return false;
  }
  out = id;
  return true;
}

void write_digest(ByteWriter& writer, const std::uint8_t* bytes) {
  write_uuid(writer, bytes, kDigestBytes);
}

void write_provenance(ByteWriter& writer, const Provenance& provenance) {
  writer.u8(static_cast<std::uint8_t>(provenance.source));
  writer.u8(static_cast<std::uint8_t>(provenance.validity_class));
  writer.text(provenance.mechanism);
  writer.text(provenance.source_identity);
}

bool read_provenance(ByteReader& reader, std::size_t max_string, Provenance& out, std::string& error) {
  std::uint8_t raw_source = 0;
  std::uint8_t raw_class = 0;
  if (!reader.u8(raw_source) || !reader.u8(raw_class)) {
    return false;
  }
  if (raw_source > kObservationSourceCount) {
    error = "record contains an invalid observation source";
    return false;
  }
  if (raw_class > static_cast<std::uint8_t>(ProvenanceClass::Unsupported)) {
    error = "record contains an invalid provenance class";
    return false;
  }
  Provenance provenance;
  provenance.source = static_cast<ObservationSource>(raw_source);
  provenance.validity_class = static_cast<ProvenanceClass>(raw_class);
  if (!reader.text(provenance.mechanism, max_string) || !reader.text(provenance.source_identity, max_string)) {
    error = "record provenance strings are out of bounds";
    return false;
  }
  if (!is_valid_identity_text(provenance.mechanism) || !is_valid_identity_text(provenance.source_identity)) {
    error = "record provenance contains invalid text";
    return false;
  }
  out = std::move(provenance);
  return true;
}

void write_evidence(ByteWriter& writer, const EvidenceState& evidence) {
  writer.u64(evidence.generation.value());
  writer.u8(static_cast<std::uint8_t>(evidence.evidence_class));
  writer.u8(evidence.valid ? 1 : 0);
  writer.u64(evidence.epoch.value());
  write_id_bytes(writer, evidence.publisher.bytes());
  write_id_bytes(writer, evidence.publisher_boot.bytes());
  writer.u64(evidence.accepted_at.value());
  write_provenance(writer, evidence.provenance);
}

bool read_evidence(ByteReader& reader, std::size_t max_string, EvidenceState& out, std::string& error) {
  std::uint64_t generation = 0;
  std::uint8_t raw_class = 0;
  std::uint8_t valid = 0;
  std::uint64_t epoch = 0;
  IdBytes publisher{};
  IdBytes publisher_boot{};
  std::uint64_t accepted_at = 0;
  if (!reader.u64(generation) || !reader.u8(raw_class) || !reader.u8(valid) || !reader.u64(epoch)) {
    return false;
  }
  if (!read_id_bytes(reader, publisher) || !read_id_bytes(reader, publisher_boot)) {
    return false;
  }
  if (!reader.u64(accepted_at)) {
    return false;
  }
  if (raw_class > static_cast<std::uint8_t>(EvidenceClass::DurableAuthority)) {
    error = "record contains an invalid evidence class";
    return false;
  }
  if (valid > 1) {
    error = "record contains an invalid evidence validity marker";
    return false;
  }
  EvidenceState evidence;
  evidence.generation = EvidenceGeneration(generation);
  evidence.evidence_class = static_cast<EvidenceClass>(raw_class);
  evidence.valid = valid == 1;
  evidence.epoch = CoordinatorEpoch(epoch);
  evidence.publisher = PublisherId::from_bytes(publisher);
  evidence.publisher_boot = WorkerBootId::from_bytes(publisher_boot);
  evidence.accepted_at = RegistryGeneration(accepted_at);
  if (!read_provenance(reader, max_string, evidence.provenance, error)) {
    return false;
  }
  out = std::move(evidence);
  return true;
}

bool validate_alias_key(const AliasKey& key, std::string& error) {
  if (alias_scope(key.alias_namespace) == AliasScope::Informational && key.alias_namespace == AliasNamespace::Unspecified) {
    error = "record contains an alias with an unspecified namespace";
    return false;
  }
  if (key.value.empty()) {
    error = "record contains an alias with an empty value";
    return false;
  }
  switch (alias_scope(key.alias_namespace)) {
    case AliasScope::Global:
      if (!key.scope.empty()) {
        error = "record contains a global alias carrying a scope";
        return false;
      }
      return true;
    case AliasScope::Informational:
      if (key.scope != "info") {
        error = "record contains an informational alias without the informational scope marker";
        return false;
      }
      return true;
    default:
      if (key.scope.empty()) {
        error = "record contains a scoped alias without a scope";
        return false;
      }
      return true;
  }
}

} // namespace

void write_record(ByteWriter& writer, const EntityRecord& record) {
  writer.u8(static_cast<std::uint8_t>(record.entity_class));
  write_id_bytes(writer, record.id.bytes());
  writer.u8(static_cast<std::uint8_t>(record.lifecycle));
  writer.u64(record.record_generation.value());
  writer.u64(record.creation_generation.value());
  writer.u64(record.evidence_generation.value());
  write_digest(writer, record.fingerprint.data());
  write_digest(writer, record.hardware_identity.data());
  writer.text(record.derivation_namespace);
  writer.text(record.friendly_name);
  write_optional_canonical_id(writer, record.parent_device);
  if (record.fabric.has_value()) {
    writer.u8(1);
    write_id_bytes(writer, record.fabric->bytes());
  } else {
    writer.u8(0);
  }
  if (record.site.has_value()) {
    writer.u8(1);
    write_id_bytes(writer, record.site->bytes());
  } else {
    writer.u8(0);
  }
  if (record.control_domain.has_value()) {
    writer.u8(1);
    write_id_bytes(writer, record.control_domain->bytes());
  } else {
    writer.u8(0);
  }
  writer.u32(static_cast<std::uint32_t>(record.facts.size()));
  for (const IdentityFact& fact : record.facts) {
    writer.u8(static_cast<std::uint8_t>(fact.kind));
    writer.text(fact.scope);
    writer.text(fact.value);
  }
  writer.u32(static_cast<std::uint32_t>(record.aliases.size()));
  for (const AliasKey& alias : record.aliases) {
    writer.u8(static_cast<std::uint8_t>(alias.alias_namespace));
    writer.text(alias.scope);
    writer.text(alias.value);
  }
  writer.u32(static_cast<std::uint32_t>(record.metadata.size()));
  for (const MetadataEntry& entry : record.metadata) {
    writer.text(entry.key);
    writer.text(entry.value);
  }
  write_evidence(writer, record.evidence);
  write_optional_canonical_id(writer, record.superseded_by);
  write_optional_canonical_id(writer, record.supersedes);
  writer.text(record.status_reason);
  writer.u64(record.last_modified.value());
  write_id_bytes(writer, record.created_by.bytes());
  write_id_bytes(writer, record.created_boot.bytes());
  writer.u64(record.created_epoch.value());
}

bool read_record(ByteReader& reader, const RegistryLimits& limits, EntityRecord& out, std::string& error) {
  std::uint8_t raw_class = 0;
  if (!reader.u8(raw_class)) {
    error = "record header is truncated";
    return false;
  }
  const EntityClass entity_class = static_cast<EntityClass>(raw_class);
  if (!is_valid_entity_class(entity_class)) {
    error = "record declares an invalid entity class";
    return false;
  }
  EntityRecord record;
  record.entity_class = entity_class;
  IdBytes bytes{};
  if (!read_id_bytes(reader, bytes)) {
    error = "record identifier is truncated";
    return false;
  }
  record.id = CanonicalId(entity_class, bytes);
  if (record.id.is_null()) {
    error = "record declares a null canonical identity";
    return false;
  }
  std::uint8_t raw_lifecycle = 0;
  if (!reader.u8(raw_lifecycle)) {
    error = "record lifecycle is truncated";
    return false;
  }
  if (raw_lifecycle >= kLifecycleCount) {
    error = "record declares an invalid lifecycle";
    return false;
  }
  record.lifecycle = static_cast<Lifecycle>(raw_lifecycle);
  std::uint64_t record_generation = 0;
  std::uint64_t creation_generation = 0;
  std::uint64_t evidence_generation = 0;
  if (!reader.u64(record_generation) || !reader.u64(creation_generation) || !reader.u64(evidence_generation)) {
    error = "record generations are truncated";
    return false;
  }
  record.record_generation = RecordGeneration(record_generation);
  record.creation_generation = RecordGeneration(creation_generation);
  record.evidence_generation = EvidenceGeneration(evidence_generation);
  if (record.record_generation.is_zero() || record.creation_generation.is_zero()) {
    error = "record declares a zero generation";
    return false;
  }
  if (record.creation_generation > record.record_generation) {
    error = "record creation generation is ahead of its record generation";
    return false;
  }
  DigestBytes fingerprint{};
  DigestBytes hardware_identity{};
  if (!reader.raw(fingerprint.data(), fingerprint.size()) ||
      !reader.raw(hardware_identity.data(), hardware_identity.size())) {
    error = "record digests are truncated";
    return false;
  }
  record.fingerprint = FingerprintDigest::from_bytes(fingerprint);
  record.hardware_identity = StableHardwareIdentity::from_bytes(hardware_identity);
  if (!reader.text(record.derivation_namespace, limits.max_string_bytes) ||
      !reader.text(record.friendly_name, limits.max_string_bytes)) {
    error = "record names are out of bounds";
    return false;
  }
  if (!is_valid_identity_text(record.derivation_namespace) || !is_valid_identity_text(record.friendly_name)) {
    error = "record names contain invalid text";
    return false;
  }
  if (!read_optional_canonical_id(reader, record.parent_device, error)) {
    return false;
  }
  const auto read_optional_typed = [&](auto& target) -> bool {
    using Target = std::decay_t<decltype(target)>;
    std::uint8_t present = 0;
    if (!reader.u8(present)) {
      error = "record reference is truncated";
      return false;
    }
    if (present == 0) {
      target.reset();
      return true;
    }
    if (present != 1) {
      error = "record reference has an invalid presence marker";
      return false;
    }
    IdBytes value{};
    if (!read_id_bytes(reader, value)) {
      error = "record reference is truncated";
      return false;
    }
    using IdType = typename Target::value_type;
    const IdType typed = IdType::from_bytes(value);
    if (typed.is_null()) {
      error = "record reference is null";
      return false;
    }
    target = typed;
    return true;
  };
  if (!read_optional_typed(record.fabric) || !read_optional_typed(record.site) ||
      !read_optional_typed(record.control_domain)) {
    return false;
  }

  std::uint32_t fact_count = 0;
  if (!reader.u32(fact_count)) {
    error = "record fact count is truncated";
    return false;
  }
  if (fact_count > limits.max_facts_per_entity) {
    error = "record declares more facts than the configured bound";
    return false;
  }
  record.facts.reserve(fact_count);
  for (std::uint32_t i = 0; i < fact_count; ++i) {
    std::uint8_t raw_kind = 0;
    if (!reader.u8(raw_kind)) {
      error = "record fact kind is truncated";
      return false;
    }
    IdentityFact fact;
    fact.kind = static_cast<IdentityFactKind>(raw_kind);
    if (!reader.text(fact.scope, limits.max_string_bytes) || !reader.text(fact.value, limits.max_string_bytes)) {
      error = "record fact strings are out of bounds";
      return false;
    }
    const FactResult canonical = canonicalize_fact(fact.kind, fact.scope, fact.value, limits.max_string_bytes);
    if (!canonical) {
      error = std::string("record fact is not canonicalisable: ") + std::string(to_string(canonical.issue));
      return false;
    }
    if (canonical.fact->scope != fact.scope || canonical.fact->value != fact.value ||
        canonical.fact->kind != fact.kind) {
      error = "record fact is not stored in canonical form";
      return false;
    }
    record.facts.push_back(std::move(*canonical.fact));
  }
  for (std::size_t i = 1; i < record.facts.size(); ++i) {
    const IdentityFact& previous = record.facts[i - 1];
    const IdentityFact& current = record.facts[i];
    if (previous.kind == current.kind && previous.scope == current.scope && previous.value == current.value) {
      error = "record contains a duplicate fact";
      return false;
    }
    if (previous.kind == current.kind && previous.scope == current.scope && previous.value != current.value) {
      error = "record contains contradictory facts";
      return false;
    }
  }

  std::uint32_t alias_count = 0;
  if (!reader.u32(alias_count)) {
    error = "record alias count is truncated";
    return false;
  }
  if (alias_count > limits.max_aliases_per_entity) {
    error = "record declares more aliases than the configured bound";
    return false;
  }
  record.aliases.reserve(alias_count);
  for (std::uint32_t i = 0; i < alias_count; ++i) {
    AliasKey alias;
    std::uint8_t raw_namespace = 0;
    if (!reader.u8(raw_namespace)) {
      error = "record alias namespace is truncated";
      return false;
    }
    alias.alias_namespace = static_cast<AliasNamespace>(raw_namespace);
    if (!reader.text(alias.scope, limits.max_string_bytes) || !reader.text(alias.value, limits.max_string_bytes)) {
      error = "record alias strings are out of bounds";
      return false;
    }
    if (!validate_alias_key(alias, error)) {
      return false;
    }
    record.aliases.push_back(std::move(alias));
  }
  for (std::size_t i = 1; i < record.aliases.size(); ++i) {
    if (record.aliases[i - 1] == record.aliases[i]) {
      error = "record contains a duplicate alias";
      return false;
    }
  }

  std::uint32_t metadata_count = 0;
  if (!reader.u32(metadata_count)) {
    error = "record metadata count is truncated";
    return false;
  }
  if (metadata_count > limits.max_metadata_entries) {
    error = "record declares more metadata entries than the configured bound";
    return false;
  }
  std::size_t metadata_bytes = 0;
  record.metadata.reserve(metadata_count);
  for (std::uint32_t i = 0; i < metadata_count; ++i) {
    MetadataEntry entry;
    if (!reader.text(entry.key, limits.max_string_bytes) ||
        !reader.text(entry.value, limits.max_metadata_value_bytes)) {
      error = "record metadata strings are out of bounds";
      return false;
    }
    if (entry.key.empty() || !is_valid_identity_text(entry.key) || !is_valid_identity_text(entry.value)) {
      error = "record metadata contains invalid text";
      return false;
    }
    metadata_bytes += entry.key.size() + entry.value.size();
    if (metadata_bytes > limits.max_metadata_bytes_per_entity) {
      error = "record metadata exceeds the configured total bound";
      return false;
    }
    record.metadata.push_back(std::move(entry));
  }
  for (std::size_t i = 1; i < record.metadata.size(); ++i) {
    if (record.metadata[i - 1].key == record.metadata[i].key) {
      error = "record contains a duplicate metadata key";
      return false;
    }
  }

  if (!read_evidence(reader, limits.max_string_bytes, record.evidence, error)) {
    return false;
  }
  if (!read_optional_canonical_id(reader, record.superseded_by, error) ||
      !read_optional_canonical_id(reader, record.supersedes, error)) {
    return false;
  }
  if (!reader.text(record.status_reason, limits.max_string_bytes)) {
    error = "record status reason is out of bounds";
    return false;
  }
  if (!is_valid_identity_text(record.status_reason)) {
    error = "record status reason contains invalid text";
    return false;
  }
  std::uint64_t last_modified = 0;
  if (!reader.u64(last_modified)) {
    error = "record last-modified generation is truncated";
    return false;
  }
  record.last_modified = RegistryGeneration(last_modified);
  IdBytes created_by{};
  IdBytes created_boot{};
  std::uint64_t created_epoch = 0;
  if (!read_id_bytes(reader, created_by) || !read_id_bytes(reader, created_boot) || !reader.u64(created_epoch)) {
    error = "record creation authority is truncated";
    return false;
  }
  record.created_by = PublisherId::from_bytes(created_by);
  record.created_boot = WorkerBootId::from_bytes(created_boot);
  record.created_epoch = CoordinatorEpoch(created_epoch);

  if (!record.is_well_formed()) {
    error = "record violates a structural invariant";
    return false;
  }
  if (holds_current_authority(record.lifecycle) && !record.evidence.valid) {
    error = "record is current but its evidence is marked invalid";
    return false;
  }
  out = std::move(record);
  return true;
}

std::vector<std::uint8_t> encode_record(const EntityRecord& record) {
  ByteWriter writer(512);
  write_record(writer, record);
  return writer.bytes();
}

bool decode_record(std::span<const std::uint8_t> bytes,
                   const RegistryLimits& limits,
                   EntityRecord& out,
                   std::string& error) {
  if (bytes.size() > limits.max_record_bytes) {
    error = "encoded record exceeds the configured record bound";
    return false;
  }
  ByteReader reader(bytes);
  if (!read_record(reader, limits, out, error)) {
    return false;
  }
  if (!reader.at_end()) {
    error = "encoded record has trailing bytes";
    return false;
  }
  return true;
}

} // namespace fabric_registry
