// Fabric Registry — wire protocol proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every case drives the public frame surface: the container codec and each
// payload codec. Payloads are compared field by field, and every decoder is
// probed with a trailing byte, a dropped byte and an out-of-range enum value,
// because a decoder that silently accepts a malformed body is worse than one
// that refuses a valid one.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/registry_test_support.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::AliasInput;
using fabric_registry::AliasKey;
using fabric_registry::AliasMutationRequest;
using fabric_registry::AliasNamespace;
using fabric_registry::AuthorityClaim;
using fabric_registry::ByteWriter;
using fabric_registry::CanonicalId;
using fabric_registry::CoordinatorEpoch;
using fabric_registry::DigestBytes;
using fabric_registry::EntityClass;
using fabric_registry::EntityRecord;
using fabric_registry::ErrorPayload;
using fabric_registry::EvidenceClass;
using fabric_registry::EvidenceGeneration;
using fabric_registry::ExplanationStep;
using fabric_registry::FenceReason;
using fabric_registry::FingerprintDigest;
using fabric_registry::Frame;
using fabric_registry::FrameDecodeResult;
using fabric_registry::FrameDecodeStatus;
using fabric_registry::FrameLimits;
using fabric_registry::HelloRequest;
using fabric_registry::HelloResponse;
using fabric_registry::IdBytes;
using fabric_registry::IdentityFact;
using fabric_registry::IdentityFactKind;
using fabric_registry::Lifecycle;
using fabric_registry::LookupRequest;
using fabric_registry::MatchClass;
using fabric_registry::MessageType;
using fabric_registry::MetadataEntry;
using fabric_registry::Outcome;
using fabric_registry::OutcomeCode;
using fabric_registry::PublisherAttachRequest;
using fabric_registry::PublisherAttachResult;
using fabric_registry::PublisherId;
using fabric_registry::ReconcileDetail;
using fabric_registry::ReconcileObservationRequest;
using fabric_registry::ReconcileResolution;
using fabric_registry::RecordGeneration;
using fabric_registry::RegisterEntityRequest;
using fabric_registry::RegistryGeneration;
using fabric_registry::RegistryLimits;
using fabric_registry::RegistryStats;
using fabric_registry::RequestDigest;
using fabric_registry::ResolveConflictRequest;
using fabric_registry::RetireEntityRequest;
using fabric_registry::RevalidateEntityRequest;
using fabric_registry::ScopeRef;
using fabric_registry::SnapshotSequence;
using fabric_registry::SnapshotSummary;
using fabric_registry::StableHardwareIdentity;
using fabric_registry::StateDigest;
using fabric_registry::StatsPayload;
using fabric_registry::SupersedeEntityRequest;
using fabric_registry::TombstoneEntityRequest;
using fabric_registry::UpdateEvidenceRequest;
using fabric_registry::WorkerBootId;

// ---------------------------------------------------------------------------
// Sample values
// ---------------------------------------------------------------------------

IdBytes id_bytes(std::uint8_t seed) {
  IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  }
  return bytes;
}

template <class DigestType>
DigestType digest_value(std::uint8_t seed) {
  DigestBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::uint8_t>(seed * 3u + index);
  }
  return DigestType::from_bytes(bytes);
}

CanonicalId sample_id(EntityClass entity_class, std::uint8_t seed) {
  return CanonicalId(entity_class, id_bytes(seed));
}

AuthorityClaim sample_claim() {
  AuthorityClaim claim;
  claim.publisher = PublisherId::from_bytes(id_bytes(0x10));
  claim.worker_boot = WorkerBootId::from_bytes(id_bytes(0x40));
  claim.epoch = CoordinatorEpoch(7);
  return claim;
}

PublisherAttachRequest sample_attach_request() {
  PublisherAttachRequest request;
  request.publisher = PublisherId::from_bytes(id_bytes(0x21));
  request.name = "frame-publisher";
  request.protocol_version = fabric_registry::protocol_version();
  return request;
}

ScopeRef sample_scope() {
  ScopeRef scope;
  scope.fabric = fabric_registry::FabricId::from_bytes(id_bytes(0x31));
  scope.site = fabric_registry::SiteId::from_bytes(id_bytes(0x41));
  scope.control_domain = fabric_registry::ControlDomainId::from_bytes(id_bytes(0x51));
  scope.parent_device = sample_id(EntityClass::Switch, 0x61);
  return scope;
}

std::vector<IdentityFact> sample_facts() {
  return {frtest::serial_fact("FRAME-SERIAL-1"),
          frtest::fact_of(IdentityFactKind::DeviceModel, "model-1"),
          frtest::fact_of(IdentityFactKind::PciAddress, "0000:3b:00.0")};
}

std::vector<MetadataEntry> sample_metadata() {
  return {MetadataEntry{"role", "spine"}, MetadataEntry{"rack", "r1"}};
}

Outcome sample_outcome() {
  Outcome outcome(OutcomeCode::StaleGeneration, "the expected record generation is no longer current");
  outcome.record = sample_id(EntityClass::Switch, 0x71);
  outcome.record_generation = RecordGeneration(9);
  outcome.evidence_generation = EvidenceGeneration(4);
  outcome.epoch = CoordinatorEpoch(3);
  outcome.match = MatchClass::ExactCanonical;
  outcome.request_digest = digest_value<RequestDigest>(0x11);
  outcome.state_generation = RegistryGeneration(44);
  outcome.steps.push_back(ExplanationStep{"generation", "record-generation", "9", "the record moved on"});
  outcome.steps.push_back(ExplanationStep{"authority", "publisher", "abc", "the publisher is known"});
  outcome.related.push_back(sample_id(EntityClass::Port, 0x81));
  outcome.related.push_back(sample_id(EntityClass::Host, 0x91));
  return outcome;
}

Outcome empty_outcome() {
  return Outcome{};
}

EntityRecord sample_record() {
  EntityRecord record;
  record.id = sample_id(EntityClass::Switch, 0xA1);
  record.entity_class = EntityClass::Switch;
  record.lifecycle = Lifecycle::Current;
  record.record_generation = RecordGeneration(4);
  record.creation_generation = RecordGeneration::first();
  record.evidence_generation = EvidenceGeneration(2);
  record.fingerprint = digest_value<FingerprintDigest>(0x21);
  record.hardware_identity = digest_value<StableHardwareIdentity>(0x31);
  record.derivation_namespace = "test/frame";
  record.friendly_name = "frame-record";
  record.facts = sample_facts();
  record.aliases.push_back(AliasKey{AliasNamespace::ExternalCmdbId, std::string(), "asset-frame"});
  record.metadata = sample_metadata();
  record.evidence.generation = EvidenceGeneration(2);
  record.evidence.evidence_class = EvidenceClass::DurableAuthority;
  record.evidence.provenance = frtest::real_provenance("frame");
  record.evidence.epoch = CoordinatorEpoch(3);
  record.evidence.publisher = PublisherId::from_bytes(id_bytes(0x10));
  record.evidence.publisher_boot = WorkerBootId::from_bytes(id_bytes(0x40));
  record.evidence.accepted_at = RegistryGeneration(2);
  record.evidence.valid = true;
  record.last_modified = RegistryGeneration(7);
  record.created_by = PublisherId::from_bytes(id_bytes(0x10));
  record.created_boot = WorkerBootId::from_bytes(id_bytes(0x40));
  record.created_epoch = CoordinatorEpoch(3);
  return record;
}

RegisterEntityRequest sample_register_request() {
  RegisterEntityRequest request;
  request.attempt = frtest::attempt_from("frame-register");
  request.authority = sample_claim();
  request.entity_class = EntityClass::Switch;
  request.derivation_namespace = "test/frame";
  request.friendly_name = "frame-switch";
  request.facts = sample_facts();
  request.aliases = {frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-1")};
  request.metadata = sample_metadata();
  request.scope = sample_scope();
  request.provenance = frtest::real_provenance("frame");
  request.evidence_class = EvidenceClass::DurableAuthority;
  request.admission = fabric_registry::AdmissionMode::RequireCurrent;
  request.expected_generation = RecordGeneration(3);
  request.resolution = ReconcileResolution::ForceExisting;
  request.resolve_to = sample_id(EntityClass::Switch, 0xB1);
  request.record_conflict = true;
  return request;
}

ReconcileObservationRequest sample_reconcile_request() {
  ReconcileObservationRequest request;
  request.attempt = frtest::attempt_from("frame-reconcile");
  request.authority = sample_claim();
  request.entity_class = EntityClass::Nic;
  request.facts = sample_facts();
  request.aliases = {frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-1")};
  request.scope = sample_scope();
  request.provenance = frtest::synthetic_provenance("frame");
  request.resolution = ReconcileResolution::ForceExisting;
  request.resolve_to = sample_id(EntityClass::Nic, 0xC1);
  return request;
}

// ---------------------------------------------------------------------------
// Comparisons
// ---------------------------------------------------------------------------

bool same_scope(const ScopeRef& left, const ScopeRef& right) {
  return left.fabric == right.fabric && left.site == right.site && left.control_domain == right.control_domain &&
         left.parent_device == right.parent_device;
}

bool same_outcome(const Outcome& left, const Outcome& right) {
  if (left.code != right.code || left.message != right.message) {
    return false;
  }
  if (left.record != right.record || left.record_generation != right.record_generation ||
      left.evidence_generation != right.evidence_generation || left.epoch != right.epoch || left.match != right.match ||
      left.request_digest != right.request_digest || left.state_generation != right.state_generation) {
    return false;
  }
  return left.steps == right.steps && left.related == right.related;
}

bool same_stats(const RegistryStats& left, const RegistryStats& right) {
  return left.entities == right.entities && left.current_entities == right.current_entities &&
         left.discovered_entities == right.discovered_entities && left.candidate_entities == right.candidate_entities &&
         left.revalidation_required_entities == right.revalidation_required_entities &&
         left.superseded_entities == right.superseded_entities && left.retired_entities == right.retired_entities &&
         left.tombstoned_entities == right.tombstoned_entities &&
         left.conflicted_entities == right.conflicted_entities && left.rejected_entities == right.rejected_entities &&
         left.aliases == right.aliases && left.indexed_aliases == right.indexed_aliases &&
         left.publishers == right.publishers && left.active_publishers == right.active_publishers &&
         left.lineage_entries == right.lineage_entries && left.idempotency_records == right.idempotency_records &&
         left.generation == right.generation && left.epoch == right.epoch;
}

bool same_register_request(const RegisterEntityRequest& left, const RegisterEntityRequest& right) {
  return left.attempt == right.attempt && left.authority == right.authority &&
         left.entity_class == right.entity_class && left.canonical_id == right.canonical_id &&
         left.derivation_namespace == right.derivation_namespace && left.friendly_name == right.friendly_name &&
         left.facts == right.facts && left.aliases == right.aliases && left.metadata == right.metadata &&
         same_scope(left.scope, right.scope) && left.provenance == right.provenance &&
         left.evidence_class == right.evidence_class && left.admission == right.admission &&
         left.expected_generation == right.expected_generation && left.resolution == right.resolution &&
         left.resolve_to == right.resolve_to && left.record_conflict == right.record_conflict;
}

bool same_reconcile_request(const ReconcileObservationRequest& left, const ReconcileObservationRequest& right) {
  return left.attempt == right.attempt && left.authority == right.authority &&
         left.entity_class == right.entity_class && left.facts == right.facts && left.aliases == right.aliases &&
         same_scope(left.scope, right.scope) && left.provenance == right.provenance &&
         left.resolution == right.resolution && left.resolve_to == right.resolve_to;
}

bool same_reconcile_detail(const ReconcileDetail& left, const ReconcileDetail& right) {
  return left.match == right.match && left.matched == right.matched && left.candidates == right.candidates &&
         left.conflicting_facts == right.conflicting_facts && left.conflicting_aliases == right.conflicting_aliases &&
         left.observation_fingerprint == right.observation_fingerprint;
}

/// Two records are identical when their canonical encodings are identical; the
/// encoding is the complete, ordered projection of every field.
bool same_record(const std::shared_ptr<const EntityRecord>& left, const std::shared_ptr<const EntityRecord>& right) {
  if (left == nullptr || right == nullptr) {
    return left == right;
  }
  return fabric_registry::encode_record(*left) == fabric_registry::encode_record(*right);
}

// ---------------------------------------------------------------------------
// Frame-level helpers
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> patterned_payload(std::size_t length) {
  std::vector<std::uint8_t> payload(length, 0);
  for (std::size_t index = 0; index < length; ++index) {
    payload[index] = static_cast<std::uint8_t>((index * 7u + 3u) & 0xFFu);
  }
  return payload;
}

void patch_u16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

void patch_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>((value >> (8u * index)) & 0xFFu);
  }
}

FrameDecodeResult decode_bytes(const std::vector<std::uint8_t>& bytes, const FrameLimits& limits) {
  return fabric_registry::decode_frame(bytes, limits);
}

// ---------------------------------------------------------------------------
// Payload probes
// ---------------------------------------------------------------------------

using Encoder = std::function<std::vector<std::uint8_t>()>;
using Decoder = std::function<bool(std::span<const std::uint8_t>)>;

struct CodecProbe {
  std::string name;
  Encoder encode;
  Decoder decode;
};

/// One probe per public payload decoder, each carrying a fully populated body.
std::vector<CodecProbe> all_codec_probes() {
  std::vector<CodecProbe> probes;

  {
    const HelloRequest value = [] {
      HelloRequest request;
      request.protocol_version = fabric_registry::protocol_version();
      request.client_name = "frame-client";
      return request;
    }();
    CodecProbe probe;
    probe.name = "hello request";
    probe.encode = [value] { return fabric_registry::encode_hello_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      HelloRequest out;
      std::string error;
      return fabric_registry::decode_hello_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const HelloResponse value = [] {
      HelloResponse response;
      response.accepted = true;
      response.protocol_version = fabric_registry::protocol_version();
      response.coordinator_epoch = CoordinatorEpoch(5);
      response.registry_generation = RegistryGeneration(11);
      response.server_name = "frame-coordinator";
      response.reason = "accepted";
      return response;
    }();
    CodecProbe probe;
    probe.name = "hello response";
    probe.encode = [value] { return fabric_registry::encode_hello_response(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      HelloResponse out;
      std::string error;
      return fabric_registry::decode_hello_response(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const PublisherAttachRequest value = sample_attach_request();
    CodecProbe probe;
    probe.name = "attach request";
    probe.encode = [value] { return fabric_registry::encode_attach_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      PublisherAttachRequest out;
      std::string error;
      return fabric_registry::decode_attach_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const PublisherAttachResult value = [] {
      PublisherAttachResult result;
      result.outcome = Outcome(OutcomeCode::Committed, "publisher attached");
      result.publisher = PublisherId::from_bytes(id_bytes(0x21));
      result.worker_boot = WorkerBootId::from_bytes(id_bytes(0x41));
      result.epoch = CoordinatorEpoch(2);
      result.fenced_previous = true;
      return result;
    }();
    CodecProbe probe;
    probe.name = "attach response";
    probe.encode = [value] { return fabric_registry::encode_attach_response(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      PublisherAttachResult out;
      std::string error;
      return fabric_registry::decode_attach_response(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const AuthorityClaim claim = sample_claim();
    CodecProbe probe;
    probe.name = "detach request";
    probe.encode = [claim] { return fabric_registry::encode_detach_request(claim, FenceReason::ExplicitDetach); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      AuthorityClaim out;
      FenceReason reason = FenceReason::SessionLost;
      std::string error;
      return fabric_registry::decode_detach_request(payload, out, reason, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const AuthorityClaim claim = sample_claim();
    CodecProbe probe;
    probe.name = "authority";
    probe.encode = [claim] { return fabric_registry::encode_authority(claim); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      AuthorityClaim out;
      std::string error;
      return fabric_registry::decode_authority(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const Outcome value = sample_outcome();
    CodecProbe probe;
    probe.name = "outcome";
    probe.encode = [value] { return fabric_registry::encode_outcome(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      Outcome out;
      std::string error;
      return fabric_registry::decode_outcome(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const RegisterEntityRequest value = sample_register_request();
    CodecProbe probe;
    probe.name = "register request";
    probe.encode = [value] { return fabric_registry::encode_register_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      RegisterEntityRequest out;
      std::string error;
      return fabric_registry::decode_register_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const UpdateEvidenceRequest value = [] {
      UpdateEvidenceRequest request;
      request.attempt = frtest::attempt_from("frame-evidence");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.facts = sample_facts();
      request.provenance = frtest::real_provenance("frame");
      request.evidence_class = EvidenceClass::DurableAuthority;
      request.merge_facts = true;
      return request;
    }();
    CodecProbe probe;
    probe.name = "update evidence request";
    probe.encode = [value] { return fabric_registry::encode_update_evidence_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      UpdateEvidenceRequest out;
      std::string error;
      return fabric_registry::decode_update_evidence_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const AliasMutationRequest value = [] {
      AliasMutationRequest request;
      request.attempt = frtest::attempt_from("frame-alias");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.alias = frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-1");
      return request;
    }();
    CodecProbe probe;
    probe.name = "alias request";
    probe.encode = [value] { return fabric_registry::encode_alias_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      AliasMutationRequest out;
      std::string error;
      return fabric_registry::decode_alias_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const SupersedeEntityRequest value = [] {
      SupersedeEntityRequest request;
      request.attempt = frtest::attempt_from("frame-supersede");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.successor = sample_id(EntityClass::Switch, 0xE1);
      request.reason = "replaced by a newer chassis";
      return request;
    }();
    CodecProbe probe;
    probe.name = "supersede request";
    probe.encode = [value] { return fabric_registry::encode_supersede_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      SupersedeEntityRequest out;
      std::string error;
      return fabric_registry::decode_supersede_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const RetireEntityRequest value = [] {
      RetireEntityRequest request;
      request.attempt = frtest::attempt_from("frame-retire");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.reason = "withdrawn";
      return request;
    }();
    CodecProbe probe;
    probe.name = "retire request";
    probe.encode = [value] { return fabric_registry::encode_retire_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      RetireEntityRequest out;
      std::string error;
      return fabric_registry::decode_retire_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const TombstoneEntityRequest value = [] {
      TombstoneEntityRequest request;
      request.attempt = frtest::attempt_from("frame-tombstone");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.reason = "decommissioned";
      return request;
    }();
    CodecProbe probe;
    probe.name = "tombstone request";
    probe.encode = [value] { return fabric_registry::encode_tombstone_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      TombstoneEntityRequest out;
      std::string error;
      return fabric_registry::decode_tombstone_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const RevalidateEntityRequest value = [] {
      RevalidateEntityRequest request;
      request.attempt = frtest::attempt_from("frame-revalidate");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.facts = sample_facts();
      request.provenance = frtest::real_provenance("frame");
      request.evidence_class = EvidenceClass::ProcessBound;
      request.merge_facts = true;
      return request;
    }();
    CodecProbe probe;
    probe.name = "revalidate request";
    probe.encode = [value] { return fabric_registry::encode_revalidate_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      RevalidateEntityRequest out;
      std::string error;
      return fabric_registry::decode_revalidate_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const ResolveConflictRequest value = [] {
      ResolveConflictRequest request;
      request.attempt = frtest::attempt_from("frame-conflict");
      request.authority = sample_claim();
      request.target = sample_id(EntityClass::Switch, 0xD1);
      request.expected_generation = RecordGeneration(6);
      request.resolution = fabric_registry::ConflictResolution::KeepCurrent;
      request.reason = "the current claimant keeps authority";
      return request;
    }();
    CodecProbe probe;
    probe.name = "resolve conflict request";
    probe.encode = [value] { return fabric_registry::encode_resolve_conflict_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      ResolveConflictRequest out;
      std::string error;
      return fabric_registry::decode_resolve_conflict_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const ReconcileObservationRequest value = sample_reconcile_request();
    CodecProbe probe;
    probe.name = "reconcile request";
    probe.encode = [value] { return fabric_registry::encode_reconcile_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      ReconcileObservationRequest out;
      std::string error;
      return fabric_registry::decode_reconcile_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const LookupRequest value = [] {
      LookupRequest request;
      request.target = sample_id(EntityClass::Nic, 0xF1);
      return request;
    }();
    CodecProbe probe;
    probe.name = "lookup request";
    probe.encode = [value] { return fabric_registry::encode_lookup_request(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      LookupRequest out;
      std::string error;
      return fabric_registry::decode_lookup_request(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const ReconcileDetail value = [] {
      ReconcileDetail detail;
      detail.match = MatchClass::Conflicting;
      detail.matched = sample_id(EntityClass::Switch, 0x12);
      detail.candidates = {sample_id(EntityClass::Switch, 0x22), sample_id(EntityClass::Switch, 0x32)};
      detail.conflicting_facts = {frtest::serial_fact("OTHER-SERIAL")};
      detail.conflicting_aliases = {AliasKey{AliasNamespace::ExternalCmdbId, std::string(), "asset-other"}};
      detail.observation_fingerprint = digest_value<FingerprintDigest>(0x41);
      return detail;
    }();
    CodecProbe probe;
    probe.name = "reconcile detail";
    probe.encode = [value] { return fabric_registry::encode_reconcile_detail(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      ReconcileDetail out;
      std::string error;
      return fabric_registry::decode_reconcile_detail(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const Outcome outcome = Outcome(OutcomeCode::Committed, "record found");
    const std::shared_ptr<const EntityRecord> record = std::make_shared<const EntityRecord>(sample_record());
    CodecProbe probe;
    probe.name = "lookup response with a record";
    probe.encode = [outcome, record] { return fabric_registry::encode_lookup_response(outcome, record); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      Outcome out;
      std::shared_ptr<const EntityRecord> decoded;
      std::string error;
      return fabric_registry::decode_lookup_response(payload, out, decoded, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const Outcome outcome = Outcome(OutcomeCode::NotFound, "the addressed record does not exist");
    CodecProbe probe;
    probe.name = "lookup response without a record";
    probe.encode = [outcome] { return fabric_registry::encode_lookup_response(outcome, nullptr); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      Outcome out;
      std::shared_ptr<const EntityRecord> decoded;
      std::string error;
      return fabric_registry::decode_lookup_response(payload, out, decoded, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const SnapshotSummary value = [] {
      SnapshotSummary summary;
      summary.generation = RegistryGeneration(19);
      summary.epoch = CoordinatorEpoch(4);
      summary.sequence = SnapshotSequence(3);
      summary.digest = digest_value<StateDigest>(0x51);
      summary.record_count = 12;
      summary.alias_count = 7;
      return summary;
    }();
    CodecProbe probe;
    probe.name = "snapshot summary";
    probe.encode = [value] { return fabric_registry::encode_snapshot_summary(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      SnapshotSummary out;
      std::string error;
      return fabric_registry::decode_snapshot_summary(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const StatsPayload value = [] {
      StatsPayload payload;
      payload.stats.entities = 3;
      payload.stats.current_entities = 2;
      payload.stats.discovered_entities = 1;
      payload.stats.candidate_entities = 4;
      payload.stats.revalidation_required_entities = 5;
      payload.stats.superseded_entities = 6;
      payload.stats.retired_entities = 7;
      payload.stats.tombstoned_entities = 8;
      payload.stats.conflicted_entities = 9;
      payload.stats.rejected_entities = 10;
      payload.stats.aliases = 11;
      payload.stats.indexed_aliases = 12;
      payload.stats.publishers = 13;
      payload.stats.active_publishers = 14;
      payload.stats.lineage_entries = 15;
      payload.stats.idempotency_records = 16;
      payload.stats.generation = RegistryGeneration(17);
      payload.stats.epoch = CoordinatorEpoch(18);
      return payload;
    }();
    CodecProbe probe;
    probe.name = "stats";
    probe.encode = [value] { return fabric_registry::encode_stats(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      StatsPayload out;
      std::string error;
      return fabric_registry::decode_stats(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }
  {
    const ErrorPayload value = [] {
      ErrorPayload payload;
      payload.code = OutcomeCode::IntegrityFailure;
      payload.message = "the state image failed its integrity digest";
      return payload;
    }();
    CodecProbe probe;
    probe.name = "error";
    probe.encode = [value] { return fabric_registry::encode_error(value); };
    probe.decode = [](std::span<const std::uint8_t> payload) {
      ErrorPayload out;
      std::string error;
      return fabric_registry::decode_error(payload, out, error);
    };
    probes.push_back(std::move(probe));
  }

  return probes;
}

/// A complete alias-request body whose alias namespace byte is under test.
std::vector<std::uint8_t> alias_request_body(std::uint8_t raw_namespace) {
  ByteWriter writer(96);
  const IdBytes attempt = id_bytes(0x31);
  const IdBytes publisher = id_bytes(0x10);
  const IdBytes boot = id_bytes(0x40);
  const IdBytes target = id_bytes(0x71);
  writer.raw(attempt.data(), attempt.size());
  writer.raw(publisher.data(), publisher.size());
  writer.raw(boot.data(), boot.size());
  writer.u64(7);
  writer.u8(static_cast<std::uint8_t>(EntityClass::Switch));
  writer.raw(target.data(), target.size());
  writer.u8(0);
  writer.u8(raw_namespace);
  writer.text("asset-1");
  return writer.bytes();
}

/// A complete register-request body whose first fact kind byte is under test.
std::vector<std::uint8_t> register_request_body(std::uint8_t raw_fact_kind) {
  ByteWriter writer(192);
  const IdBytes attempt = id_bytes(0x31);
  const IdBytes publisher = id_bytes(0x10);
  const IdBytes boot = id_bytes(0x40);
  writer.raw(attempt.data(), attempt.size());
  writer.raw(publisher.data(), publisher.size());
  writer.raw(boot.data(), boot.size());
  writer.u64(7);
  writer.u8(static_cast<std::uint8_t>(EntityClass::Switch));
  writer.u8(0);
  writer.text("test/frame");
  writer.text("frame-switch");
  writer.u32(1);
  writer.u8(raw_fact_kind);
  writer.text("vendor:0x15b3/product:0x1017");
  writer.text("FRAME-SERIAL-1");
  writer.u32(0);
  writer.u32(0);
  writer.u8(0);
  writer.u8(0);
  writer.u8(0);
  writer.u8(0);
  writer.u8(static_cast<std::uint8_t>(fabric_registry::ObservationSource::DeviceAgent));
  writer.u8(static_cast<std::uint8_t>(fabric_registry::ProvenanceClass::Real));
  writer.text("frame");
  writer.text("frame-test");
  writer.u8(static_cast<std::uint8_t>(EvidenceClass::DurableAuthority));
  writer.u8(static_cast<std::uint8_t>(fabric_registry::AdmissionMode::RequireCurrent));
  writer.u8(0);
  writer.u8(static_cast<std::uint8_t>(ReconcileResolution::Auto));
  writer.u8(0);
  writer.u8(0);
  return writer.bytes();
}

}  // namespace

// ---------------------------------------------------------------------------
// Frame container
// ---------------------------------------------------------------------------

FR_TEST_CASE(frame, round_trips_every_message_type_at_three_payload_lengths) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::size_t lengths[] = {0, 1, 1000};
  for (std::uint16_t raw = 1; raw <= fabric_registry::kMessageTypeCount; ++raw) {
    const MessageType type = static_cast<MessageType>(raw);
    FR_CHECK_MSG(fabric_registry::to_string(type) != std::string_view("unknown"),
                 "a defined message type has no name");
    for (const std::size_t length : lengths) {
      const std::vector<std::uint8_t> payload = patterned_payload(length);
      std::string error;
      const std::vector<std::uint8_t> frame =
          fabric_registry::encode_frame(type, 0x1234u + raw, payload, limits, error);
      FR_CHECK_MSG(error.empty(), "encode_frame refused a payload inside the bound");
      FR_CHECK_EQ(frame.size(), fabric_registry::kFrameOverheadBytes + length);

      const FrameDecodeResult result = decode_bytes(frame, limits);
      FR_CHECK_EQ(result.status, FrameDecodeStatus::Complete);
      FR_CHECK_EQ(result.consumed, frame.size());
      FR_CHECK_EQ(result.frame.type, type);
      FR_CHECK_EQ(result.frame.request_id, std::uint64_t{0x1234u + raw});
      FR_CHECK_EQ(result.frame.flags, std::uint32_t{0});
      FR_CHECK_EQ(result.frame.payload, payload);
    }
  }

  // A payload above the configured bound is refused, and nothing is produced.
  {
    const FrameLimits small = [] {
      FrameLimits limits;
      limits.max_payload_bytes = 64;
      return limits;
    }();
    const std::vector<std::uint8_t> payload = patterned_payload(65);
    std::string error;
    const std::vector<std::uint8_t> frame =
        fabric_registry::encode_frame(MessageType::Hello, 1, payload, small, error);
    FR_CHECK(frame.empty());
    FR_CHECK(!error.empty());
  }
}

FR_TEST_CASE(frame, decodes_one_byte_at_a_time_and_reports_the_consumed_size) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::vector<std::uint8_t> payload = patterned_payload(64);
  std::string error;
  const std::vector<std::uint8_t> frame =
      fabric_registry::encode_frame(MessageType::RegisterEntity, 42, payload, limits, error);
  FR_CHECK(error.empty());
  FR_CHECK(!frame.empty());

  for (std::size_t prefix = 1; prefix < frame.size(); ++prefix) {
    const FrameDecodeResult partial = decode_bytes(std::vector<std::uint8_t>(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(prefix)), limits);
    FR_CHECK_EQ(partial.status, FrameDecodeStatus::NeedMoreData);
    FR_CHECK_EQ(partial.consumed, std::size_t{0});
  }

  const FrameDecodeResult complete = decode_bytes(frame, limits);
  FR_CHECK_EQ(complete.status, FrameDecodeStatus::Complete);
  FR_CHECK_EQ(complete.consumed, frame.size());
  FR_CHECK_EQ(complete.frame.request_id, std::uint64_t{42});
  FR_CHECK_EQ(complete.frame.type, MessageType::RegisterEntity);
  FR_CHECK_EQ(complete.frame.payload, payload);
}

FR_TEST_CASE(frame, decode_rejections_carry_the_exact_status) {
  const FrameLimits limits = FrameLimits::defaults();
  const std::vector<std::uint8_t> payload = patterned_payload(32);
  std::string error;
  const std::vector<std::uint8_t> frame =
      fabric_registry::encode_frame(MessageType::Hello, 7, payload, limits, error);
  FR_CHECK(error.empty());
  FR_CHECK_EQ(decode_bytes(frame, limits).status, FrameDecodeStatus::Complete);

  // Bad magic.
  {
    std::vector<std::uint8_t> bad = frame;
    bad[0] = static_cast<std::uint8_t>('X');
    const FrameDecodeResult result = decode_bytes(bad, limits);
    FR_CHECK_EQ(result.status, FrameDecodeStatus::Malformed);
    FR_CHECK_EQ(result.consumed, std::size_t{0});
    FR_CHECK(!result.detail.empty());
  }

  // Wrong protocol version.
  {
    std::vector<std::uint8_t> bad = frame;
    patch_u16(bad, 4, static_cast<std::uint16_t>(fabric_registry::protocol_version() + 1));
    const FrameDecodeResult result = decode_bytes(bad, limits);
    FR_CHECK_EQ(result.status, FrameDecodeStatus::Malformed);
    FR_CHECK_EQ(result.consumed, std::size_t{0});
  }

  // Non-zero reserved flags.
  {
    std::vector<std::uint8_t> bad = frame;
    patch_u32(bad, 8, 1);
    const FrameDecodeResult result = decode_bytes(bad, limits);
    FR_CHECK_EQ(result.status, FrameDecodeStatus::Malformed);
  }

  // Unknown message types, including the sentinel and a value far above the
  // defined range.
  {
    std::vector<std::uint8_t> bad = frame;
    patch_u16(bad, 6, 0);
    FR_CHECK_EQ(decode_bytes(bad, limits).status, FrameDecodeStatus::UnknownMessageType);
    patch_u16(bad, 6, 60000);
    FR_CHECK_EQ(decode_bytes(bad, limits).status, FrameDecodeStatus::UnknownMessageType);
    patch_u16(bad, 6, static_cast<std::uint16_t>(fabric_registry::kMessageTypeCount + 1));
    FR_CHECK_EQ(decode_bytes(bad, limits).status, FrameDecodeStatus::UnknownMessageType);
  }

  // A declared payload length one above the configured bound.
  {
    std::vector<std::uint8_t> bad = frame;
    patch_u32(bad, 20, static_cast<std::uint32_t>(limits.max_payload_bytes + 1));
    const FrameDecodeResult result = decode_bytes(bad, limits);
    FR_CHECK_EQ(result.status, FrameDecodeStatus::PayloadTooLarge);
    FR_CHECK_EQ(result.consumed, std::size_t{0});
  }

  // A truncated tail.
  {
    const std::vector<std::uint8_t> bad(frame.begin(), frame.end() - 1);
    const FrameDecodeResult result = decode_bytes(bad, limits);
    FR_CHECK_EQ(result.status, FrameDecodeStatus::NeedMoreData);
    FR_CHECK_EQ(result.consumed, std::size_t{0});
  }

  // A flipped checksum byte.
  {
    std::vector<std::uint8_t> bad = frame;
    bad.back() = static_cast<std::uint8_t>(bad.back() ^ 0x01u);
    const FrameDecodeResult result = decode_bytes(bad, limits);
    FR_CHECK_EQ(result.status, FrameDecodeStatus::ChecksumMismatch);
    FR_CHECK_EQ(result.consumed, frame.size());
  }

  // A buffer shorter than the fixed header is never reported as malformed: it
  // is simply not a frame yet.
  {
    const std::vector<std::uint8_t> header_prefix(frame.begin(), frame.begin() + 23);
    FR_CHECK_EQ(decode_bytes(header_prefix, limits).status, FrameDecodeStatus::NeedMoreData);
  }
}

FR_TEST_CASE(frame, message_type_identity_is_exactly_one_through_twenty_seven) {
  for (std::uint32_t raw = 0; raw <= 0xFFFFu; ++raw) {
    const bool expected = raw >= 1u && raw <= fabric_registry::kMessageTypeCount;
    if (fabric_registry::is_known_message_type(static_cast<std::uint16_t>(raw)) != expected) {
      FR_FAIL("is_known_message_type disagreed with the defined range at " + std::to_string(raw));
    }
  }
  FR_CHECK(!fabric_registry::is_known_message_type(0));
  FR_CHECK(fabric_registry::is_known_message_type(1));
  FR_CHECK(fabric_registry::is_known_message_type(fabric_registry::kMessageTypeCount));
  FR_CHECK(!fabric_registry::is_known_message_type(28));
  FR_CHECK(!fabric_registry::is_known_message_type(60000));
}

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

FR_TEST_CASE(frame, hello_payloads_round_trip_including_the_empty_form) {
  {
    HelloRequest request;
    request.protocol_version = fabric_registry::protocol_version();
    request.client_name = "frame-client";
    const std::vector<std::uint8_t> payload = fabric_registry::encode_hello_request(request);
    HelloRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_hello_request(payload, decoded, error));
    FR_CHECK_EQ(decoded.protocol_version, request.protocol_version);
    FR_CHECK_EQ(decoded.client_name, request.client_name);
  }
  {
    const HelloRequest request;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_hello_request(request);
    HelloRequest decoded;
    decoded.protocol_version = 99;
    decoded.client_name = "not-empty";
    std::string error;
    FR_CHECK(fabric_registry::decode_hello_request(payload, decoded, error));
    FR_CHECK_EQ(decoded.protocol_version, std::uint16_t{0});
    FR_CHECK(decoded.client_name.empty());
  }
  {
    HelloResponse response;
    response.accepted = true;
    response.protocol_version = fabric_registry::protocol_version();
    response.coordinator_epoch = CoordinatorEpoch(5);
    response.registry_generation = RegistryGeneration(11);
    response.server_name = "frame-coordinator";
    response.reason = "accepted";
    const std::vector<std::uint8_t> payload = fabric_registry::encode_hello_response(response);
    HelloResponse decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_hello_response(payload, decoded, error));
    FR_CHECK_EQ(decoded.accepted, response.accepted);
    FR_CHECK_EQ(decoded.protocol_version, response.protocol_version);
    FR_CHECK_EQ(decoded.coordinator_epoch, response.coordinator_epoch);
    FR_CHECK_EQ(decoded.registry_generation, response.registry_generation);
    FR_CHECK_EQ(decoded.server_name, response.server_name);
    FR_CHECK_EQ(decoded.reason, response.reason);
  }
  {
    const HelloResponse response;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_hello_response(response);
    HelloResponse decoded;
    decoded.accepted = true;
    decoded.server_name = "not-empty";
    std::string error;
    FR_CHECK(fabric_registry::decode_hello_response(payload, decoded, error));
    FR_CHECK(!decoded.accepted);
    FR_CHECK_EQ(decoded.protocol_version, std::uint16_t{0});
    FR_CHECK(decoded.coordinator_epoch.is_zero());
    FR_CHECK(decoded.registry_generation.is_zero());
    FR_CHECK(decoded.server_name.empty());
    FR_CHECK(decoded.reason.empty());
  }
}

FR_TEST_CASE(frame, attach_payloads_round_trip_with_and_without_a_publisher) {
  {
    const PublisherAttachRequest request = sample_attach_request();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_attach_request(request);
    PublisherAttachRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_attach_request(payload, decoded, error));
    FR_CHECK(decoded.publisher == request.publisher);
    FR_CHECK_EQ(decoded.name, request.name);
    FR_CHECK_EQ(decoded.protocol_version, request.protocol_version);
  }
  {
    const PublisherAttachRequest request;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_attach_request(request);
    PublisherAttachRequest decoded;
    decoded.name = "not-empty";
    std::string error;
    FR_CHECK(fabric_registry::decode_attach_request(payload, decoded, error));
    FR_CHECK(decoded.publisher.is_null());
    FR_CHECK(decoded.name.empty());
    FR_CHECK_EQ(decoded.protocol_version, std::uint16_t{0});
  }
  {
    PublisherAttachResult result;
    result.outcome = Outcome(OutcomeCode::Committed, "publisher reattached with a fresh incarnation");
    result.outcome.epoch = CoordinatorEpoch(2);
    result.outcome.state_generation = RegistryGeneration(9);
    result.publisher = PublisherId::from_bytes(id_bytes(0x21));
    result.worker_boot = WorkerBootId::from_bytes(id_bytes(0x41));
    result.epoch = CoordinatorEpoch(2);
    result.fenced_previous = true;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_attach_response(result);
    PublisherAttachResult decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_attach_response(payload, decoded, error));
    FR_CHECK(same_outcome(decoded.outcome, result.outcome));
    FR_CHECK(decoded.publisher == result.publisher);
    FR_CHECK(decoded.worker_boot == result.worker_boot);
    FR_CHECK_EQ(decoded.epoch, result.epoch);
    FR_CHECK_EQ(decoded.fenced_previous, result.fenced_previous);
  }
  {
    const PublisherAttachResult result;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_attach_response(result);
    PublisherAttachResult decoded;
    decoded.fenced_previous = true;
    std::string error;
    FR_CHECK(fabric_registry::decode_attach_response(payload, decoded, error));
    FR_CHECK(same_outcome(decoded.outcome, result.outcome));
    FR_CHECK(decoded.publisher.is_null());
    FR_CHECK(decoded.worker_boot.is_null());
    FR_CHECK(decoded.epoch.is_zero());
    FR_CHECK(!decoded.fenced_previous);
  }
}

FR_TEST_CASE(frame, detach_and_authority_payloads_round_trip_for_every_fence_reason) {
  const AuthorityClaim claim = sample_claim();
  for (std::uint8_t raw = 0; raw <= static_cast<std::uint8_t>(FenceReason::Administrative); ++raw) {
    const FenceReason reason = static_cast<FenceReason>(raw);
    const std::vector<std::uint8_t> payload = fabric_registry::encode_detach_request(claim, reason);
    AuthorityClaim decoded;
    FenceReason decoded_reason = FenceReason::SessionLost;
    std::string error;
    FR_CHECK(fabric_registry::decode_detach_request(payload, decoded, decoded_reason, error));
    FR_CHECK(decoded == claim);
    FR_CHECK_EQ(decoded_reason, reason);
  }
  {
    const std::vector<std::uint8_t> payload = fabric_registry::encode_authority(claim);
    AuthorityClaim decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_authority(payload, decoded, error));
    FR_CHECK(decoded == claim);
  }
  {
    const AuthorityClaim empty;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_authority(empty);
    AuthorityClaim decoded = claim;
    std::string error;
    FR_CHECK(fabric_registry::decode_authority(payload, decoded, error));
    FR_CHECK(decoded.publisher.is_null());
    FR_CHECK(decoded.worker_boot.is_null());
    FR_CHECK(decoded.epoch.is_zero());
    FR_CHECK(!decoded.is_complete());
  }
}

FR_TEST_CASE(frame, outcome_payloads_round_trip_fully_populated_and_fully_empty) {
  {
    const Outcome outcome = sample_outcome();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_outcome(outcome);
    Outcome decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_outcome(payload, decoded, error));
    FR_CHECK_MSG(same_outcome(decoded, outcome), "a fully populated outcome did not round trip");
    FR_CHECK_EQ(decoded.steps.size(), std::size_t{2});
    FR_CHECK_EQ(decoded.related.size(), std::size_t{2});
    FR_CHECK(decoded.record.has_value());
    FR_CHECK(decoded.match.has_value());
    FR_CHECK(decoded.request_digest.has_value());
  }
  {
    const Outcome outcome = empty_outcome();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_outcome(outcome);
    Outcome decoded = sample_outcome();
    std::string error;
    FR_CHECK(fabric_registry::decode_outcome(payload, decoded, error));
    FR_CHECK_MSG(same_outcome(decoded, outcome), "an empty outcome did not round trip");
    FR_CHECK(!decoded.record.has_value());
    FR_CHECK(!decoded.record_generation.has_value());
    FR_CHECK(!decoded.evidence_generation.has_value());
    FR_CHECK(!decoded.epoch.has_value());
    FR_CHECK(!decoded.match.has_value());
    FR_CHECK(!decoded.request_digest.has_value());
    FR_CHECK(!decoded.state_generation.has_value());
    FR_CHECK(decoded.steps.empty());
    FR_CHECK(decoded.related.empty());
    FR_CHECK_EQ(decoded.code, OutcomeCode::InternalFailure);
  }
}

FR_TEST_CASE(frame, register_request_round_trips_explicit_and_derived_identities) {
  {
    const RegisterEntityRequest request = sample_register_request();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_register_request(request);
    RegisterEntityRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_register_request(payload, decoded, error));
    FR_CHECK_MSG(same_register_request(decoded, request), "a fully populated register request did not round trip");
    FR_CHECK(decoded.expected_generation.has_value());
    FR_CHECK(decoded.resolve_to.has_value());
    FR_CHECK(decoded.record_conflict);
  }
  {
    RegisterEntityRequest request;
    request.attempt = frtest::attempt_from("frame-register-derived");
    request.authority = sample_claim();
    request.entity_class = EntityClass::Nic;
    request.derivation_namespace = "test/frame-derived";
    request.friendly_name = "frame-nic";
    request.facts = {frtest::serial_fact("FRAME-SERIAL-2")};
    request.provenance = frtest::synthetic_provenance("frame");
    request.evidence_class = EvidenceClass::ProcessBound;
    request.admission = fabric_registry::AdmissionMode::AllowObservation;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_register_request(request);
    RegisterEntityRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_register_request(payload, decoded, error));
    FR_CHECK_MSG(same_register_request(decoded, request), "a minimal register request did not round trip");
    FR_CHECK(!decoded.canonical_id.has_value());
    FR_CHECK(!decoded.expected_generation.has_value());
    FR_CHECK(!decoded.resolve_to.has_value());
    FR_CHECK(!decoded.record_conflict);
    FR_CHECK(decoded.aliases.empty());
    FR_CHECK(decoded.metadata.empty());
    FR_CHECK(!decoded.scope.fabric.has_value());
    FR_CHECK(!decoded.scope.parent_device.has_value());
  }
}

FR_TEST_CASE(frame, mutation_request_payloads_round_trip_with_every_optional_field) {
  {
    const UpdateEvidenceRequest request = [] {
      UpdateEvidenceRequest value;
      value.attempt = frtest::attempt_from("frame-evidence");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.facts = sample_facts();
      value.provenance = frtest::real_provenance("frame");
      value.evidence_class = EvidenceClass::DurableAuthority;
      value.merge_facts = true;
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_update_evidence_request(request);
    UpdateEvidenceRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_update_evidence_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK(decoded.facts == request.facts);
    FR_CHECK(decoded.provenance == request.provenance);
    FR_CHECK_EQ(decoded.evidence_class, request.evidence_class);
    FR_CHECK_EQ(decoded.merge_facts, request.merge_facts);

    UpdateEvidenceRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-evidence-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD2);
    minimal.provenance = frtest::real_provenance("frame");
    minimal.evidence_class = EvidenceClass::ProcessBound;
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_update_evidence_request(minimal);
    UpdateEvidenceRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_update_evidence_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK(decoded_minimal.facts.empty());
    FR_CHECK(!decoded_minimal.merge_facts);
  }
  {
    const AliasMutationRequest request = [] {
      AliasMutationRequest value;
      value.attempt = frtest::attempt_from("frame-alias");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.alias = frtest::alias_of(AliasNamespace::DeviceInstanceId, "device-1");
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_alias_request(request);
    AliasMutationRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_alias_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK(decoded.alias == request.alias);

    AliasMutationRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-alias-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD3);
    minimal.alias = frtest::alias_of(AliasNamespace::Unspecified, std::string());
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_alias_request(minimal);
    AliasMutationRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_alias_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK_EQ(decoded_minimal.alias.alias_namespace, AliasNamespace::Unspecified);
    FR_CHECK(decoded_minimal.alias.value.empty());
  }
  {
    const SupersedeEntityRequest request = [] {
      SupersedeEntityRequest value;
      value.attempt = frtest::attempt_from("frame-supersede");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.successor = sample_id(EntityClass::Switch, 0xE1);
      value.reason = "replaced";
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_supersede_request(request);
    SupersedeEntityRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_supersede_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK(decoded.successor == request.successor);
    FR_CHECK_EQ(decoded.reason, request.reason);

    SupersedeEntityRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-supersede-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD4);
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_supersede_request(minimal);
    SupersedeEntityRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_supersede_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.successor.has_value());
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK(decoded_minimal.reason.empty());
  }
  {
    const RetireEntityRequest request = [] {
      RetireEntityRequest value;
      value.attempt = frtest::attempt_from("frame-retire");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.reason = "withdrawn";
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_retire_request(request);
    RetireEntityRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_retire_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK_EQ(decoded.reason, request.reason);

    RetireEntityRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-retire-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD5);
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_retire_request(minimal);
    RetireEntityRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_retire_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK(decoded_minimal.reason.empty());
  }
  {
    const TombstoneEntityRequest request = [] {
      TombstoneEntityRequest value;
      value.attempt = frtest::attempt_from("frame-tombstone");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.reason = "decommissioned";
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_tombstone_request(request);
    TombstoneEntityRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_tombstone_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK_EQ(decoded.reason, request.reason);

    TombstoneEntityRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-tombstone-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD6);
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_tombstone_request(minimal);
    TombstoneEntityRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_tombstone_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK(decoded_minimal.reason.empty());
  }
  {
    const RevalidateEntityRequest request = [] {
      RevalidateEntityRequest value;
      value.attempt = frtest::attempt_from("frame-revalidate");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.facts = sample_facts();
      value.provenance = frtest::real_provenance("frame");
      value.evidence_class = EvidenceClass::ProcessBound;
      value.merge_facts = true;
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_revalidate_request(request);
    RevalidateEntityRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_revalidate_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK(decoded.facts == request.facts);
    FR_CHECK(decoded.provenance == request.provenance);
    FR_CHECK_EQ(decoded.evidence_class, request.evidence_class);
    FR_CHECK_EQ(decoded.merge_facts, request.merge_facts);

    RevalidateEntityRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-revalidate-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD7);
    minimal.provenance = frtest::real_provenance("frame");
    minimal.evidence_class = EvidenceClass::ProcessBound;
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_revalidate_request(minimal);
    RevalidateEntityRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_revalidate_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK(decoded_minimal.facts.empty());
    FR_CHECK(!decoded_minimal.merge_facts);
  }
  {
    const ResolveConflictRequest request = [] {
      ResolveConflictRequest value;
      value.attempt = frtest::attempt_from("frame-conflict");
      value.authority = sample_claim();
      value.target = sample_id(EntityClass::Switch, 0xD1);
      value.expected_generation = RecordGeneration(6);
      value.resolution = fabric_registry::ConflictResolution::Retire;
      value.reason = "the conflicting claim wins";
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_resolve_conflict_request(request);
    ResolveConflictRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_resolve_conflict_request(payload, decoded, error));
    FR_CHECK(decoded.attempt == request.attempt);
    FR_CHECK(decoded.authority == request.authority);
    FR_CHECK(decoded.target == request.target);
    FR_CHECK(decoded.expected_generation == request.expected_generation);
    FR_CHECK_EQ(decoded.resolution, request.resolution);
    FR_CHECK_EQ(decoded.reason, request.reason);

    ResolveConflictRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-conflict-min");
    minimal.authority = sample_claim();
    minimal.target = sample_id(EntityClass::Switch, 0xD8);
    minimal.resolution = fabric_registry::ConflictResolution::Reject;
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_resolve_conflict_request(minimal);
    ResolveConflictRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_resolve_conflict_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(!decoded_minimal.expected_generation.has_value());
    FR_CHECK(decoded_minimal.reason.empty());
  }
}

FR_TEST_CASE(frame, reconcile_lookup_and_detail_payloads_round_trip_exactly) {
  {
    const ReconcileObservationRequest request = sample_reconcile_request();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_reconcile_request(request);
    ReconcileObservationRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_reconcile_request(payload, decoded, error));
    FR_CHECK_MSG(same_reconcile_request(decoded, request), "a reconcile request did not round trip");

    ReconcileObservationRequest minimal;
    minimal.attempt = frtest::attempt_from("frame-reconcile-min");
    minimal.authority = sample_claim();
    minimal.entity_class = EntityClass::Host;
    minimal.provenance = frtest::synthetic_provenance("frame");
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_reconcile_request(minimal);
    ReconcileObservationRequest decoded_minimal;
    FR_CHECK(fabric_registry::decode_reconcile_request(minimal_payload, decoded_minimal, error));
    FR_CHECK(decoded_minimal.facts.empty());
    FR_CHECK(decoded_minimal.aliases.empty());
    FR_CHECK(!decoded_minimal.resolve_to.has_value());
    FR_CHECK(!decoded_minimal.scope.fabric.has_value());
  }
  {
    const LookupRequest request = [] {
      LookupRequest value;
      value.target = sample_id(EntityClass::Nic, 0xF1);
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_lookup_request(request);
    LookupRequest decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_lookup_request(payload, decoded, error));
    FR_CHECK(decoded.target == request.target);
    FR_CHECK_EQ(decoded.target.entity_class(), EntityClass::Nic);
  }
  {
    const ReconcileDetail detail = [] {
      ReconcileDetail value;
      value.match = MatchClass::Ambiguous;
      value.matched = sample_id(EntityClass::Switch, 0x12);
      value.candidates = {sample_id(EntityClass::Switch, 0x22), sample_id(EntityClass::Switch, 0x32)};
      value.conflicting_facts = {frtest::serial_fact("OTHER-SERIAL")};
      value.conflicting_aliases = {AliasKey{AliasNamespace::ExternalCmdbId, std::string(), "asset-other"}};
      value.observation_fingerprint = digest_value<FingerprintDigest>(0x41);
      return value;
    }();
    const std::vector<std::uint8_t> payload = fabric_registry::encode_reconcile_detail(detail);
    ReconcileDetail decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_reconcile_detail(payload, decoded, error));
    FR_CHECK_MSG(same_reconcile_detail(decoded, detail), "a reconcile detail did not round trip");

    const ReconcileDetail minimal;
    const std::vector<std::uint8_t> minimal_payload = fabric_registry::encode_reconcile_detail(minimal);
    ReconcileDetail decoded_minimal = detail;
    FR_CHECK(fabric_registry::decode_reconcile_detail(minimal_payload, decoded_minimal, error));
    FR_CHECK_MSG(same_reconcile_detail(decoded_minimal, minimal), "an empty reconcile detail did not round trip");
    FR_CHECK(!decoded_minimal.matched.has_value());
    FR_CHECK(decoded_minimal.candidates.empty());
    FR_CHECK(decoded_minimal.conflicting_facts.empty());
    FR_CHECK(decoded_minimal.conflicting_aliases.empty());
    FR_CHECK_EQ(decoded_minimal.match, MatchClass::NoMatch);
  }
}

FR_TEST_CASE(frame, lookup_response_round_trips_with_and_without_a_record) {
  const EntityRecord record = sample_record();
  const std::shared_ptr<const EntityRecord> shared = std::make_shared<const EntityRecord>(record);
  const Outcome outcome = [] {
    Outcome value(OutcomeCode::Committed, "record found");
    value.record = sample_id(EntityClass::Switch, 0xA1);
    value.record_generation = RecordGeneration(4);
    value.match = MatchClass::ExactCanonical;
    return value;
  }();
  {
    const std::vector<std::uint8_t> payload = fabric_registry::encode_lookup_response(outcome, shared);
    Outcome decoded_outcome;
    std::shared_ptr<const EntityRecord> decoded_record;
    std::string error;
    FR_CHECK(fabric_registry::decode_lookup_response(payload, decoded_outcome, decoded_record, error));
    FR_CHECK(same_outcome(decoded_outcome, outcome));
    FR_CHECK(decoded_record != nullptr);
    FR_CHECK_MSG(same_record(decoded_record, shared), "the record carried by a lookup response did not round trip");
    FR_CHECK(decoded_record->id == record.id);
    FR_CHECK(decoded_record->record_generation == record.record_generation);
    FR_CHECK_EQ(decoded_record->lifecycle, record.lifecycle);
    FR_CHECK(decoded_record->facts == record.facts);
    FR_CHECK(decoded_record->aliases == record.aliases);
    FR_CHECK(decoded_record->metadata == record.metadata);
    FR_CHECK(decoded_record->evidence.valid);
  }
  {
    const Outcome missing(OutcomeCode::NotFound, "the addressed record does not exist");
    const std::vector<std::uint8_t> payload = fabric_registry::encode_lookup_response(missing, nullptr);
    Outcome decoded_outcome;
    std::shared_ptr<const EntityRecord> decoded_record = shared;
    std::string error;
    FR_CHECK(fabric_registry::decode_lookup_response(payload, decoded_outcome, decoded_record, error));
    FR_CHECK(same_outcome(decoded_outcome, missing));
    FR_CHECK_MSG(decoded_record == nullptr, "a lookup response without a record produced a record");
  }
}

FR_TEST_CASE(frame, snapshot_stats_and_error_payloads_round_trip_exactly) {
  {
    SnapshotSummary summary;
    summary.generation = RegistryGeneration(19);
    summary.epoch = CoordinatorEpoch(4);
    summary.sequence = SnapshotSequence(3);
    summary.digest = digest_value<StateDigest>(0x51);
    summary.record_count = 12;
    summary.alias_count = 7;
    const std::vector<std::uint8_t> payload = fabric_registry::encode_snapshot_summary(summary);
    SnapshotSummary decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_snapshot_summary(payload, decoded, error));
    FR_CHECK_EQ(decoded.generation, summary.generation);
    FR_CHECK_EQ(decoded.epoch, summary.epoch);
    FR_CHECK_EQ(decoded.sequence, summary.sequence);
    FR_CHECK_EQ(decoded.digest, summary.digest);
    FR_CHECK_EQ(decoded.record_count, summary.record_count);
    FR_CHECK_EQ(decoded.alias_count, summary.alias_count);

    const SnapshotSummary empty;
    const std::vector<std::uint8_t> empty_payload = fabric_registry::encode_snapshot_summary(empty);
    SnapshotSummary decoded_empty = summary;
    FR_CHECK(fabric_registry::decode_snapshot_summary(empty_payload, decoded_empty, error));
    FR_CHECK(decoded_empty.generation.is_zero());
    FR_CHECK(decoded_empty.epoch.is_zero());
    FR_CHECK(decoded_empty.sequence.is_zero());
    FR_CHECK(decoded_empty.digest.is_null());
    FR_CHECK_EQ(decoded_empty.record_count, std::uint64_t{0});
    FR_CHECK_EQ(decoded_empty.alias_count, std::uint64_t{0});
  }
  {
    StatsPayload stats;
    stats.stats.entities = 3;
    stats.stats.current_entities = 2;
    stats.stats.discovered_entities = 1;
    stats.stats.candidate_entities = 4;
    stats.stats.revalidation_required_entities = 5;
    stats.stats.superseded_entities = 6;
    stats.stats.retired_entities = 7;
    stats.stats.tombstoned_entities = 8;
    stats.stats.conflicted_entities = 9;
    stats.stats.rejected_entities = 10;
    stats.stats.aliases = 11;
    stats.stats.indexed_aliases = 12;
    stats.stats.publishers = 13;
    stats.stats.active_publishers = 14;
    stats.stats.lineage_entries = 15;
    stats.stats.idempotency_records = 16;
    stats.stats.generation = RegistryGeneration(17);
    stats.stats.epoch = CoordinatorEpoch(18);
    const std::vector<std::uint8_t> payload = fabric_registry::encode_stats(stats);
    StatsPayload decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_stats(payload, decoded, error));
    FR_CHECK_MSG(same_stats(decoded.stats, stats.stats), "a stats payload did not round trip");

    const StatsPayload empty;
    const std::vector<std::uint8_t> empty_payload = fabric_registry::encode_stats(empty);
    StatsPayload decoded_empty;
    decoded_empty.stats.entities = 99;
    FR_CHECK(fabric_registry::decode_stats(empty_payload, decoded_empty, error));
    FR_CHECK(same_stats(decoded_empty.stats, RegistryStats{}));
  }
  {
    ErrorPayload error_payload;
    error_payload.code = OutcomeCode::IntegrityFailure;
    error_payload.message = "the state image failed its integrity digest";
    const std::vector<std::uint8_t> payload = fabric_registry::encode_error(error_payload);
    ErrorPayload decoded;
    std::string error;
    FR_CHECK(fabric_registry::decode_error(payload, decoded, error));
    FR_CHECK_EQ(decoded.code, error_payload.code);
    FR_CHECK_EQ(decoded.message, error_payload.message);

    const ErrorPayload empty;
    const std::vector<std::uint8_t> empty_payload = fabric_registry::encode_error(empty);
    ErrorPayload decoded_empty;
    decoded_empty.code = OutcomeCode::Committed;
    decoded_empty.message = "not-empty";
    FR_CHECK(fabric_registry::decode_error(empty_payload, decoded_empty, error));
    FR_CHECK_EQ(decoded_empty.code, OutcomeCode::InternalFailure);
    FR_CHECK(decoded_empty.message.empty());
  }
}

FR_TEST_CASE(frame, every_decoder_rejects_a_trailing_extra_byte) {
  for (const CodecProbe& probe : all_codec_probes()) {
    const std::vector<std::uint8_t> payload = probe.encode();
    FR_CHECK_MSG(!payload.empty(), "a codec produced an empty payload: " + probe.name);
    FR_CHECK_MSG(probe.decode(payload), "a codec rejected its own encoding: " + probe.name);

    std::vector<std::uint8_t> extended = payload;
    extended.push_back(0x5Au);
    FR_CHECK_MSG(!probe.decode(extended), "a decoder accepted a payload with a trailing byte: " + probe.name);
  }
}

FR_TEST_CASE(frame, every_decoder_rejects_a_truncated_payload) {
  for (const CodecProbe& probe : all_codec_probes()) {
    const std::vector<std::uint8_t> payload = probe.encode();
    FR_CHECK_MSG(probe.decode(payload), "a codec rejected its own encoding: " + probe.name);
    const std::vector<std::uint8_t> truncated(payload.begin(), payload.end() - 1);
    FR_CHECK_MSG(!probe.decode(truncated), "a decoder accepted a truncated payload: " + probe.name);
  }
}

FR_TEST_CASE(frame, decoders_reject_out_of_range_enum_bytes) {
  std::string error;

  // Outcome code 200, through the error payload and through an outcome.
  {
    const ErrorPayload value{OutcomeCode::Committed, "ok"};
    std::vector<std::uint8_t> payload = fabric_registry::encode_error(value);
    ErrorPayload out;
    FR_CHECK(fabric_registry::decode_error(payload, out, error));
    payload[0] = 200;
    FR_CHECK_MSG(!fabric_registry::decode_error(payload, out, error), "an outcome code of 200 was accepted");

    std::vector<std::uint8_t> outcome_payload = fabric_registry::encode_outcome(Outcome(OutcomeCode::Committed, "ok"));
    Outcome decoded;
    FR_CHECK(fabric_registry::decode_outcome(outcome_payload, decoded, error));
    outcome_payload[0] = 200;
    FR_CHECK_MSG(!fabric_registry::decode_outcome(outcome_payload, decoded, error),
                 "an outcome code of 200 was accepted by the outcome decoder");
  }

  // Entity class 200, through the lookup request (the class is its first byte).
  {
    LookupRequest request;
    request.target = sample_id(EntityClass::Switch, 0x61);
    std::vector<std::uint8_t> payload = fabric_registry::encode_lookup_request(request);
    LookupRequest out;
    FR_CHECK(fabric_registry::decode_lookup_request(payload, out, error));
    payload[0] = 200;
    FR_CHECK_MSG(!fabric_registry::decode_lookup_request(payload, out, error), "an entity class of 200 was accepted");
  }

  // Alias namespace 200, through a complete alias request body.
  {
    AliasMutationRequest out;
    FR_CHECK(fabric_registry::decode_alias_request(alias_request_body(static_cast<std::uint8_t>(AliasNamespace::ExternalCmdbId)), out, error));
    FR_CHECK_MSG(!fabric_registry::decode_alias_request(alias_request_body(200), out, error),
                 "an alias namespace of 200 was accepted");
  }

  // Fact kind 200, through a complete register request body.
  {
    RegisterEntityRequest out;
    FR_CHECK(fabric_registry::decode_register_request(
        register_request_body(static_cast<std::uint8_t>(IdentityFactKind::SerialNumber)), out, error));
    FR_CHECK_MSG(!fabric_registry::decode_register_request(register_request_body(200), out, error),
                 "a fact kind of 200 was accepted");
  }

  // Lifecycle 200, through the record codec (the lifecycle is the byte after the
  // entity class and the sixteen identifier bytes).
  {
    const std::vector<std::uint8_t> encoded = fabric_registry::encode_record(sample_record());
    FR_CHECK(encoded.size() > 17);
    EntityRecord out;
    FR_CHECK(fabric_registry::decode_record(encoded, RegistryLimits{}, out, error));
    std::vector<std::uint8_t> payload = encoded;
    payload[17] = 200;
    FR_CHECK_MSG(!fabric_registry::decode_record(payload, RegistryLimits{}, out, error),
                 "a lifecycle of 200 was accepted");
  }
}

FR_TEST_CASE(frame, register_request_rejects_a_fact_count_above_the_bound) {
  RegisterEntityRequest request;
  request.attempt = frtest::attempt_from("frame-many-facts");
  request.authority = sample_claim();
  request.entity_class = EntityClass::Switch;
  request.derivation_namespace = "test/frame";
  request.provenance = frtest::real_provenance("frame");
  request.evidence_class = EvidenceClass::DurableAuthority;

  const std::size_t bound = fabric_registry::hard_limits::kMaxFactsPerEntity;
  for (std::size_t index = 0; index < bound; ++index) {
    request.facts.push_back(frtest::fact_of(IdentityFactKind::DeviceModel, "model-" + std::to_string(index)));
  }
  RegisterEntityRequest decoded;
  std::string error;
  const std::vector<std::uint8_t> at_bound = fabric_registry::encode_register_request(request);
  FR_CHECK_MSG(fabric_registry::decode_register_request(at_bound, decoded, error),
               "a fact set exactly at the bound was rejected");
  FR_CHECK_EQ(decoded.facts.size(), bound);

  request.facts.push_back(frtest::fact_of(IdentityFactKind::DeviceModel, "model-overflow"));
  const std::vector<std::uint8_t> over_bound = fabric_registry::encode_register_request(request);
  FR_CHECK_MSG(!fabric_registry::decode_register_request(over_bound, decoded, error),
               "a fact set above the bound was accepted");
  FR_CHECK(error.find("bound") != std::string::npos);
}

int main(int argc, char** argv) { return frtest::run_all(argc, argv); }
