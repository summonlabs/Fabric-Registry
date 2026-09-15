// Fabric Registry — structured outcomes and deterministic explanations.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/errors.hpp"

namespace fabric_registry {

std::string_view to_string(OutcomeCode value) noexcept {
  switch (value) {
    case OutcomeCode::Committed:
      return "committed";
    case OutcomeCode::Idempotent:
      return "idempotent";
    case OutcomeCode::StaleGeneration:
      return "stale-generation";
    case OutcomeCode::StaleAuthority:
      return "stale-authority";
    case OutcomeCode::StaleEpoch:
      return "stale-epoch";
    case OutcomeCode::StaleWorkerBoot:
      return "stale-worker-boot";
    case OutcomeCode::FencedPublisher:
      return "fenced-publisher";
    case OutcomeCode::DuplicateIdentity:
      return "duplicate-identity";
    case OutcomeCode::AliasConflict:
      return "alias-conflict";
    case OutcomeCode::IdentityConflict:
      return "identity-conflict";
    case OutcomeCode::AmbiguousMatch:
      return "ambiguous-match";
    case OutcomeCode::ConflictingReplay:
      return "conflicting-replay";
    case OutcomeCode::InvalidEvidence:
      return "invalid-evidence";
    case OutcomeCode::RevalidationRequired:
      return "revalidation-required";
    case OutcomeCode::Retired:
      return "retired";
    case OutcomeCode::Superseded:
      return "superseded";
    case OutcomeCode::Tombstoned:
      return "tombstoned";
    case OutcomeCode::IllegalTransition:
      return "illegal-transition";
    case OutcomeCode::ConflictUnresolved:
      return "conflict-unresolved";
    case OutcomeCode::MalformedRequest:
      return "malformed-request";
    case OutcomeCode::ResourceLimit:
      return "resource-limit";
    case OutcomeCode::PolicyRejected:
      return "policy-rejected";
    case OutcomeCode::NotFound:
      return "not-found";
    case OutcomeCode::NotCurrent:
      return "not-current";
    case OutcomeCode::UnsupportedCapability:
      return "unsupported-capability";
    case OutcomeCode::PersistenceFailure:
      return "persistence-failure";
    case OutcomeCode::TransportFailure:
      return "transport-failure";
    case OutcomeCode::ProtocolViolation:
      return "protocol-violation";
    case OutcomeCode::IntegrityFailure:
      return "integrity-failure";
    case OutcomeCode::InternalFailure:
      return "internal-failure";
    case OutcomeCode::NoAuthority:
      return "no-authority";
    case OutcomeCode::ProbableMatch:
      return "probable-match";
  }
  return "unknown";
}

bool is_commit(OutcomeCode value) noexcept {
  return value == OutcomeCode::Committed;
}

bool is_stale(OutcomeCode value) noexcept {
  switch (value) {
    case OutcomeCode::StaleGeneration:
    case OutcomeCode::StaleAuthority:
    case OutcomeCode::StaleEpoch:
    case OutcomeCode::StaleWorkerBoot:
    case OutcomeCode::FencedPublisher:
    case OutcomeCode::ConflictingReplay:
      return true;
    default:
      return false;
  }
}

bool is_closed(OutcomeCode value) noexcept {
  switch (value) {
    case OutcomeCode::Retired:
    case OutcomeCode::Superseded:
    case OutcomeCode::Tombstoned:
      return true;
    default:
      return false;
  }
}

bool is_retryable_after_refresh(OutcomeCode value) noexcept {
  switch (value) {
    case OutcomeCode::StaleGeneration:
    case OutcomeCode::RevalidationRequired:
    case OutcomeCode::ConflictUnresolved:
    case OutcomeCode::AmbiguousMatch:
    case OutcomeCode::ProbableMatch:
      return true;
    default:
      return false;
  }
}

Outcome& Outcome::step(std::string stage_name, std::string detail) {
  ExplanationStep entry;
  entry.stage = std::move(stage_name);
  entry.detail = std::move(detail);
  steps.push_back(std::move(entry));
  return *this;
}

Outcome& Outcome::field_step(std::string stage_name, std::string field, std::string value, std::string detail) {
  ExplanationStep entry;
  entry.stage = std::move(stage_name);
  entry.field = std::move(field);
  entry.value = std::move(value);
  entry.detail = std::move(detail);
  steps.push_back(std::move(entry));
  return *this;
}

Outcome& Outcome::with_record(const CanonicalId& id) {
  record = id;
  return *this;
}

Outcome& Outcome::with_generation(RecordGeneration generation) {
  record_generation = generation;
  return *this;
}

std::string Outcome::render() const {
  std::string out;
  out += "outcome: ";
  out += to_string(code);
  out += '\n';
  out += "message: ";
  out += message;
  out += '\n';
  if (record.has_value()) {
    out += "record: ";
    out += record->to_string();
    out += '\n';
  }
  if (record_generation.has_value()) {
    out += "record-generation: ";
    out += record_generation->to_string();
    out += '\n';
  }
  if (evidence_generation.has_value()) {
    out += "evidence-generation: ";
    out += evidence_generation->to_string();
    out += '\n';
  }
  if (epoch.has_value()) {
    out += "coordinator-epoch: ";
    out += epoch->to_string();
    out += '\n';
  }
  if (match.has_value()) {
    out += "match: ";
    out += to_string(*match);
    out += '\n';
  }
  if (request_digest.has_value()) {
    out += "request-digest: ";
    out += request_digest->to_string();
    out += '\n';
  }
  if (state_generation.has_value()) {
    out += "state-generation: ";
    out += state_generation->to_string();
    out += '\n';
  }
  if (!related.empty()) {
    out += "related:";
    for (const CanonicalId& id : related) {
      out += ' ';
      out += id.to_string();
    }
    out += '\n';
  }
  out += "steps:";
  out += '\n';
  for (const ExplanationStep& entry : steps) {
    out += "  - stage=";
    out += entry.stage;
    if (!entry.field.empty()) {
      out += " field=";
      out += entry.field;
    }
    if (!entry.value.empty()) {
      out += " value=";
      out += entry.value;
    }
    out += " :: ";
    out += entry.detail;
    out += '\n';
  }
  return out;
}

} // namespace fabric_registry
