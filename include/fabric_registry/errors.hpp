// Fabric Registry — structured outcomes and deterministic explanations.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// No public operation returns bare bool. Every mutation and every lookup
// returns an Outcome carrying a specific code, the identity it concerns, the
// generations involved, the match class that was decided and an ordered list of
// explanation steps naming the exact stage, field and value that produced the
// result.

#ifndef FABRIC_REGISTRY_ERRORS_HPP
#define FABRIC_REGISTRY_ERRORS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/export.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/ids.hpp"

namespace fabric_registry {

/// The specific, stage-bearing result of an operation.
enum class OutcomeCode : std::uint8_t {
  /// The mutation was applied and produced a new authorized generation.
  Committed = 0,
  /// The exact same already-committed request was replayed under still-valid
  /// semantics. No new generation was produced.
  Idempotent = 1,
  /// The request expected a record generation that is no longer current.
  StaleGeneration = 2,
  /// The publisher is not known to this registry, or is not permitted.
  StaleAuthority = 3,
  /// The request carries a coordinator epoch that is no longer current.
  StaleEpoch = 4,
  /// The request carries a worker incarnation that has been superseded.
  StaleWorkerBoot = 5,
  /// The publisher has been fenced and may not mutate state until it reattaches
  /// with a fresh incarnation.
  FencedPublisher = 6,
  /// The identity described already exists and the request did not address it.
  DuplicateIdentity = 7,
  /// A unique alias is already bound to a different record.
  AliasConflict = 8,
  /// Strong facts contradict an existing record.
  IdentityConflict = 9,
  /// More than one record matched with equal strength. Never resolved silently.
  AmbiguousMatch = 10,
  /// The same registration attempt id was reused with different content.
  ConflictingReplay = 11,
  /// The evidence is missing, malformed, or categorically unusable.
  InvalidEvidence = 12,
  /// The record exists but its evidence is not current; an explicit
  /// revalidation is required before it can be treated as current again.
  RevalidationRequired = 13,
  /// The record is retired and cannot be mutated back into authority.
  Retired = 14,
  /// The record was superseded by a newer identity.
  Superseded = 15,
  /// The identity is tombstoned and permanently closed.
  Tombstoned = 16,
  /// The requested lifecycle transition is not legal from the current state.
  IllegalTransition = 17,
  /// A conflict is recorded and must be resolved explicitly before mutation.
  ConflictUnresolved = 18,
  /// The request is structurally invalid.
  MalformedRequest = 19,
  /// A configured resource bound would be exceeded.
  ResourceLimit = 20,
  /// Registry policy rejects the request.
  PolicyRejected = 21,
  /// The addressed record does not exist.
  NotFound = 22,
  /// The addressed record exists but is not current.
  NotCurrent = 23,
  /// The capability cannot be provided truthfully in this build or environment.
  UnsupportedCapability = 24,
  /// The durable state could not be written or read back.
  PersistenceFailure = 25,
  /// A transport operation failed.
  TransportFailure = 26,
  /// A peer violated the framing or message protocol.
  ProtocolViolation = 27,
  /// An integrity digest did not validate.
  IntegrityFailure = 28,
  /// An unexpected internal failure. Never used to hide a known condition.
  InternalFailure = 29,
  /// The operation requires an authority claim and none was supplied.
  NoAuthority = 30,
  /// An existing record matched the observation only weakly. The registry did
  /// not commit anything; an explicit resolution or stronger evidence is
  /// required.
  ProbableMatch = 31,
};

inline constexpr std::uint8_t kOutcomeCodeCount = 32;

FABRIC_REGISTRY_API std::string_view to_string(OutcomeCode value) noexcept;

/// True for outcomes that represent a durable, authorized state change.
FABRIC_REGISTRY_API bool is_commit(OutcomeCode value) noexcept;

/// True for outcomes that mean "this request lost to a newer one".
FABRIC_REGISTRY_API bool is_stale(OutcomeCode value) noexcept;

/// True for outcomes that mean "the identity is permanently closed".
FABRIC_REGISTRY_API bool is_closed(OutcomeCode value) noexcept;

/// True when the caller may usefully retry after obtaining fresh state.
FABRIC_REGISTRY_API bool is_retryable_after_refresh(OutcomeCode value) noexcept;

/// One ordered step of a deterministic explanation.
struct ExplanationStep {
  /// Pipeline stage, e.g. "validate", "authority", "reconcile", "generation",
  /// "conflict", "commit", "persist".
  std::string stage;
  /// The specific field the stage examined, when it examined one.
  std::string field;
  /// The value observed, rendered canonically.
  std::string value;
  /// What was decided and why.
  std::string detail;

  friend bool operator==(const ExplanationStep&, const ExplanationStep&) = default;
};

/// The result of an operation.
struct FABRIC_REGISTRY_API Outcome {
  OutcomeCode code{OutcomeCode::InternalFailure};
  /// Short human-readable summary. Deterministic for a given set of inputs.
  std::string message;

  /// Canonical identity the outcome concerns, when there is one.
  std::optional<CanonicalId> record;
  /// Generation of the record after the operation (for commits) or before it
  /// (for rejections).
  std::optional<RecordGeneration> record_generation;
  std::optional<EvidenceGeneration> evidence_generation;
  std::optional<CoordinatorEpoch> epoch;
  std::optional<MatchClass> match;
  /// Digest of the request that produced this outcome. Present on every
  /// mutation outcome so an idempotent replay can be recognized.
  std::optional<RequestDigest> request_digest;
  /// Registry generation after the operation.
  std::optional<RegistryGeneration> state_generation;
  /// Ordered explanation steps.
  std::vector<ExplanationStep> steps;
  /// Records affected by a batch or by a supersession.
  std::vector<CanonicalId> related;

  Outcome() = default;
  Outcome(OutcomeCode code_in, std::string message_in) : code(code_in), message(std::move(message_in)) {}

  static Outcome make(OutcomeCode code_in, std::string message_in) { return Outcome(code_in, std::move(message_in)); }

  /// True only for Committed.
  bool committed() const noexcept { return code == OutcomeCode::Committed; }
  /// True for Committed and Idempotent: the caller's intent is satisfied.
  bool succeeded() const noexcept { return is_commit(code) || code == OutcomeCode::Idempotent; }
  bool stale() const noexcept { return is_stale(code); }

  Outcome& step(std::string stage, std::string detail);
  Outcome& field_step(std::string stage, std::string field, std::string value, std::string detail);
  Outcome& with_record(const CanonicalId& id);
  Outcome& with_generation(RecordGeneration generation);

  /// Deterministic multi-line rendering used by the CLI, the examples and the
  /// tests.
  std::string render() const;
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_ERRORS_HPP
