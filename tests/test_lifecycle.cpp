// Fabric Registry — lifecycle, reason and outcome proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The lifecycle machine and the outcome classification are the two places where
// the runtime makes a promise to every caller. Both are exhaustive here: all
// nine lifecycle states, all 81 transitions and all 32 outcome codes are
// compared against an expectation table written out in full in this file, so a
// change to either contract cannot pass unnoticed.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "fabric_registry/entity.hpp"
#include "fabric_registry/errors.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::Lifecycle;
using fabric_registry::OutcomeCode;
using fabric_registry::ReasonCode;

/// The stable wire names, in enumerator order.
constexpr std::string_view kLifecycleNames[fabric_registry::kLifecycleCount] = {
    "discovered", "candidate", "current", "revalidation-required", "superseded",
    "retired",    "tombstoned", "conflicted", "rejected"};

/// True only for states with no legal transition out of them.
constexpr bool kTerminalLifecycle[fabric_registry::kLifecycleCount] = {
    false, false, false, false, false, false, true, false, true};

/// True only for the one state that may be treated as authoritative now.
constexpr bool kHoldsCurrentAuthority[fabric_registry::kLifecycleCount] = {
    false, false, true, false, false, false, false, false, false};

/// The complete transition table, in enumerator order:
/// 0 Discovered, 1 Candidate, 2 Current, 3 RevalidationRequired, 4 Superseded,
/// 5 Retired, 6 Tombstoned, 7 Conflicted, 8 Rejected.
///
///   Discovered           -> Candidate, Conflicted, Rejected
///   Candidate            -> Current, Conflicted, Rejected
///   Current              -> RevalidationRequired, Superseded, Retired, Conflicted
///   RevalidationRequired -> Current, Superseded, Retired, Conflicted
///   Conflicted           -> Current, Retired, Rejected
///   Superseded           -> Retired, Tombstoned
///   Retired              -> Tombstoned
///   Tombstoned           -> (none)
///   Rejected             -> (none)
///
/// A transition to the same state is not a transition and is never allowed.
constexpr bool kTransitionTable[fabric_registry::kLifecycleCount][fabric_registry::kLifecycleCount] = {
    // to:           Disc   Cand   Curr   Reva   Supe   Reti   Tomb   Conf   Reje
    /* Discovered */ {false, true,  false, false, false, false, false, true,  true},
    /* Candidate  */ {false, false, true,  false, false, false, false, true,  true},
    /* Current    */ {false, false, false, true,  true,  true,  false, true,  false},
    /* Revalidati */ {false, false, true,  false, true,  true,  false, true,  false},
    /* Superseded */ {false, false, false, false, false, true,  true,  false, false},
    /* Retired    */ {false, false, false, false, false, false, true,  false, false},
    /* Tombstoned */ {false, false, false, false, false, false, false, false, false},
    /* Conflicted */ {false, false, true,  false, false, true,  false, false, true},
    /* Rejected   */ {false, false, false, false, false, false, false, false, false},
};

constexpr std::string_view kReasonNames[fabric_registry::kReasonCodeCount] = {
    "registration",     "evidence-update",  "alias-attach",     "alias-detach",   "revalidation",
    "supersede",        "retire",           "tombstone",        "conflict-raised", "conflict-resolved",
    "promotion",        "recovery-demotion", "publisher-fenced", "epoch-advance"};

struct OutcomeExpectation {
  OutcomeCode code;
  bool commit;
  bool stale;
  bool closed;
  bool retryable_after_refresh;
};

/// One row per outcome code, in enumerator order (the loop below asserts that
/// the order matches static_cast<std::uint8_t>(code)).
constexpr OutcomeExpectation kOutcomeExpectations[fabric_registry::kOutcomeCodeCount] = {
    {OutcomeCode::Committed, true, false, false, false},
    {OutcomeCode::Idempotent, false, false, false, false},
    {OutcomeCode::StaleGeneration, false, true, false, true},
    {OutcomeCode::StaleAuthority, false, true, false, false},
    {OutcomeCode::StaleEpoch, false, true, false, false},
    {OutcomeCode::StaleWorkerBoot, false, true, false, false},
    {OutcomeCode::FencedPublisher, false, true, false, false},
    {OutcomeCode::DuplicateIdentity, false, false, false, false},
    {OutcomeCode::AliasConflict, false, false, false, false},
    {OutcomeCode::IdentityConflict, false, false, false, false},
    {OutcomeCode::AmbiguousMatch, false, false, false, true},
    {OutcomeCode::ConflictingReplay, false, true, false, false},
    {OutcomeCode::InvalidEvidence, false, false, false, false},
    {OutcomeCode::RevalidationRequired, false, false, false, true},
    {OutcomeCode::Retired, false, false, true, false},
    {OutcomeCode::Superseded, false, false, true, false},
    {OutcomeCode::Tombstoned, false, false, true, false},
    {OutcomeCode::IllegalTransition, false, false, false, false},
    {OutcomeCode::ConflictUnresolved, false, false, false, true},
    {OutcomeCode::MalformedRequest, false, false, false, false},
    {OutcomeCode::ResourceLimit, false, false, false, false},
    {OutcomeCode::PolicyRejected, false, false, false, false},
    {OutcomeCode::NotFound, false, false, false, false},
    {OutcomeCode::NotCurrent, false, false, false, false},
    {OutcomeCode::UnsupportedCapability, false, false, false, false},
    {OutcomeCode::PersistenceFailure, false, false, false, false},
    {OutcomeCode::TransportFailure, false, false, false, false},
    {OutcomeCode::ProtocolViolation, false, false, false, false},
    {OutcomeCode::IntegrityFailure, false, false, false, false},
    {OutcomeCode::InternalFailure, false, false, false, false},
    {OutcomeCode::NoAuthority, false, false, false, false},
    {OutcomeCode::ProbableMatch, false, false, false, true},
};

/// The exact wire names of all 32 outcome codes, in enumerator order.
constexpr std::string_view kOutcomeNames[fabric_registry::kOutcomeCodeCount] = {
    "committed",         "idempotent",         "stale-generation",     "stale-authority",
    "stale-epoch",       "stale-worker-boot",  "fenced-publisher",     "duplicate-identity",
    "alias-conflict",    "identity-conflict",  "ambiguous-match",      "conflicting-replay",
    "invalid-evidence",  "revalidation-required", "retired",           "superseded",
    "tombstoned",        "illegal-transition", "conflict-unresolved",  "malformed-request",
    "resource-limit",    "policy-rejected",    "not-found",            "not-current",
    "unsupported-capability", "persistence-failure", "transport-failure", "protocol-violation",
    "integrity-failure", "internal-failure",   "no-authority",         "probable-match"};

} // namespace

FR_TEST_CASE(lifecycle, names_round_trip) {
  std::set<std::string_view> names;
  for (std::uint8_t raw = 0; raw < fabric_registry::kLifecycleCount; ++raw) {
    const Lifecycle value = static_cast<Lifecycle>(raw);
    const std::string_view name = fabric_registry::to_string(value);
    FR_CHECK_MSG(name != std::string_view("unknown"),
                 "lifecycle " + std::to_string(raw) + " has no stable name");
    FR_CHECK_EQ(name, kLifecycleNames[static_cast<std::size_t>(raw)]);

    const std::optional<Lifecycle> parsed = fabric_registry::lifecycle_from_string(name);
    FR_CHECK(parsed.has_value());
    FR_CHECK_EQ(*parsed, value);
    FR_CHECK_MSG(names.insert(name).second, "duplicate lifecycle name: " + std::string(name));
  }
  FR_CHECK_EQ(names.size(), static_cast<std::size_t>(fabric_registry::kLifecycleCount));

  FR_CHECK(!fabric_registry::lifecycle_from_string("unknown").has_value());
  FR_CHECK(!fabric_registry::lifecycle_from_string("").has_value());
  FR_CHECK(!fabric_registry::lifecycle_from_string("Current").has_value());
  FR_CHECK(!fabric_registry::lifecycle_from_string("revalidation_required").has_value());
  FR_CHECK_EQ(fabric_registry::to_string(static_cast<Lifecycle>(200)), std::string_view("unknown"));
}

FR_TEST_CASE(lifecycle, terminal_and_authority_flags) {
  std::size_t terminal_count = 0;
  std::size_t authority_count = 0;
  for (std::uint8_t raw = 0; raw < fabric_registry::kLifecycleCount; ++raw) {
    const Lifecycle value = static_cast<Lifecycle>(raw);
    const std::size_t index = static_cast<std::size_t>(raw);
    FR_CHECK_EQ(fabric_registry::is_terminal_lifecycle(value), kTerminalLifecycle[index]);
    FR_CHECK_EQ(fabric_registry::holds_current_authority(value), kHoldsCurrentAuthority[index]);
    if (kTerminalLifecycle[index]) {
      ++terminal_count;
    }
    if (kHoldsCurrentAuthority[index]) {
      ++authority_count;
    }
  }
  FR_CHECK_EQ(terminal_count, std::size_t{2});
  FR_CHECK_EQ(authority_count, std::size_t{1});

  FR_CHECK(fabric_registry::is_terminal_lifecycle(Lifecycle::Tombstoned));
  FR_CHECK(fabric_registry::is_terminal_lifecycle(Lifecycle::Rejected));
  FR_CHECK(!fabric_registry::is_terminal_lifecycle(Lifecycle::Retired));
  FR_CHECK(!fabric_registry::is_terminal_lifecycle(Lifecycle::Superseded));
  FR_CHECK(fabric_registry::holds_current_authority(Lifecycle::Current));
  FR_CHECK(!fabric_registry::holds_current_authority(Lifecycle::Candidate));
  FR_CHECK(!fabric_registry::holds_current_authority(Lifecycle::RevalidationRequired));
  FR_CHECK(!fabric_registry::holds_current_authority(Lifecycle::Conflicted));
}

FR_TEST_CASE(lifecycle, transition_table_is_exact) {
  std::size_t allowed_count = 0;
  for (std::uint8_t from_raw = 0; from_raw < fabric_registry::kLifecycleCount; ++from_raw) {
    for (std::uint8_t to_raw = 0; to_raw < fabric_registry::kLifecycleCount; ++to_raw) {
      const Lifecycle from = static_cast<Lifecycle>(from_raw);
      const Lifecycle to = static_cast<Lifecycle>(to_raw);
      const bool expected =
          kTransitionTable[static_cast<std::size_t>(from_raw)][static_cast<std::size_t>(to_raw)];
      FR_CHECK_EQ(fabric_registry::lifecycle_transition_allowed(from, to), expected);
      if (expected) {
        ++allowed_count;
      }
    }
  }
  FR_CHECK_EQ(allowed_count, std::size_t{20});

  // No transition leaves a terminal state.
  for (std::uint8_t to_raw = 0; to_raw < fabric_registry::kLifecycleCount; ++to_raw) {
    const Lifecycle to = static_cast<Lifecycle>(to_raw);
    FR_CHECK(!fabric_registry::lifecycle_transition_allowed(Lifecycle::Tombstoned, to));
    FR_CHECK(!fabric_registry::lifecycle_transition_allowed(Lifecycle::Rejected, to));
  }

  // A closed identity can never be made current again.
  const Lifecycle closed[] = {Lifecycle::Superseded, Lifecycle::Retired, Lifecycle::Tombstoned,
                              Lifecycle::Rejected};
  for (Lifecycle from : closed) {
    FR_CHECK(!fabric_registry::lifecycle_transition_allowed(from, Lifecycle::Current));
  }

  // A state is never its own successor.
  for (std::uint8_t raw = 0; raw < fabric_registry::kLifecycleCount; ++raw) {
    const Lifecycle value = static_cast<Lifecycle>(raw);
    FR_CHECK(!fabric_registry::lifecycle_transition_allowed(value, value));
  }

  FR_CHECK(fabric_registry::lifecycle_transition_allowed(Lifecycle::Discovered, Lifecycle::Candidate));
  FR_CHECK(fabric_registry::lifecycle_transition_allowed(Lifecycle::Candidate, Lifecycle::Current));
  FR_CHECK(fabric_registry::lifecycle_transition_allowed(Lifecycle::RevalidationRequired, Lifecycle::Current));
  FR_CHECK(fabric_registry::lifecycle_transition_allowed(Lifecycle::Conflicted, Lifecycle::Current));
  FR_CHECK(fabric_registry::lifecycle_transition_allowed(Lifecycle::Superseded, Lifecycle::Tombstoned));
  FR_CHECK(!fabric_registry::lifecycle_transition_allowed(Lifecycle::Discovered, Lifecycle::Current));
  FR_CHECK(!fabric_registry::lifecycle_transition_allowed(Lifecycle::Current, Lifecycle::Rejected));
  FR_CHECK(!fabric_registry::lifecycle_transition_allowed(Lifecycle::Rejected, Lifecycle::Current));
  FR_CHECK(!fabric_registry::lifecycle_transition_allowed(Lifecycle::Tombstoned, Lifecycle::Retired));
}

FR_TEST_CASE(lifecycle, reason_codes_are_named) {
  std::set<std::string_view> names;
  for (std::uint8_t raw = 0; raw < fabric_registry::kReasonCodeCount; ++raw) {
    const ReasonCode value = static_cast<ReasonCode>(raw);
    const std::string_view name = fabric_registry::to_string(value);
    FR_CHECK_MSG(name != std::string_view("unknown"), "reason code " + std::to_string(raw) + " has no name");
    FR_CHECK_EQ(name, kReasonNames[static_cast<std::size_t>(raw)]);
    FR_CHECK(names.insert(name).second);
  }
  FR_CHECK_EQ(names.size(), static_cast<std::size_t>(fabric_registry::kReasonCodeCount));

  FR_CHECK_EQ(fabric_registry::to_string(ReasonCode::Registration), std::string_view("registration"));
  FR_CHECK_EQ(fabric_registry::to_string(ReasonCode::EpochAdvance), std::string_view("epoch-advance"));
  FR_CHECK_EQ(fabric_registry::to_string(static_cast<ReasonCode>(200)), std::string_view("unknown"));
}

FR_TEST_CASE(lifecycle, outcome_codes_are_named) {
  std::set<std::string_view> names;
  for (std::uint8_t raw = 0; raw < fabric_registry::kOutcomeCodeCount; ++raw) {
    const OutcomeCode value = static_cast<OutcomeCode>(raw);
    const std::string_view name = fabric_registry::to_string(value);
    FR_CHECK_MSG(name != std::string_view("unknown"), "outcome code " + std::to_string(raw) + " has no name");
    FR_CHECK(!name.empty());
    FR_CHECK_EQ(name, kOutcomeNames[static_cast<std::size_t>(raw)]);
    FR_CHECK(names.insert(name).second);
  }
  FR_CHECK_EQ(names.size(), static_cast<std::size_t>(fabric_registry::kOutcomeCodeCount));
  FR_CHECK_EQ(fabric_registry::to_string(static_cast<OutcomeCode>(200)), std::string_view("unknown"));
}

FR_TEST_CASE(lifecycle, outcome_flags_match_the_table) {
  std::size_t commit_count = 0;
  std::size_t stale_count = 0;
  std::size_t closed_count = 0;
  std::size_t retryable_count = 0;

  for (std::uint8_t raw = 0; raw < fabric_registry::kOutcomeCodeCount; ++raw) {
    const OutcomeExpectation& expected = kOutcomeExpectations[raw];
    FR_CHECK_EQ(static_cast<std::uint8_t>(expected.code), raw);
    FR_CHECK_EQ(fabric_registry::is_commit(expected.code), expected.commit);
    FR_CHECK_EQ(fabric_registry::is_stale(expected.code), expected.stale);
    FR_CHECK_EQ(fabric_registry::is_closed(expected.code), expected.closed);
    FR_CHECK_EQ(fabric_registry::is_retryable_after_refresh(expected.code), expected.retryable_after_refresh);

    // A classification is a partition, not a set of independent guesses.
    FR_CHECK(!(expected.commit && expected.stale));
    FR_CHECK(!(expected.commit && expected.closed));
    FR_CHECK(!(expected.closed && expected.retryable_after_refresh));
    if (expected.commit) {
      ++commit_count;
    }
    if (expected.stale) {
      ++stale_count;
    }
    if (expected.closed) {
      ++closed_count;
    }
    if (expected.retryable_after_refresh) {
      ++retryable_count;
    }
  }

  FR_CHECK_EQ(commit_count, std::size_t{1});
  FR_CHECK_EQ(stale_count, std::size_t{6});
  FR_CHECK_EQ(closed_count, std::size_t{3});
  FR_CHECK_EQ(retryable_count, std::size_t{5});

  FR_CHECK(fabric_registry::is_commit(OutcomeCode::Committed));
  FR_CHECK(!fabric_registry::is_commit(OutcomeCode::Idempotent));
  FR_CHECK(fabric_registry::is_stale(OutcomeCode::StaleGeneration));
  FR_CHECK(fabric_registry::is_closed(OutcomeCode::Tombstoned));
  FR_CHECK(fabric_registry::is_retryable_after_refresh(OutcomeCode::RevalidationRequired));
  FR_CHECK(!fabric_registry::is_retryable_after_refresh(OutcomeCode::Tombstoned));
}

FR_TEST_CASE(lifecycle, outcome_helpers_agree_with_the_flags) {
  for (std::uint8_t raw = 0; raw < fabric_registry::kOutcomeCodeCount; ++raw) {
    const OutcomeCode code = static_cast<OutcomeCode>(raw);
    fabric_registry::Outcome outcome(code, "message");
    FR_CHECK_EQ(outcome.committed(), code == OutcomeCode::Committed);
    FR_CHECK_EQ(outcome.succeeded(), fabric_registry::is_commit(code) || code == OutcomeCode::Idempotent);
    FR_CHECK_EQ(outcome.stale(), fabric_registry::is_stale(code));
    const std::string rendered = outcome.render();
    FR_CHECK_EQ(rendered.rfind("outcome: ", 0), std::size_t{0});
    FR_CHECK(rendered.find(fabric_registry::to_string(code)) != std::string::npos);
  }
}

int main(int argc, char** argv) { return frtest::run_all(argc, argv); }
