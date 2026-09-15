// Fabric Registry — deterministic races and concurrency safety.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every case here releases two or more threads at a chosen point with a barrier
// and then asserts the *legal* set of outcome pairs the contract allows, never a
// particular interleaving. No case uses a timeout to hide a deadlock: the
// barrier waits on a predicate without a deadline, so a genuine deadlock hangs
// the test instead of passing it.
//
// Thread bodies never assert. They record outcomes, counts and problem strings
// into storage that only they touch; the joining thread performs every check
// afterwards. No exception can therefore escape a thread, and every thread is
// joined.

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/registry_test_support.hpp"
#include "support/test_harness.hpp"

namespace fr = fabric_registry;

namespace {

using RecordPtr = std::shared_ptr<const fr::EntityRecord>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A single-use rendezvous point. \`arrive_and_wait\` returns only when every
/// party has arrived; the wait has no timeout on purpose.
class Barrier {
public:
  explicit Barrier(std::size_t parties) noexcept : parties_(parties) {}
  Barrier(const Barrier&) = delete;
  Barrier& operator=(const Barrier&) = delete;

  void arrive_and_wait() {
    const std::size_t arrived = counter_.fetch_add(1, std::memory_order_acq_rel) + 1;
    std::unique_lock<std::mutex> lock(mutex_);
    if (arrived == parties_) {
      ++round_;
      condition_.notify_all();
      return;
    }
    const std::uint64_t round = round_;
    condition_.wait(lock, [this, round] { return round_ != round; });
  }

private:
  std::size_t parties_;
  std::atomic<std::size_t> counter_{0};
  std::mutex mutex_;
  std::condition_variable condition_;
  std::uint64_t round_{0};
};

/// What one thread saw. Every thread owns its own instance, so no lock is
/// needed to fill it in.
struct Observation {
  std::vector<fr::Outcome> outcomes;
  std::vector<std::string> problems;
  std::size_t committed{0};
  std::size_t missing{0};
};

std::string describe(const fr::Outcome& outcome) {
  return std::string(fr::to_string(outcome.code)) + " (" + outcome.message + ")";
}

bool commit_or_stale(fr::OutcomeCode code) {
  return code == fr::OutcomeCode::Committed || fr::is_stale(code);
}

fr::RegisterEntityRequest make_registration(fr::Registry& registry,
                                            const std::string& label,
                                            const std::string& serial,
                                            const std::string& derivation_namespace,
                                            fr::EvidenceClass evidence_class) {
  return frtest::device_request(registry, label, serial, fr::EntityClass::Switch, derivation_namespace, evidence_class);
}

RecordPtr load_record(const fr::Registry& registry, const fr::CanonicalId& id) {
  RecordPtr record;
  if (!registry.lookup(id, record).committed()) {
    return nullptr;
  }
  return record;
}

/// Registers one record and resolves its canonical identity, or fails the case.
fr::CanonicalId register_one(fr::Registry& registry,
                             const std::string& label,
                             const std::string& serial,
                             const std::string& derivation_namespace = "concurrency/namespace",
                             fr::EvidenceClass evidence_class = fr::EvidenceClass::DurableAuthority) {
  const fr::Outcome outcome = registry.register_entity(make_registration(registry, label, serial, derivation_namespace, evidence_class));
  if (!outcome.committed()) {
    // fail() records the reason and throws, so no thread ever continues past a
    // broken fixture.
    ::frtest::fail(__FILE__, __LINE__, "fixture registration failed: " + outcome.message);
  }
  std::vector<fr::CanonicalId> found;
  const fr::Outcome by_fact = registry.lookup_by_fact(frtest::serial_fact(serial), found);
  if (!by_fact.committed() || found.size() != 1) {
    ::frtest::fail(__FILE__, __LINE__, "the fixture registration is not indexed by its serial fact");
  }
  return found.front();
}

std::string validate_now(const fr::Registry& registry) {
  std::string report;
  if (!registry.validate_state(report).committed()) {
    return "validate_state rejected the registry: " + report;
  }
  if (report.find("consistent: true") == std::string::npos) {
    return "validate_state did not report a consistent state";
  }
  return std::string();
}

/// Fails the running case unless the live registry is internally consistent.
void require_consistent(const fr::Registry& registry) {
  const std::string problem = validate_now(registry);
  FR_CHECK_MSG(problem.empty(), problem);
}

fr::UpdateEvidenceRequest make_update(fr::Registry& registry,
                                      const std::string& label,
                                      const fr::CanonicalId& target,
                                      const std::vector<fr::IdentityFact>& facts,
                                      std::optional<fr::RecordGeneration> expected = std::nullopt) {
  fr::UpdateEvidenceRequest request;
  request.attempt = frtest::attempt_from(label);
  request.authority = registry.local_authority();
  request.target = target;
  request.expected_generation = expected;
  request.facts = facts;
  request.provenance = frtest::real_provenance();
  request.evidence_class = fr::EvidenceClass::DurableAuthority;
  request.merge_facts = true;
  return request;
}

} // namespace

// ---------------------------------------------------------------------------
// Races
// ---------------------------------------------------------------------------

FR_TEST_CASE(concurrency, two_threads_register_the_same_new_identity) {
  const std::string serial = "race-same-serial";
  const std::string name_space = "race/same-namespace";
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(7);

  const fr::RegisterEntityRequest first = make_registration(*registry, "same-a", serial, name_space, fr::EvidenceClass::DurableAuthority);
  const fr::RegisterEntityRequest second = make_registration(*registry, "same-b", serial, name_space, fr::EvidenceClass::DurableAuthority);

  Observation left;
  Observation right;
  Barrier barrier(2);
  std::thread one([&] {
    barrier.arrive_and_wait();
    left.outcomes.push_back(registry->register_entity(first));
  });
  std::thread two([&] {
    barrier.arrive_and_wait();
    right.outcomes.push_back(registry->register_entity(second));
  });
  one.join();
  two.join();

  FR_CHECK_EQ(left.outcomes.size(), std::size_t{1});
  FR_CHECK_EQ(right.outcomes.size(), std::size_t{1});
  const fr::Outcome& outcome_one = left.outcomes.front();
  const fr::Outcome& outcome_two = right.outcomes.front();

  std::size_t committed = 0;
  for (const fr::Outcome* outcome : {&outcome_one, &outcome_two}) {
    if (outcome->committed()) {
      ++committed;
    } else {
      const fr::OutcomeCode code = outcome->code;
      FR_CHECK_MSG(code == fr::OutcomeCode::DuplicateIdentity || code == fr::OutcomeCode::IdentityConflict ||
                       code == fr::OutcomeCode::AmbiguousMatch || fr::is_stale(code) ||
                       code == fr::OutcomeCode::ConflictingReplay,
                   "an unexpected losing outcome: " + describe(*outcome));
    }
  }
  FR_CHECK_MSG(committed >= 1, "neither thread registered the identity");

  std::vector<fr::CanonicalId> found;
  FR_CHECK(registry->lookup_by_fact(frtest::serial_fact(serial), found).committed());
  FR_CHECK_EQ(found.size(), std::size_t{1});
  const fr::CanonicalId identity = found.front();
  const RecordPtr record = load_record(*registry, identity);
  FR_CHECK_MSG(record != nullptr && record->lifecycle == fr::Lifecycle::Current,
               "the surviving record must hold current authority");
  for (const fr::Outcome* outcome : {&outcome_one, &outcome_two}) {
    if (outcome->committed()) {
      FR_CHECK_MSG(outcome->record.has_value() && *outcome->record == identity,
                   "a committed registration must name the one surviving record");
    }
  }
  FR_CHECK_MSG(registry->stats().entities == std::size_t{1}, "the race produced more than one record for one identity");
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, conflicting_identities_leave_exactly_one_live_record) {
  const std::string serial = "race-conflict-serial";
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(11);

  fr::RegisterEntityRequest first = make_registration(*registry, "conflict-a", serial, "race/namespace-a", fr::EvidenceClass::DurableAuthority);
  first.facts.push_back(frtest::fact_of(fr::IdentityFactKind::HostName, "host-a"));
  fr::RegisterEntityRequest second = make_registration(*registry, "conflict-b", serial, "race/namespace-b", fr::EvidenceClass::DurableAuthority);
  second.facts.push_back(frtest::fact_of(fr::IdentityFactKind::HostName, "host-b"));

  Observation left;
  Observation right;
  Barrier barrier(2);
  std::thread one([&] {
    barrier.arrive_and_wait();
    left.outcomes.push_back(registry->register_entity(first));
  });
  std::thread two([&] {
    barrier.arrive_and_wait();
    right.outcomes.push_back(registry->register_entity(second));
  });
  one.join();
  two.join();

  const fr::Outcome& outcome_one = left.outcomes.front();
  const fr::Outcome& outcome_two = right.outcomes.front();
  std::size_t committed = 0;
  for (const fr::Outcome* outcome : {&outcome_one, &outcome_two}) {
    if (outcome->committed()) {
      ++committed;
    }
  }
  FR_CHECK_MSG(committed == 1, "a contradictory pair of observations must produce exactly one live record");
  for (const fr::Outcome* outcome : {&outcome_one, &outcome_two}) {
    if (!outcome->committed()) {
      const fr::OutcomeCode code = outcome->code;
      FR_CHECK_MSG(code == fr::OutcomeCode::IdentityConflict || code == fr::OutcomeCode::DuplicateIdentity ||
                       code == fr::OutcomeCode::AmbiguousMatch,
                   "a losing conflicting registration returned " + describe(*outcome));
    }
  }

  std::vector<fr::CanonicalId> found;
  FR_CHECK(registry->lookup_by_fact(frtest::serial_fact(serial), found).committed());
  FR_CHECK_EQ(found.size(), std::size_t{1});
  const RecordPtr record = load_record(*registry, found.front());
  FR_CHECK_MSG(record != nullptr && record->lifecycle == fr::Lifecycle::Current,
               "the surviving record must hold current authority");
  FR_CHECK_EQ(registry->stats().entities, std::size_t{1});

  // The loser created nothing: its own weak fact must not be indexed at all.
  const std::vector<fr::IdentityFact> probes = {frtest::fact_of(fr::IdentityFactKind::HostName, "host-a"),
                                                 frtest::fact_of(fr::IdentityFactKind::HostName, "host-b")};
  std::size_t indexed_hosts = 0;
  for (const fr::IdentityFact& probe : probes) {
    std::vector<fr::CanonicalId> hosts;
    if (registry->lookup_by_fact(probe, hosts).committed()) {
      ++indexed_hosts;
    }
  }
  FR_CHECK_EQ(indexed_hosts, std::size_t{1});
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, update_versus_retire_on_one_record) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(13);
  const fr::CanonicalId target = register_one(*registry, "uvr-base", "uvr-serial");
  const RecordPtr created = load_record(*registry, target);
  FR_CHECK(created != nullptr);
  FR_CHECK_EQ(created->record_generation.value(), std::uint64_t{1});

  const fr::UpdateEvidenceRequest update = make_update(*registry, "uvr-update", target, created->facts, created->record_generation);
  fr::RetireEntityRequest retire;
  retire.attempt = frtest::attempt_from("uvr-retire");
  retire.authority = registry->local_authority();
  retire.target = target;
  retire.expected_generation = created->record_generation;
  retire.reason = "concurrency race";

  Observation updating;
  Observation retiring;
  Barrier barrier(2);
  std::thread u([&] {
    barrier.arrive_and_wait();
    updating.outcomes.push_back(registry->update_evidence(update));
  });
  std::thread r([&] {
    barrier.arrive_and_wait();
    retiring.outcomes.push_back(registry->retire_entity(retire));
  });
  u.join();
  r.join();

  const fr::Outcome& update_outcome = updating.outcomes.front();
  const fr::Outcome& retire_outcome = retiring.outcomes.front();
  const fr::OutcomeCode update_code = update_outcome.code;
  const fr::OutcomeCode retire_code = retire_outcome.code;
  FR_CHECK_MSG(update_code == fr::OutcomeCode::Committed || update_code == fr::OutcomeCode::Retired ||
                   update_code == fr::OutcomeCode::StaleGeneration || update_code == fr::OutcomeCode::IllegalTransition,
               "the update returned an outcome outside the legal set: " + describe(update_outcome));
  FR_CHECK_MSG(retire_code == fr::OutcomeCode::Committed || retire_code == fr::OutcomeCode::StaleGeneration ||
                   retire_code == fr::OutcomeCode::IllegalTransition || retire_code == fr::OutcomeCode::Retired,
               "the retirement returned an outcome outside the legal set: " + describe(retire_outcome));

  const RecordPtr after = load_record(*registry, target);
  FR_CHECK(after != nullptr);
  if (retire_outcome.committed()) {
    FR_CHECK_MSG(after->lifecycle == fr::Lifecycle::Retired, "a committed retirement must leave the record retired");
    FR_CHECK_MSG(retire_outcome.record_generation.has_value() &&
                     *retire_outcome.record_generation == after->record_generation,
                 "the retirement outcome does not describe the final generation");
    if (update_outcome.committed()) {
      FR_CHECK_MSG(after->record_generation.value() == std::uint64_t{3},
                   "the update ran before the retirement, so the record must be at generation three");
    } else {
      FR_CHECK_MSG(after->record_generation.value() == std::uint64_t{2},
                   "a rejected update must not have advanced the record generation");
    }
  } else {
    FR_CHECK_MSG(update_outcome.committed(), "the retirement lost, so the update must have committed");
    FR_CHECK_MSG(after->lifecycle == fr::Lifecycle::Current, "the record must still be current");
    FR_CHECK_MSG(after->record_generation.value() == std::uint64_t{2}, "exactly one mutation may have committed");
  }
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, two_threads_attach_the_same_alias) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(17);
  const fr::CanonicalId first = register_one(*registry, "alias-race-a", "alias-race-serial-a");
  const fr::CanonicalId second = register_one(*registry, "alias-race-b", "alias-race-serial-b");
  const std::string value = "shared-cmdb-identifier";

  fr::AliasMutationRequest first_request;
  first_request.attempt = frtest::attempt_from("alias-race-attach-a");
  first_request.authority = registry->local_authority();
  first_request.target = first;
  first_request.alias = frtest::alias_of(fr::AliasNamespace::ExternalCmdbId, value);
  fr::AliasMutationRequest second_request = first_request;
  second_request.attempt = frtest::attempt_from("alias-race-attach-b");
  second_request.target = second;

  Observation left;
  Observation right;
  Barrier barrier(2);
  std::thread one([&] {
    barrier.arrive_and_wait();
    left.outcomes.push_back(registry->attach_alias(first_request));
  });
  std::thread two([&] {
    barrier.arrive_and_wait();
    right.outcomes.push_back(registry->attach_alias(second_request));
  });
  one.join();
  two.join();

  const fr::Outcome& outcome_one = left.outcomes.front();
  const fr::Outcome& outcome_two = right.outcomes.front();
  const std::size_t committed = (outcome_one.committed() ? 1u : 0u) + (outcome_two.committed() ? 1u : 0u);
  FR_CHECK_MSG(committed == 1, "exactly one attach of a unique alias may commit");
  const fr::Outcome& loser = outcome_one.committed() ? outcome_two : outcome_one;
  FR_CHECK_MSG(loser.code == fr::OutcomeCode::AliasConflict,
               "the losing attach returned " + describe(loser));

  fr::AliasKey key;
  key.alias_namespace = fr::AliasNamespace::ExternalCmdbId;
  key.value = value;
  RecordPtr holder;
  FR_CHECK_MSG(registry->lookup_by_alias(key, holder).committed() && holder != nullptr,
               "the winning alias must resolve after the race");
  const fr::CanonicalId loser_target = outcome_one.committed() ? second : first;
  const RecordPtr loser_record = load_record(*registry, loser_target);
  FR_CHECK(loser_record != nullptr);
  FR_CHECK_MSG(std::find(loser_record->aliases.begin(), loser_record->aliases.end(), key) == loser_record->aliases.end(),
               "the rejected attach left the alias attached anyway");
  FR_CHECK_MSG(holder->id == (outcome_one.committed() ? first : second), "the alias resolves to the wrong record");
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, register_versus_advance_epoch) {
  const std::string serial = "epoch-race-serial";
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(19);
  const fr::RegisterEntityRequest request =
      make_registration(*registry, "epoch-race", serial, "epoch/namespace", fr::EvidenceClass::ProcessBound);

  Observation registering;
  Observation advancing;
  Barrier barrier(2);
  std::thread one([&] {
    barrier.arrive_and_wait();
    registering.outcomes.push_back(registry->register_entity(request));
  });
  std::thread two([&] {
    barrier.arrive_and_wait();
    std::size_t demoted = 0;
    advancing.outcomes.push_back(registry->advance_epoch(demoted));
  });
  one.join();
  two.join();

  const fr::Outcome& registration = registering.outcomes.front();
  const fr::Outcome& epoch_advance = advancing.outcomes.front();
  FR_CHECK_MSG(epoch_advance.committed(), "the epoch advance must commit: " + describe(epoch_advance));
  if (registration.committed()) {
    std::vector<fr::CanonicalId> found;
    FR_CHECK(registry->lookup_by_fact(frtest::serial_fact(serial), found).committed());
    FR_CHECK_EQ(found.size(), std::size_t{1});
    const RecordPtr record = load_record(*registry, found.front());
    FR_CHECK(record != nullptr);
    FR_CHECK_MSG(record->lifecycle == fr::Lifecycle::RevalidationRequired,
                 "a registration committed at the old epoch must be demoted by the epoch advance");
    FR_CHECK_MSG(!record->evidence.valid, "a demoted record must carry invalid evidence");
  } else {
    const fr::OutcomeCode code = registration.code;
    FR_CHECK_MSG(code == fr::OutcomeCode::StaleEpoch || code == fr::OutcomeCode::FencedPublisher ||
                     code == fr::OutcomeCode::StaleWorkerBoot || code == fr::OutcomeCode::StaleAuthority,
                 "a registration that lost to the epoch advance returned " + describe(registration));
    std::vector<fr::CanonicalId> found;
    FR_CHECK_MSG(!registry->lookup_by_fact(frtest::serial_fact(serial), found).committed(),
                 "a rejected registration must not leave a record behind");
  }

  for (const fr::CanonicalId& id : registry->all_ids(registry->limits().max_enumeration)) {
    const RecordPtr record = load_record(*registry, id);
    FR_CHECK(record != nullptr);
    if (record->lifecycle == fr::Lifecycle::Current) {
      FR_CHECK_MSG(record->evidence.valid, "a current record carries invalid evidence: " + id.to_string());
    }
  }
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, mutation_versus_publisher_fencing) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(23);
  const fr::CanonicalId target = register_one(*registry, "fence-base", "fence-serial");
  const RecordPtr base = load_record(*registry, target);
  FR_CHECK(base != nullptr);

  fr::PublisherAttachRequest attach;
  attach.name = "racing-publisher";
  const fr::PublisherAttachResult attached = registry->attach_publisher(attach);
  FR_CHECK_MSG(attached.outcome.committed(), "attaching the racing publisher failed: " + attached.outcome.message);
  fr::AuthorityClaim claim;
  claim.publisher = attached.publisher;
  claim.worker_boot = attached.worker_boot;
  claim.epoch = attached.epoch;

  constexpr std::size_t kMutations = 64;
  Observation mutating;
  Observation fencing;
  Barrier barrier(2);
  std::thread mutations([&] {
    barrier.arrive_and_wait();
    for (std::size_t step = 0; step < kMutations; ++step) {
      fr::UpdateEvidenceRequest request;
      request.attempt = frtest::attempt_from("fence-mutation-" + std::to_string(step));
      request.authority = claim;
      request.target = target;
      request.facts = base->facts;
      request.provenance = frtest::real_provenance();
      request.evidence_class = fr::EvidenceClass::DurableAuthority;
      request.merge_facts = true;
      mutating.outcomes.push_back(registry->update_evidence(request));
    }
  });
  std::thread fencer([&] {
    barrier.arrive_and_wait();
    std::size_t demoted = 0;
    fencing.outcomes.push_back(registry->fence_publisher(attached.publisher, fr::FenceReason::SessionLost, demoted));
  });
  mutations.join();
  fencer.join();

  FR_CHECK_EQ(mutating.outcomes.size(), kMutations);
  FR_CHECK_MSG(fencing.outcomes.front().committed(), "fencing a live publisher must commit");
  for (const fr::Outcome& outcome : mutating.outcomes) {
    FR_CHECK_MSG(commit_or_stale(outcome.code),
                 "a mutation racing a publisher fence returned " + describe(outcome));
    FR_CHECK_MSG(outcome.code != fr::OutcomeCode::InternalFailure, "a fencing race produced an internal failure");
  }
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, stale_replay_versus_fresh_registration) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(29);
  const fr::CanonicalId target = register_one(*registry, "replay-race-base", "replay-race-serial");
  const RecordPtr created = load_record(*registry, target);
  FR_CHECK(created != nullptr);

  const fr::UpdateEvidenceRequest replayable = make_update(*registry, "replay-race-original", target, created->facts, created->record_generation);
  FR_CHECK_MSG(registry->update_evidence(replayable).committed(), "the original request must commit before it is replayed");
  const fr::UpdateEvidenceRequest fresh = make_update(*registry, "replay-race-fresh", target, created->facts);

  Observation replaying;
  Observation mutating;
  Barrier barrier(2);
  std::thread replay([&] {
    barrier.arrive_and_wait();
    replaying.outcomes.push_back(registry->update_evidence(replayable));
  });
  std::thread mutate([&] {
    barrier.arrive_and_wait();
    mutating.outcomes.push_back(registry->update_evidence(fresh));
  });
  replay.join();
  mutate.join();

  const fr::Outcome& replay_outcome = replaying.outcomes.front();
  FR_CHECK_MSG(replay_outcome.code == fr::OutcomeCode::Idempotent ||
                   replay_outcome.code == fr::OutcomeCode::StaleGeneration,
               "an idempotent replay returned " + describe(replay_outcome));
  FR_CHECK_MSG(mutating.outcomes.front().committed(),
               "the fresh mutation must commit: " + describe(mutating.outcomes.front()));
  const RecordPtr after = load_record(*registry, target);
  FR_CHECK(after != nullptr);
  FR_CHECK_MSG(after->record_generation.value() == std::uint64_t{3},
               "only the fresh mutation may advance the record generation");
  FR_CHECK_MSG(registry->stats().entities == std::size_t{1}, "the replay race changed the record count");
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, supersede_versus_update) {
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(31);
  const fr::CanonicalId target = register_one(*registry, "supersede-race-target", "supersede-race-serial");
  const fr::CanonicalId successor = register_one(*registry, "supersede-race-successor", "supersede-race-successor-serial");
  const RecordPtr created = load_record(*registry, target);
  FR_CHECK(created != nullptr);

  const fr::UpdateEvidenceRequest update = make_update(*registry, "supersede-race-update", target, created->facts, created->record_generation);
  fr::SupersedeEntityRequest supersede;
  supersede.attempt = frtest::attempt_from("supersede-race-supersede");
  supersede.authority = registry->local_authority();
  supersede.target = target;
  supersede.successor = successor;
  supersede.reason = "concurrency race";

  Observation updating;
  Observation superseding;
  Barrier barrier(2);
  std::thread u([&] {
    barrier.arrive_and_wait();
    updating.outcomes.push_back(registry->update_evidence(update));
  });
  std::thread s([&] {
    barrier.arrive_and_wait();
    superseding.outcomes.push_back(registry->supersede_entity(supersede));
  });
  u.join();
  s.join();

  const fr::Outcome& update_outcome = updating.outcomes.front();
  const fr::Outcome& supersede_outcome = superseding.outcomes.front();
  FR_CHECK_MSG(supersede_outcome.committed(), "the supersession must commit: " + describe(supersede_outcome));
  const fr::OutcomeCode update_code = update_outcome.code;
  FR_CHECK_MSG(update_code == fr::OutcomeCode::Committed || update_code == fr::OutcomeCode::Superseded ||
                   update_code == fr::OutcomeCode::StaleGeneration,
               "an update racing a supersession returned " + describe(update_outcome));

  const RecordPtr after = load_record(*registry, target);
  FR_CHECK(after != nullptr);
  FR_CHECK_MSG(after->lifecycle == fr::Lifecycle::Superseded, "the superseded record must be superseded");
  FR_CHECK_MSG(after->superseded_by.has_value() && *after->superseded_by == successor,
               "the superseded record must name its successor");
  const std::uint64_t expected_generation = update_outcome.committed() ? std::uint64_t{3} : std::uint64_t{2};
  FR_CHECK_MSG(after->record_generation.value() == expected_generation,
               "the final generation does not match the outcome pair");
  const RecordPtr successor_record = load_record(*registry, successor);
  FR_CHECK(successor_record != nullptr);
  FR_CHECK_MSG(successor_record->supersedes.has_value() && *successor_record->supersedes == target,
               "the successor must record the identity it replaced");
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, snapshot_versus_mutation) {
  constexpr std::size_t kRecords = 24;
  constexpr std::size_t kRounds = 300;
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(37);
  for (std::size_t index = 0; index < kRecords; ++index) {
    const std::string tag = std::to_string(index);
    register_one(*registry, "snapshot-" + tag, "snapshot-serial-" + tag);
  }
  const std::vector<fr::CanonicalId> ids = registry->all_ids(registry->limits().max_enumeration);
  FR_CHECK_EQ(ids.size(), kRecords);

  // Taken before the writer starts: every later mutation invalidates it.
  const fr::Snapshot early = registry->snapshot();

  Observation snapshots;
  Observation writing;
  Barrier barrier(2);
  std::thread reader([&] {
    barrier.arrive_and_wait();
    for (std::size_t round = 0; round < kRounds; ++round) {
      const fr::Snapshot snapshot = registry->snapshot();
      if (snapshot.empty()) {
        snapshots.problems.push_back("a snapshot of a populated registry was empty");
        continue;
      }
      std::size_t indexed = 0;
      for (const RecordPtr& record : snapshot.records()) {
        if (record == nullptr) {
          snapshots.problems.push_back("a snapshot holds a null record");
          continue;
        }
        if (!record->is_well_formed()) {
          snapshots.problems.push_back("a snapshot holds a malformed record: " + record->id.to_string());
        }
        if (record->record_generation < record->creation_generation) {
          snapshots.problems.push_back("a snapshot holds a record whose generation is behind its creation generation");
        }
        if (snapshot.find(record->id) != record) {
          snapshots.problems.push_back("snapshot.find disagrees with the snapshot record list");
        }
        for (const fr::AliasKey& alias : record->aliases) {
          if (fr::alias_is_unique(alias.alias_namespace)) {
            ++indexed;
          }
        }
      }
      if (indexed != snapshot.alias_count()) {
        snapshots.problems.push_back("a snapshot alias count disagrees with its records");
      }
      if (snapshot.size() != kRecords) {
        snapshots.problems.push_back("a snapshot lost or gained a record");
      }
    }
  });
  std::thread writer([&] {
    barrier.arrive_and_wait();
    frtest::Rng rng(41);
    for (std::size_t round = 0; round < kRounds; ++round) {
      const fr::CanonicalId target = ids[static_cast<std::size_t>(rng.below(ids.size()))];
      const RecordPtr record = load_record(*registry, target);
      if (record == nullptr) {
        writing.problems.push_back("the writer lost a record");
        continue;
      }
      fr::UpdateEvidenceRequest request = make_update(*registry, "snapshot-write-" + std::to_string(round), target, record->facts);
      const fr::Outcome outcome = registry->update_evidence(request);
      if (!outcome.committed()) {
        writing.problems.push_back("a snapshot mutation was rejected: " + describe(outcome));
      }
    }
  });
  reader.join();
  writer.join();

  FR_CHECK_MSG(snapshots.problems.empty(), snapshots.problems.empty() ? std::string() : snapshots.problems.front());
  FR_CHECK_MSG(writing.problems.empty(), writing.problems.empty() ? std::string() : writing.problems.front());
  FR_CHECK_MSG(!registry->snapshot_current(early), "a snapshot taken before the last mutation is still current");
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, concurrent_reads_with_a_writer) {
  constexpr std::size_t kReadThreads = 8;
  constexpr std::size_t kLookupsPerThread = 5000;
  constexpr std::size_t kRecords = 500;
  constexpr std::size_t kMutations = 500;
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(43);
  for (std::size_t index = 0; index < kRecords; ++index) {
    const std::string tag = std::to_string(index);
    register_one(*registry, "reader-" + tag, "reader-serial-" + tag);
  }
  const std::vector<fr::CanonicalId> ids = registry->all_ids(registry->limits().max_enumeration);
  FR_CHECK_EQ(ids.size(), kRecords);

  std::array<Observation, kReadThreads> readers;
  Observation writer;
  Barrier barrier(kReadThreads + 1);
  std::vector<std::thread> threads;
  threads.reserve(kReadThreads);
  for (std::size_t slot = 0; slot < kReadThreads; ++slot) {
    threads.emplace_back([&, slot] {
      barrier.arrive_and_wait();
      frtest::Rng rng(slot * 1000 + 7);
      for (std::size_t step = 0; step < kLookupsPerThread; ++step) {
        const fr::CanonicalId target = ids[static_cast<std::size_t>(rng.below(ids.size()))];
        RecordPtr record;
        const fr::Outcome outcome = registry->lookup(target, record);
        if (outcome.code == fr::OutcomeCode::Committed) {
          ++readers[slot].committed;
          if (record == nullptr) {
            readers[slot].problems.push_back("a committed lookup returned no record");
            continue;
          }
          if (!record->is_well_formed()) {
            readers[slot].problems.push_back("a returned record is malformed");
          }
          if (record->record_generation < record->creation_generation) {
            readers[slot].problems.push_back("a returned record is behind its creation generation");
          }
          if (!(record->id == target)) {
            readers[slot].problems.push_back("a lookup returned a different identity");
          }
        } else if (outcome.code == fr::OutcomeCode::NotFound) {
          ++readers[slot].missing;
        } else {
          readers[slot].problems.push_back("an unexpected lookup outcome: " + describe(outcome));
        }
      }
    });
  }
  std::thread mutator([&] {
    barrier.arrive_and_wait();
    frtest::Rng rng(1234567);
    for (std::size_t step = 0; step < kMutations; ++step) {
      const fr::CanonicalId target = ids[static_cast<std::size_t>(rng.below(ids.size()))];
      const RecordPtr record = load_record(*registry, target);
      if (record == nullptr) {
        writer.problems.push_back("the writer lost a record");
        continue;
      }
      fr::UpdateEvidenceRequest request = make_update(*registry, "reader-write-" + std::to_string(step), target, record->facts);
      const fr::Outcome outcome = registry->update_evidence(request);
      if (!outcome.committed()) {
        writer.problems.push_back("a concurrent mutation was rejected: " + describe(outcome));
      } else {
        ++writer.committed;
      }
    }
  });
  mutator.join();
  for (std::thread& thread : threads) {
    thread.join();
  }

  FR_CHECK_MSG(writer.problems.empty(), writer.problems.empty() ? std::string() : writer.problems.front());
  FR_CHECK_EQ(writer.committed, kMutations);
  std::size_t committed_reads = 0;
  std::size_t missing_reads = 0;
  for (std::size_t slot = 0; slot < kReadThreads; ++slot) {
    FR_CHECK_MSG(readers[slot].problems.empty(),
                 readers[slot].problems.empty() ? std::string() : readers[slot].problems.front());
    FR_CHECK_EQ(readers[slot].committed + readers[slot].missing, kLookupsPerThread);
    committed_reads += readers[slot].committed;
    missing_reads += readers[slot].missing;
  }
  FR_CHECK_MSG(missing_reads == 0, "a lookup missed a record that was never removed");
  FR_CHECK_EQ(committed_reads, kReadThreads * kLookupsPerThread);
  FR_CHECK_MSG(registry->stats().entities == kRecords, "the read race changed the record count");
  require_consistent(*registry);
}

FR_TEST_CASE(concurrency, publisher_loss_and_fencing_race) {
  constexpr std::size_t kWorkers = 4;
  constexpr std::size_t kRegistrationsPerWorker = 25;
  const std::unique_ptr<fr::Registry> registry = frtest::make_registry(47);

  std::array<Observation, kWorkers> workers;
  Observation fencing;
  std::atomic<bool> finished{false};
  std::mutex publisher_mutex;
  std::vector<fr::PublisherId> publisher_ids;

  std::vector<std::thread> threads;
  threads.reserve(kWorkers);
  for (std::size_t slot = 0; slot < kWorkers; ++slot) {
    threads.emplace_back([&, slot] {
      fr::PublisherAttachRequest attach;
      attach.name = "race-worker-" + std::to_string(slot);
      const fr::PublisherAttachResult attached = registry->attach_publisher(attach);
      workers[slot].outcomes.push_back(attached.outcome);
      if (!attached.outcome.committed()) {
        return;
      }
      {
        std::lock_guard<std::mutex> guard(publisher_mutex);
        publisher_ids.push_back(attached.publisher);
      }
      fr::AuthorityClaim claim;
      claim.publisher = attached.publisher;
      claim.worker_boot = attached.worker_boot;
      claim.epoch = attached.epoch;
      for (std::size_t step = 0; step < kRegistrationsPerWorker; ++step) {
        const std::string tag = std::to_string(slot) + "-" + std::to_string(step);
        fr::RegisterEntityRequest request =
            make_registration(*registry, "worker-" + tag, "worker-serial-" + tag, "race/worker-namespace", fr::EvidenceClass::DurableAuthority);
        request.authority = claim;
        workers[slot].outcomes.push_back(registry->register_entity(request));
      }
    });
  }

  std::thread fencer([&] {
    std::size_t rounds = 0;
    while (!finished.load() && rounds < 2000) {
      std::vector<fr::PublisherId> known;
      {
        std::lock_guard<std::mutex> guard(publisher_mutex);
        known = publisher_ids;
      }
      for (const fr::PublisherId& id : known) {
        std::size_t demoted = 0;
        fencing.outcomes.push_back(registry->fence_publisher(id, fr::FenceReason::Administrative, demoted));
      }
      ++rounds;
    }
  });

  for (std::thread& thread : threads) {
    thread.join();
  }
  finished.store(true);
  fencer.join();

  std::size_t registrations = 0;
  std::size_t commits = 0;
  for (std::size_t slot = 0; slot < kWorkers; ++slot) {
    FR_CHECK_MSG(!workers[slot].outcomes.empty(), "a worker recorded no outcome at all");
    FR_CHECK_MSG(workers[slot].outcomes.front().committed(), "attaching a worker publisher must commit");
    for (std::size_t index = 1; index < workers[slot].outcomes.size(); ++index) {
      const fr::Outcome& outcome = workers[slot].outcomes[index];
      ++registrations;
      if (outcome.committed()) {
        ++commits;
      } else {
        FR_CHECK_MSG(outcome.code == fr::OutcomeCode::Idempotent || fr::is_stale(outcome.code),
                     "a registration racing publisher fencing returned " + describe(outcome));
        FR_CHECK_MSG(outcome.code != fr::OutcomeCode::InternalFailure,
                     "publisher fencing produced an internal failure");
      }
    }
  }
  FR_CHECK_EQ(registrations, kWorkers * kRegistrationsPerWorker);
  FR_CHECK_MSG(commits > 0, "no registration survived the fencing race");
  FR_CHECK_MSG(!fencing.outcomes.empty(), "the fencing thread never fenced a publisher");
  for (const fr::Outcome& outcome : fencing.outcomes) {
    FR_CHECK_MSG(outcome.committed(), "fencing a known publisher must commit: " + describe(outcome));
  }
  require_consistent(*registry);
}

int main(int argc, char** argv) {
  return frtest::run_all(argc, argv);
}
