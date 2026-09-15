// Fabric Registry — registry engine: state, authority, indexes, queries,
// snapshots and persistence.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/registry.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <shared_mutex>
#include <stdexcept>
#include <thread>

#include "fabric_registry/digest.hpp"
#include "fabric_registry/persistence.hpp"
#include "fabric_registry/record_codec.hpp"
#include "fabric_registry/serialization.hpp"
#include "fabric_registry/version.hpp"
#include "registry_internal.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fabric_registry {

// ---------------------------------------------------------------------------
// Hashers
// ---------------------------------------------------------------------------

namespace {

std::size_t hash_bytes(std::size_t seed, const std::uint8_t* data, std::size_t size) noexcept {
  std::size_t accumulator = seed;
  for (std::size_t i = 0; i < size; ++i) {
    accumulator ^= static_cast<std::size_t>(data[i]);
    accumulator *= 1099511628211ull;
  }
  return accumulator;
}

} // namespace

std::size_t IdempotencyKeyHash::operator()(const IdempotencyKey& key) const noexcept {
  std::size_t accumulator = hash_bytes(0x9E3779B97F4A7C15ull, key.publisher.data(), kOpaqueIdBytes);
  return hash_bytes(accumulator, key.attempt.data(), kOpaqueIdBytes);
}

std::size_t IdentityFactHash::operator()(const IdentityFact& fact) const noexcept {
  std::size_t accumulator = static_cast<std::size_t>(fact.kind) + 0x9E3779B97F4A7C15ull;
  accumulator = hash_bytes(accumulator, reinterpret_cast<const std::uint8_t*>(fact.scope.data()), fact.scope.size());
  accumulator = hash_bytes(accumulator ^ 0xFFull, reinterpret_cast<const std::uint8_t*>(fact.value.data()), fact.value.size());
  return accumulator;
}

std::size_t AliasKeyHash::operator()(const AliasKey& key) const noexcept {
  std::size_t accumulator = static_cast<std::size_t>(key.alias_namespace) + 0x9E3779B97F4A7C15ull;
  accumulator = hash_bytes(accumulator, reinterpret_cast<const std::uint8_t*>(key.scope.data()), key.scope.size());
  accumulator = hash_bytes(accumulator ^ 0xFFull, reinterpret_cast<const std::uint8_t*>(key.value.data()), key.value.size());
  return accumulator;
}

// ---------------------------------------------------------------------------
// RegistryState
// ---------------------------------------------------------------------------

RegistryState::RegistryState(const RegistryOptions& options_in, const RegistryLimits& limits_in)
    : options(options_in), limits(limits_in) {}

namespace {

/// Mixes the operating system CSPRNG with a strictly increasing counter so two
/// mints in the same tick still differ, and so a deterministic test source
/// still produces distinct identifiers.
void os_entropy(std::uint8_t* out, std::size_t size) noexcept {
  if (size == 0) {
    return;
  }
#if defined(_WIN32)
  const NTSTATUS status = BCryptGenRandom(nullptr, out, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status == 0) {
    return;
  }
#endif
  // Portable fallback: a thread-local generator seeded from the clock and the
  // thread identity. Used only when the platform CSPRNG is unavailable.
  static thread_local std::mt19937_64 generator([] {
    const auto now = static_cast<std::uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    const auto thread = static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::random_device device;
    std::seed_seq seed{static_cast<std::uint32_t>(now), static_cast<std::uint32_t>(now >> 32),
                       static_cast<std::uint32_t>(thread), static_cast<std::uint32_t>(thread >> 32),
                       device()};
    return std::mt19937_64(seed);
  }());
  for (std::size_t i = 0; i < size; ++i) {
    out[i] = static_cast<std::uint8_t>(generator() & 0xFFu);
  }
}

} // namespace

void fill_entropy(RegistryState& state, std::uint8_t* out, std::size_t size) {
  if (state.options.entropy_source) {
    state.options.entropy_source(out, size);
  } else {
    os_entropy(out, size);
  }
  // Counter mixing: guarantees distinct outputs even when a caller installs a
  // constant entropy source by mistake.
  const std::uint64_t counter = state.mint_counter++;
  CanonicalHasher mixer;
  mixer.begin("fabric-registry/entropy-mix/1");
  mixer.u64(counter);
  mixer.bytes(std::span<const std::uint8_t>(out, size));
  const DigestBytes mixed = mixer.finish();
  for (std::size_t i = 0; i < size; ++i) {
    out[i] = static_cast<std::uint8_t>(out[i] ^ mixed[i % kDigestBytes]);
  }
}

PublisherId mint_publisher_id(RegistryState& state) {
  std::uint8_t material[kOpaqueIdBytes + 8] = {};
  fill_entropy(state, material, sizeof(material));
  IdBytes bytes{};
  std::memcpy(bytes.data(), material, kOpaqueIdBytes);
  if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) {
    bytes[0] = 1;
  }
  return PublisherId::from_bytes(bytes);
}

WorkerBootId mint_worker_boot_id(RegistryState& state) {
  std::uint8_t material[kOpaqueIdBytes + 8] = {};
  fill_entropy(state, material, sizeof(material));
  IdBytes bytes{};
  std::memcpy(bytes.data(), material, kOpaqueIdBytes);
  if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) {
    bytes[0] = 1;
  }
  return WorkerBootId::from_bytes(bytes);
}

bool publisher_known(const RegistryState& state, const PublisherId& id) {
  return state.publishers.find(id) != state.publishers.end();
}

Outcome check_authority(const RegistryState& state, const AuthorityClaim& claim, const RegistrationId& attempt) {
  Outcome outcome(OutcomeCode::Committed, "authority verified");
  outcome.steps.clear();
  if (!claim.is_complete()) {
    return Outcome(OutcomeCode::NoAuthority,
                   "the request carries no complete authority claim (publisher, worker incarnation and epoch are all required)")
        .field_step("authority", "attempt", attempt.to_string(), "the mutation was refused before any state was read");
  }
  if (claim.epoch != state.epoch) {
    return Outcome(OutcomeCode::StaleEpoch, "the request carries a coordinator epoch that is no longer current")
        .field_step("authority", "epoch", claim.epoch.to_string(), "current coordinator epoch is " + state.epoch.to_string());
  }
  const auto publisher = state.publishers.find(claim.publisher);
  if (publisher == state.publishers.end()) {
    return Outcome(OutcomeCode::StaleAuthority, "the publisher is not known to this registry")
        .field_step("authority", "publisher", claim.publisher.to_string(), "no publisher record exists");
  }
  const PublisherRecord& record = publisher->second;
  if (record.state == PublisherState::Retired) {
    return Outcome(OutcomeCode::StaleAuthority, "the publisher has been administratively retired")
        .field_step("authority", "publisher", claim.publisher.to_string(), record.status_reason);
  }
  if (record.state != PublisherState::Active) {
    return Outcome(OutcomeCode::FencedPublisher,
                   "the publisher is not currently attached and may not mutate registry state")
        .field_step("authority", "publisher", claim.publisher.to_string(),
                    record.status_reason.empty() ? std::string("publisher state is fenced") : record.status_reason);
  }
  if (claim.worker_boot != record.current_boot) {
    const bool fenced = std::find(record.fenced_boots.begin(), record.fenced_boots.end(), claim.worker_boot) !=
                        record.fenced_boots.end();
    return Outcome(OutcomeCode::StaleWorkerBoot,
                   fenced ? "the worker incarnation presented by this request has been fenced"
                          : "the worker incarnation presented by this request is not the one currently bound to the publisher")
        .field_step("authority", "worker-boot", claim.worker_boot.to_string(),
                    "current incarnation is " + record.current_boot.to_string());
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// Index maintenance
// ---------------------------------------------------------------------------

void sorted_insert(std::vector<CanonicalId>& values, const CanonicalId& id) {
  const auto position = std::lower_bound(values.begin(), values.end(), id);
  if (position != values.end() && *position == id) {
    return;
  }
  values.insert(position, id);
}

void sorted_erase(std::vector<CanonicalId>& values, const CanonicalId& id) {
  const auto position = std::lower_bound(values.begin(), values.end(), id);
  if (position != values.end() && *position == id) {
    values.erase(position);
  }
}

void index_add(RegistryState& state, const EntityRecord& record) {
  state.by_class[record.entity_class].insert(record.id);
  state.by_lifecycle[record.lifecycle].insert(record.id);
  for (const AliasKey& alias : record.aliases) {
    if (alias_is_unique(alias.alias_namespace)) {
      state.alias_index[alias] = record.id;
    }
  }
  for (const IdentityFact& fact : record.facts) {
    sorted_insert(state.fact_index[fact], record.id);
  }
  if (!record.hardware_identity.is_null()) {
    sorted_insert(state.hardware_index[record.hardware_identity], record.id);
  }
  if (record.fabric.has_value()) {
    state.by_fabric[*record.fabric].insert(record.id);
  }
  if (record.site.has_value()) {
    state.by_site[*record.site].insert(record.id);
  }
  if (!record.evidence.publisher.is_null()) {
    state.evidence_by_publisher[record.evidence.publisher].insert(record.id);
  }
}

void index_remove(RegistryState& state, const EntityRecord& record) {
  // An index map never keeps an empty bucket: the live indexes must be
  // structurally identical to indexes recomputed from the record table, which is
  // exactly what Registry::validate_state() checks.
  if (auto entry = state.by_class.find(record.entity_class); entry != state.by_class.end()) {
    entry->second.erase(record.id);
    if (entry->second.empty()) {
      state.by_class.erase(entry);
    }
  }
  if (auto entry = state.by_lifecycle.find(record.lifecycle); entry != state.by_lifecycle.end()) {
    entry->second.erase(record.id);
    if (entry->second.empty()) {
      state.by_lifecycle.erase(entry);
    }
  }
  for (const AliasKey& alias : record.aliases) {
    if (!alias_is_unique(alias.alias_namespace)) {
      continue;
    }
    const auto entry = state.alias_index.find(alias);
    if (entry != state.alias_index.end() && entry->second == record.id) {
      state.alias_index.erase(entry);
    }
  }
  for (const IdentityFact& fact : record.facts) {
    const auto entry = state.fact_index.find(fact);
    if (entry != state.fact_index.end()) {
      sorted_erase(entry->second, record.id);
      if (entry->second.empty()) {
        state.fact_index.erase(entry);
      }
    }
  }
  if (!record.hardware_identity.is_null()) {
    const auto entry = state.hardware_index.find(record.hardware_identity);
    if (entry != state.hardware_index.end()) {
      sorted_erase(entry->second, record.id);
      if (entry->second.empty()) {
        state.hardware_index.erase(entry);
      }
    }
  }
  if (record.fabric.has_value()) {
    if (auto entry = state.by_fabric.find(*record.fabric); entry != state.by_fabric.end()) {
      entry->second.erase(record.id);
      if (entry->second.empty()) {
        state.by_fabric.erase(entry);
      }
    }
  }
  if (record.site.has_value()) {
    if (auto entry = state.by_site.find(*record.site); entry != state.by_site.end()) {
      entry->second.erase(record.id);
      if (entry->second.empty()) {
        state.by_site.erase(entry);
      }
    }
  }
  if (!record.evidence.publisher.is_null()) {
    if (auto entry = state.evidence_by_publisher.find(record.evidence.publisher);
        entry != state.evidence_by_publisher.end()) {
      entry->second.erase(record.id);
      if (entry->second.empty()) {
        state.evidence_by_publisher.erase(entry);
      }
    }
  }
}

void index_apply(RegistryState& state, const RecordPtr* previous, const EntityRecord& current) {
  if (previous != nullptr && *previous != nullptr) {
    index_remove(state, **previous);
  }
  index_add(state, current);
}

// ---------------------------------------------------------------------------
// Commit helpers
// ---------------------------------------------------------------------------

void append_lineage(RegistryState& state, const CanonicalId& id, const LineageEntry& entry) {
  RecordHistory& history = state.history[id];
  history.id = id;
  history.entries.push_back(entry);
  while (history.entries.size() > state.limits.max_history_entries_per_entity &&
         !history.entries.empty()) {
    history.entries.erase(history.entries.begin());
    history.truncated = true;
  }
}

bool install_record(RegistryState& state,
                    const RecordPtr* previous,
                    EntityRecord next,
                    const CommitContext& context,
                    bool preserve_generation) {
  const bool is_new = previous == nullptr || *previous == nullptr;
  RecordGeneration next_record_generation{};
  if (preserve_generation) {
    if (next.record_generation.is_zero()) {
      return false;
    }
    next_record_generation = next.record_generation;
  } else if (is_new) {
    next_record_generation = RecordGeneration::first();
  } else {
    const std::optional<RecordGeneration> bumped = (*previous)->record_generation.next();
    if (!bumped.has_value()) {
      return false;
    }
    next_record_generation = *bumped;
  }
  const std::optional<RegistryGeneration> next_registry_generation = state.generation.next();
  if (!next_registry_generation.has_value()) {
    return false;
  }
  state.generation = *next_registry_generation;

  // Capture everything that must be read from the PREVIOUS revision before the
  // record table is touched: `previous` points into the table, so reading it
  // after the replacement would report the new revision as its own predecessor.
  const std::optional<RecordGeneration> previous_generation =
      is_new ? std::nullopt : std::optional<RecordGeneration>((*previous)->record_generation);
  const RecordGeneration previous_creation =
      is_new ? next_record_generation : (*previous)->creation_generation;

  next.record_generation = next_record_generation;
  if (!preserve_generation) {
    next.creation_generation = previous_creation;
  }
  next.last_modified = state.generation;
  index_apply(state, previous, next);

  RecordPtr stored = std::make_shared<const EntityRecord>(std::move(next));
  const CanonicalId id = stored->id;
  state.records.insert_or_assign(id, stored);

  LineageEntry entry;
  entry.reason = context.reason;
  entry.resulting_generation = stored->record_generation;
  entry.epoch = state.epoch;
  entry.publisher = context.publisher;
  entry.attempt = context.attempt;
  entry.detail = context.detail;
  entry.previous_generation = previous_generation;
  append_lineage(state, id, entry);
  return true;
}

bool install_publisher(RegistryState& state, PublisherRecord next) {
  const std::optional<RegistryGeneration> bumped = state.generation.next();
  if (!bumped.has_value()) {
    return false;
  }
  state.generation = *bumped;
  next.last_modified = state.generation;
  state.publishers.insert_or_assign(next.id, std::move(next));
  return true;
}

void record_idempotency(RegistryState& state, const IdempotencyEntry& entry) {
  IdempotencyKey key;
  key.publisher = entry.publisher;
  key.attempt = entry.attempt;
  state.idempotency.insert_or_assign(key, entry);
  std::deque<RegistrationId>& order = state.idempotency_order[entry.publisher];
  order.push_back(entry.attempt);
  while (order.size() > state.limits.max_idempotency_entries_per_publisher) {
    const RegistrationId oldest = order.front();
    order.pop_front();
    IdempotencyKey stale;
    stale.publisher = entry.publisher;
    stale.attempt = oldest;
    state.idempotency.erase(stale);
  }
}

const IdempotencyEntry* find_idempotency(const RegistryState& state,
                                         const PublisherId& publisher,
                                         const RegistrationId& attempt) {
  IdempotencyKey key;
  key.publisher = publisher;
  key.attempt = attempt;
  const auto entry = state.idempotency.find(key);
  return entry == state.idempotency.end() ? nullptr : &entry->second;
}

std::size_t demote_records_of_publisher(RegistryState& state,
                                        const PublisherId& publisher,
                                        const WorkerBootId& boot,
                                        bool match_boot_only,
                                        const std::string& detail) {
  std::vector<CanonicalId> affected;
  const auto entry = state.evidence_by_publisher.find(publisher);
  if (entry != state.evidence_by_publisher.end()) {
    affected.assign(entry->second.begin(), entry->second.end());
  }
  std::sort(affected.begin(), affected.end());
  std::size_t demoted = 0;
  for (const CanonicalId& id : affected) {
    const auto record_entry = state.records.find(id);
    if (record_entry == state.records.end()) {
      continue;
    }
    const RecordPtr& existing = record_entry->second;
    if (match_boot_only && existing->evidence.publisher_boot != boot) {
      continue;
    }
    if (existing->evidence.evidence_class != EvidenceClass::ProcessBound) {
      continue;
    }
    EntityRecord next = *existing;
    next.evidence.valid = false;
    const bool was_current = holds_current_authority(next.lifecycle);
    if (was_current) {
      next.lifecycle = Lifecycle::RevalidationRequired;
      next.status_reason = detail;
      ++demoted;
    }
    CommitContext context;
    context.reason = ReasonCode::PublisherFenced;
    context.publisher = publisher;
    context.attempt = RegistrationId{};
    context.detail = detail;
    if (!install_record(state, &existing, std::move(next), context)) {
      break;
    }
  }
  return demoted;
}

std::size_t fence_publisher_internal(RegistryState& state,
                                     const PublisherId& publisher,
                                     FenceReason reason,
                                     const std::string& detail) {
  const auto entry = state.publishers.find(publisher);
  if (entry == state.publishers.end()) {
    return 0;
  }
  PublisherRecord next = entry->second;
  const WorkerBootId fenced_boot = next.current_boot;
  const bool had_boot = !fenced_boot.is_null();
  if (had_boot) {
    if (std::find(next.fenced_boots.begin(), next.fenced_boots.end(), fenced_boot) == next.fenced_boots.end()) {
      next.fenced_boots.push_back(fenced_boot);
      while (next.fenced_boots.size() > state.limits.max_fenced_boots_per_publisher &&
             !next.fenced_boots.empty()) {
        next.fenced_boots.erase(next.fenced_boots.begin());
      }
    }
  }
  next.current_boot = WorkerBootId{};
  next.state = PublisherState::Fenced;
  next.status_reason = std::string(to_string(reason)) + ": " + detail;
  install_publisher(state, std::move(next));

  std::size_t demoted = 0;
  if (had_boot) {
    demoted = demote_records_of_publisher(state, publisher, fenced_boot, true, detail);
  }
  return demoted;
}

std::size_t fence_all_publishers(RegistryState& state, FenceReason reason, const std::string& detail) {
  std::vector<PublisherId> publishers;
  publishers.reserve(state.publishers.size());
  for (const auto& entry : state.publishers) {
    publishers.push_back(entry.first);
  }
  std::sort(publishers.begin(), publishers.end());
  std::size_t demoted = 0;
  for (const PublisherId& publisher : publishers) {
    demoted += fence_publisher_internal(state, publisher, reason, detail);
  }
  return demoted;
}

// ---------------------------------------------------------------------------
// State digest
// ---------------------------------------------------------------------------

StateDigest compute_state_digest(const RegistryState& state) {
  std::vector<CanonicalId> ids;
  ids.reserve(state.records.size());
  for (const auto& entry : state.records) {
    ids.push_back(entry.first);
  }
  std::sort(ids.begin(), ids.end());

  CanonicalHasher hasher;
  hasher.begin("fabric-registry/state/1");
  hasher.u64(state.epoch.value());
  hasher.u64(state.generation.value());
  hasher.sequence(static_cast<std::uint64_t>(ids.size()));
  for (const CanonicalId& id : ids) {
    const auto record = state.records.find(id);
    const std::vector<std::uint8_t> encoded = encode_record(record->second.get() != nullptr ? *record->second : EntityRecord{});
    hasher.bytes(encoded);
  }

  std::vector<PublisherId> publishers;
  publishers.reserve(state.publishers.size());
  for (const auto& entry : state.publishers) {
    publishers.push_back(entry.first);
  }
  std::sort(publishers.begin(), publishers.end());
  hasher.sequence(static_cast<std::uint64_t>(publishers.size()));
  for (const PublisherId& publisher : publishers) {
    ByteWriter writer(128);
    write_publisher(writer, state.publishers.find(publisher)->second);
    hasher.bytes(writer.bytes());
  }
  return StateDigest::from_bytes(hasher.finish());
}

// ---------------------------------------------------------------------------
// Publisher / lineage / idempotency codecs
// ---------------------------------------------------------------------------

void write_publisher(ByteWriter& writer, const PublisherRecord& publisher) {
  writer.u8(static_cast<std::uint8_t>(publisher.state));
  writer.u64(publisher.attach_count);
  writer.u64(publisher.attached_epoch.value());
  writer.raw(publisher.current_boot.data(), kOpaqueIdBytes);
  writer.raw(publisher.id.data(), kOpaqueIdBytes);
  writer.u64(publisher.last_modified.value());
  writer.text(publisher.name);
  writer.text(publisher.status_reason);
  if (publisher.participant.has_value()) {
    writer.u8(1);
    writer.u8(static_cast<std::uint8_t>(publisher.participant->entity_class()));
    writer.raw(publisher.participant->bytes().data(), kOpaqueIdBytes);
  } else {
    writer.u8(0);
  }
  writer.u32(static_cast<std::uint32_t>(publisher.fenced_boots.size()));
  for (const WorkerBootId& boot : publisher.fenced_boots) {
    writer.raw(boot.data(), kOpaqueIdBytes);
  }
}

bool read_publisher(ByteReader& reader, const RegistryLimits& limits, PublisherRecord& out, std::string& error) {
  std::uint8_t raw_state = 0;
  std::uint64_t attach_count = 0;
  std::uint64_t attached_epoch = 0;
  IdBytes current_boot{};
  IdBytes id{};
  std::uint64_t last_modified = 0;
  if (!reader.u8(raw_state) || !reader.u64(attach_count) || !reader.u64(attached_epoch)) {
    error = "publisher header is truncated";
    return false;
  }
  if (raw_state > static_cast<std::uint8_t>(PublisherState::Retired)) {
    error = "publisher declares an invalid state";
    return false;
  }
  if (!reader.raw(current_boot.data(), kOpaqueIdBytes) || !reader.raw(id.data(), kOpaqueIdBytes) ||
      !reader.u64(last_modified)) {
    error = "publisher identity is truncated";
    return false;
  }
  PublisherRecord record;
  record.state = static_cast<PublisherState>(raw_state);
  record.attach_count = attach_count;
  record.attached_epoch = CoordinatorEpoch(attached_epoch);
  record.current_boot = WorkerBootId::from_bytes(current_boot);
  record.id = PublisherId::from_bytes(id);
  record.last_modified = RegistryGeneration(last_modified);
  if (record.id.is_null()) {
    error = "publisher declares a null identity";
    return false;
  }
  if (!reader.text(record.name, limits.max_string_bytes) || !reader.text(record.status_reason, limits.max_string_bytes)) {
    error = "publisher strings are out of bounds";
    return false;
  }
  if (!is_valid_identity_text(record.name) || !is_valid_identity_text(record.status_reason)) {
    error = "publisher strings contain invalid text";
    return false;
  }
  std::uint8_t has_participant = 0;
  if (!reader.u8(has_participant)) {
    error = "publisher participant marker is truncated";
    return false;
  }
  if (has_participant == 1) {
    std::uint8_t raw_class = 0;
    IdBytes participant_bytes{};
    if (!reader.u8(raw_class) || !reader.raw(participant_bytes.data(), kOpaqueIdBytes)) {
      error = "publisher participant reference is truncated";
      return false;
    }
    const EntityClass entity_class = static_cast<EntityClass>(raw_class);
    if (!is_valid_entity_class(entity_class)) {
      error = "publisher participant reference has an invalid class";
      return false;
    }
    CanonicalId participant(entity_class, participant_bytes);
    if (participant.is_null()) {
      error = "publisher participant reference is null";
      return false;
    }
    record.participant = participant;
  } else if (has_participant != 0) {
    error = "publisher participant marker is invalid";
    return false;
  }
  std::uint32_t fenced_count = 0;
  if (!reader.u32(fenced_count)) {
    error = "publisher fenced-boot count is truncated";
    return false;
  }
  if (fenced_count > limits.max_fenced_boots_per_publisher) {
    error = "publisher declares more fenced incarnations than the configured bound";
    return false;
  }
  record.fenced_boots.reserve(fenced_count);
  for (std::uint32_t i = 0; i < fenced_count; ++i) {
    IdBytes boot{};
    if (!reader.raw(boot.data(), kOpaqueIdBytes)) {
      error = "publisher fenced-boot entry is truncated";
      return false;
    }
    const WorkerBootId parsed = WorkerBootId::from_bytes(boot);
    if (parsed.is_null()) {
      error = "publisher fenced-boot entry is null";
      return false;
    }
    record.fenced_boots.push_back(parsed);
  }
  if (record.state == PublisherState::Active && record.current_boot.is_null()) {
    error = "publisher is active but declares no current incarnation";
    return false;
  }
  out = std::move(record);
  return true;
}

void write_lineage(ByteWriter& writer, const LineageEntry& entry) {
  writer.u8(static_cast<std::uint8_t>(entry.reason));
  writer.u64(entry.resulting_generation.value());
  if (entry.previous_generation.has_value()) {
    writer.u8(1);
    writer.u64(entry.previous_generation->value());
  } else {
    writer.u8(0);
  }
  writer.u64(entry.epoch.value());
  writer.raw(entry.publisher.data(), kOpaqueIdBytes);
  writer.raw(entry.attempt.data(), kOpaqueIdBytes);
  writer.text(entry.detail);
}

bool read_lineage(ByteReader& reader, const RegistryLimits& limits, LineageEntry& out, std::string& error) {
  std::uint8_t raw_reason = 0;
  std::uint64_t resulting = 0;
  std::uint8_t has_previous = 0;
  std::uint64_t previous = 0;
  std::uint64_t epoch = 0;
  IdBytes publisher{};
  IdBytes attempt{};
  if (!reader.u8(raw_reason) || !reader.u64(resulting) || !reader.u8(has_previous)) {
    error = "lineage entry is truncated";
    return false;
  }
  if (raw_reason >= kReasonCodeCount) {
    error = "lineage entry declares an invalid reason";
    return false;
  }
  if (has_previous == 1) {
    if (!reader.u64(previous)) {
      error = "lineage entry is truncated";
      return false;
    }
  } else if (has_previous != 0) {
    error = "lineage entry has an invalid previous-generation marker";
    return false;
  }
  if (!reader.u64(epoch) || !reader.raw(publisher.data(), kOpaqueIdBytes) || !reader.raw(attempt.data(), kOpaqueIdBytes)) {
    error = "lineage entry authority is truncated";
    return false;
  }
  LineageEntry entry;
  entry.reason = static_cast<ReasonCode>(raw_reason);
  entry.resulting_generation = RecordGeneration(resulting);
  if (has_previous == 1) {
    entry.previous_generation = RecordGeneration(previous);
  }
  entry.epoch = CoordinatorEpoch(epoch);
  entry.publisher = PublisherId::from_bytes(publisher);
  entry.attempt = RegistrationId::from_bytes(attempt);
  if (!reader.text(entry.detail, limits.max_string_bytes)) {
    error = "lineage detail is out of bounds";
    return false;
  }
  if (!is_valid_identity_text(entry.detail)) {
    error = "lineage detail contains invalid text";
    return false;
  }
  out = std::move(entry);
  return true;
}

void write_idempotency(ByteWriter& writer, const IdempotencyEntry& entry) {
  writer.raw(entry.publisher.data(), kOpaqueIdBytes);
  writer.raw(entry.producer_boot.data(), kOpaqueIdBytes);
  writer.raw(entry.attempt.data(), kOpaqueIdBytes);
  writer.raw(entry.digest.data(), kDigestBytes);
  writer.u8(static_cast<std::uint8_t>(entry.code));
  writer.u64(entry.record_generation.value());
  writer.u64(entry.accepted_at.value());
  writer.text(entry.message);
  if (entry.record.is_null()) {
    writer.u8(0);
  } else {
    writer.u8(1);
    writer.u8(static_cast<std::uint8_t>(entry.record.entity_class()));
    writer.raw(entry.record.bytes().data(), kOpaqueIdBytes);
  }
}

bool read_idempotency(ByteReader& reader, const RegistryLimits& limits, IdempotencyEntry& out, std::string& error) {
  IdBytes publisher{};
  IdBytes boot{};
  IdBytes attempt{};
  DigestBytes digest{};
  std::uint8_t raw_code = 0;
  std::uint64_t record_generation = 0;
  std::uint64_t accepted_at = 0;
  if (!reader.raw(publisher.data(), kOpaqueIdBytes) || !reader.raw(boot.data(), kOpaqueIdBytes) ||
      !reader.raw(attempt.data(), kOpaqueIdBytes) || !reader.raw(digest.data(), kDigestBytes) ||
      !reader.u8(raw_code) || !reader.u64(record_generation) || !reader.u64(accepted_at)) {
    error = "idempotency entry is truncated";
    return false;
  }
  if (raw_code >= kOutcomeCodeCount) {
    error = "idempotency entry declares an invalid outcome code";
    return false;
  }
  IdempotencyEntry entry;
  entry.publisher = PublisherId::from_bytes(publisher);
  entry.producer_boot = WorkerBootId::from_bytes(boot);
  entry.attempt = RegistrationId::from_bytes(attempt);
  entry.digest = RequestDigest::from_bytes(digest);
  entry.code = static_cast<OutcomeCode>(raw_code);
  entry.record_generation = RecordGeneration(record_generation);
  entry.accepted_at = RegistryGeneration(accepted_at);
  if (entry.publisher.is_null() || entry.attempt.is_null()) {
    error = "idempotency entry declares a null identity";
    return false;
  }
  if (!reader.text(entry.message, limits.max_string_bytes)) {
    error = "idempotency message is out of bounds";
    return false;
  }
  if (!is_valid_identity_text(entry.message)) {
    error = "idempotency message contains invalid text";
    return false;
  }
  std::uint8_t has_record = 0;
  if (!reader.u8(has_record)) {
    error = "idempotency record marker is truncated";
    return false;
  }
  if (has_record == 1) {
    std::uint8_t raw_class = 0;
    IdBytes bytes{};
    if (!reader.u8(raw_class) || !reader.raw(bytes.data(), kOpaqueIdBytes)) {
      error = "idempotency record reference is truncated";
      return false;
    }
    const EntityClass entity_class = static_cast<EntityClass>(raw_class);
    if (!is_valid_entity_class(entity_class)) {
      error = "idempotency record reference has an invalid class";
      return false;
    }
    entry.record = CanonicalId(entity_class, bytes);
    if (entry.record.is_null()) {
      error = "idempotency record reference is null";
      return false;
    }
  } else if (has_record != 0) {
    error = "idempotency record marker is invalid";
    return false;
  }
  out = std::move(entry);
  return true;
}

// ---------------------------------------------------------------------------
// Small helpers shared with the mutation translation unit
// ---------------------------------------------------------------------------

ValidationResult normalize_metadata(const std::vector<MetadataEntry>& input,
                                   const RegistryLimits& limits,
                                   std::vector<MetadataEntry>& out) {
  out.clear();
  if (input.size() > limits.max_metadata_entries) {
    return ValidationResult::failure("the request carries more metadata entries than the configured bound");
  }
  std::size_t total = 0;
  out.reserve(input.size());
  for (const MetadataEntry& entry : input) {
    MetadataEntry normalized;
    normalized.key.assign(trim_ascii(entry.key));
    normalized.value.assign(trim_ascii(entry.value));
    if (normalized.key.empty()) {
      return ValidationResult::failure("a metadata entry has an empty key");
    }
    if (normalized.key.size() > limits.max_string_bytes) {
      return ValidationResult::failure("a metadata key exceeds the configured string bound");
    }
    if (normalized.value.size() > limits.max_metadata_value_bytes) {
      return ValidationResult::failure("a metadata value exceeds the configured metadata value bound");
    }
    if (!is_valid_identity_text(normalized.key) || !is_valid_identity_text(normalized.value)) {
      return ValidationResult::failure("a metadata entry contains text that is not valid identity text");
    }
    total += normalized.key.size() + normalized.value.size();
    if (total > limits.max_metadata_bytes_per_entity) {
      return ValidationResult::failure("the request metadata exceeds the configured per-entity metadata bound");
    }
    out.push_back(std::move(normalized));
  }
  std::sort(out.begin(), out.end());
  for (std::size_t i = 1; i < out.size(); ++i) {
    if (out[i - 1].key == out[i].key) {
      return ValidationResult::failure("the request carries a duplicate metadata key: " + out[i].key);
    }
  }
  return ValidationResult::success();
}

AliasScopeInput scope_input_for(const ScopeRef& scope, EntityClass entity_class) {
  AliasScopeInput input;
  input.fabric = scope.fabric;
  input.site = scope.site;
  input.entity_class = entity_class;
  input.parent_device = scope.parent_device;
  return input;
}

AliasIssue build_alias_keys(const std::vector<AliasInput>& inputs,
                            const AliasScopeInput& scope,
                            std::size_t max_string_bytes,
                            std::vector<AliasKey>& out) {
  out.clear();
  std::vector<AliasKey> keys;
  keys.reserve(inputs.size());
  for (const AliasInput& input : inputs) {
    const AliasNameResult name = canonicalize_alias(input.alias_namespace, input.value, max_string_bytes);
    if (!name) {
      return name.issue;
    }
    const AliasKeyResult key = make_alias_key(*name.name, scope);
    if (!key) {
      return key.issue;
    }
    keys.push_back(*key.key);
  }
  std::sort(keys.begin(), keys.end());
  keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
  out = std::move(keys);
  return AliasIssue::None;
}

std::string describe_facts(const std::vector<IdentityFact>& facts) {
  std::string out;
  for (std::size_t i = 0; i < facts.size(); ++i) {
    if (i != 0) {
      out += "; ";
    }
    out += render_fact(facts[i]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Enum rendering
// ---------------------------------------------------------------------------

std::string_view to_string(AdmissionMode value) noexcept {
  switch (value) {
    case AdmissionMode::RequireCurrent:
      return "require-current";
    case AdmissionMode::AllowObservation:
      return "allow-observation";
    case AdmissionMode::AllowCandidate:
      return "allow-candidate";
  }
  return "unknown";
}

std::string_view to_string(ReconcileResolution value) noexcept {
  switch (value) {
    case ReconcileResolution::Auto:
      return "auto";
    case ReconcileResolution::ForceNew:
      return "force-new";
    case ReconcileResolution::ForceExisting:
      return "force-existing";
  }
  return "unknown";
}

std::string_view to_string(ConflictResolution value) noexcept {
  switch (value) {
    case ConflictResolution::KeepCurrent:
      return "keep-current";
    case ConflictResolution::Retire:
      return "retire";
    case ConflictResolution::Reject:
      return "reject";
  }
  return "unknown";
}

std::string_view to_string(PublisherState value) noexcept {
  switch (value) {
    case PublisherState::Unregistered:
      return "unregistered";
    case PublisherState::Active:
      return "active";
    case PublisherState::Fenced:
      return "fenced";
    case PublisherState::Retired:
      return "retired";
  }
  return "unknown";
}

std::string_view to_string(FenceReason value) noexcept {
  switch (value) {
    case FenceReason::SessionLost:
      return "session-lost";
    case FenceReason::HeartbeatExpired:
      return "heartbeat-expired";
    case FenceReason::ExplicitDetach:
      return "explicit-detach";
    case FenceReason::EpochAdvanced:
      return "epoch-advanced";
    case FenceReason::Administrative:
      return "administrative";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Options validation
// ---------------------------------------------------------------------------

ValidationResult RegistryOptions::validate() const {
  ValidationResult result = limits.validate();
  if (!result) {
    return result;
  }
  if (initial_epoch.is_zero()) {
    return ValidationResult::failure("initial_epoch must be at least 1; zero means 'no authority'");
  }
  if (local_publisher_name.size() > limits.max_string_bytes) {
    return ValidationResult::failure("local_publisher_name exceeds the configured string bound");
  }
  if (!is_valid_identity_text(local_publisher_name)) {
    return ValidationResult::failure("local_publisher_name is not valid identity text");
  }
  return ValidationResult::success();
}

// ---------------------------------------------------------------------------
// Registry construction
// ---------------------------------------------------------------------------

namespace {

/// Binds a fresh incarnation to the embedded local publisher, minting the
/// publisher identity on first use. The stable publisher identity survives an
/// epoch advance; only the incarnation changes.
void create_local_publisher(RegistryState& state) {
  if (state.local_publisher.is_null()) {
    state.local_publisher = mint_publisher_id(state);
  }
  state.local_boot = mint_worker_boot_id(state);
  PublisherRecord publisher;
  const auto existing = state.publishers.find(state.local_publisher);
  if (existing != state.publishers.end()) {
    publisher = existing->second;
    if (!publisher.current_boot.is_null() &&
        std::find(publisher.fenced_boots.begin(), publisher.fenced_boots.end(), publisher.current_boot) ==
            publisher.fenced_boots.end()) {
      publisher.fenced_boots.push_back(publisher.current_boot);
      while (publisher.fenced_boots.size() > state.limits.max_fenced_boots_per_publisher &&
             !publisher.fenced_boots.empty()) {
        publisher.fenced_boots.erase(publisher.fenced_boots.begin());
      }
    }
  } else {
    publisher.id = state.local_publisher;
    publisher.name = state.options.local_publisher_name;
  }
  publisher.current_boot = state.local_boot;
  publisher.attached_epoch = state.epoch;
  publisher.state = PublisherState::Active;
  publisher.attach_count += 1;
  publisher.status_reason = "embedded local publisher";
  install_publisher(state, std::move(publisher));
}

} // namespace

} // namespace fabric_registry

namespace fabric_registry {

Registry::Registry(RegistryOptions options) {
  const ValidationResult validation = options.validate();
  if (!validation) {
    throw std::invalid_argument("Fabric Registry options are invalid: " + validation.message);
  }
  impl_ = std::make_unique<Impl>(options, options.limits);
  RegistryState& state = impl_->state;
  state.epoch = options.initial_epoch;
  if (options.create_local_publisher) {
    create_local_publisher(state);
  }
}

Registry::~Registry() = default;

const RegistryLimits& Registry::limits() const noexcept { return impl_->state.limits; }

CoordinatorEpoch Registry::epoch() const noexcept {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  return impl_->state.epoch;
}

AuthorityClaim Registry::local_authority() const noexcept {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  AuthorityClaim claim;
  claim.publisher = impl_->state.local_publisher;
  claim.worker_boot = impl_->state.local_boot;
  claim.epoch = impl_->state.epoch;
  return claim;
}

// ---------------------------------------------------------------------------
// Authority operations
// ---------------------------------------------------------------------------

Outcome Registry::advance_epoch(std::size_t& demoted) {
  RegistryState& state = impl_->state;
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const std::optional<CoordinatorEpoch> next = state.epoch.next();
  if (!next.has_value()) {
    return Outcome(OutcomeCode::ResourceLimit, "the coordinator epoch space is exhausted");
  }
  Outcome outcome(OutcomeCode::Committed, "coordinator epoch advanced");
  outcome.steps.push_back(ExplanationStep{"epoch", "coordinator-epoch", state.epoch.to_string(),
                                          "advancing to " + next->to_string()});
  state.epoch = *next;
  const std::string detail = "coordinator epoch advanced to " + state.epoch.to_string();
  demoted = fence_all_publishers(state, FenceReason::EpochAdvanced, detail);
  if (state.options.create_local_publisher) {
    create_local_publisher(state);
  }
  outcome.epoch = state.epoch;
  outcome.state_generation = state.generation;
  outcome.field_step("epoch", "demoted-records", std::to_string(demoted),
                     "records whose process-bound evidence lapsed were moved to revalidation-required");
  return outcome;
}

PublisherAttachResult Registry::attach_publisher(const PublisherAttachRequest& request) {
  RegistryState& state = impl_->state;
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  PublisherAttachResult result;
  if (request.protocol_version != 0 && request.protocol_version != FABRIC_REGISTRY_PROTOCOL_VERSION) {
    result.outcome = Outcome(OutcomeCode::ProtocolViolation,
                             "the client protocol version is not supported by this build")
                         .field_step("attach", "protocol-version", std::to_string(request.protocol_version),
                                     std::string("this build speaks protocol version ") +
                                         std::to_string(FABRIC_REGISTRY_PROTOCOL_VERSION));
    return result;
  }
  if (request.name.size() > state.limits.max_string_bytes) {
    result.outcome = Outcome(OutcomeCode::ResourceLimit, "the publisher name exceeds the configured string bound");
    return result;
  }
  if (!is_valid_identity_text(request.name)) {
    result.outcome = Outcome(OutcomeCode::MalformedRequest, "the publisher name is not valid identity text");
    return result;
  }

  PublisherId publisher = request.publisher;
  bool created = false;
  if (publisher.is_null()) {
    if (state.publishers.size() >= state.limits.max_publishers) {
      result.outcome = Outcome(OutcomeCode::ResourceLimit, "the registry holds the maximum number of publishers");
      return result;
    }
    publisher = mint_publisher_id(state);
    created = true;
  } else if (!publisher_known(state, publisher)) {
    result.outcome = Outcome(OutcomeCode::StaleAuthority, "the requested publisher identity is not known to this registry")
                         .field_step("attach", "publisher", publisher.to_string(),
                                     "a publisher may only reattach under an identity it already holds");
    return result;
  }

  PublisherRecord record;
  const auto existing = state.publishers.find(publisher);
  if (existing != state.publishers.end()) {
    record = existing->second;
    if (record.state == PublisherState::Retired) {
      result.outcome = Outcome(OutcomeCode::StaleAuthority, "the publisher has been administratively retired")
                           .field_step("attach", "publisher", publisher.to_string(), record.status_reason);
      return result;
    }
  } else {
    record.id = publisher;
  }
  if (!request.name.empty()) {
    record.name = request.name;
  }

  if (!record.current_boot.is_null()) {
    const WorkerBootId previous_boot = record.current_boot;
    if (std::find(record.fenced_boots.begin(), record.fenced_boots.end(), previous_boot) == record.fenced_boots.end()) {
      record.fenced_boots.push_back(previous_boot);
      while (record.fenced_boots.size() > state.limits.max_fenced_boots_per_publisher && !record.fenced_boots.empty()) {
        record.fenced_boots.erase(record.fenced_boots.begin());
      }
    }
    result.fenced_previous = true;
  }

  const WorkerBootId previous_boot = record.current_boot;
  record.current_boot = mint_worker_boot_id(state);
  record.attached_epoch = state.epoch;
  record.state = PublisherState::Active;
  record.attach_count += 1;
  record.status_reason = created ? "created by attach" : "reattached";
  if (!install_publisher(state, std::move(record))) {
    result.outcome = Outcome(OutcomeCode::ResourceLimit, "the registry generation space is exhausted");
    return result;
  }
  if (result.fenced_previous && !previous_boot.is_null()) {
    demote_records_of_publisher(state, publisher, previous_boot, true,
                                "publisher reattached with a new incarnation");
  }

  result.outcome = Outcome(OutcomeCode::Committed, created ? "publisher created and attached"
                                                           : "publisher reattached with a fresh incarnation");
  result.outcome.epoch = state.epoch;
  result.outcome.state_generation = state.generation;
  result.outcome.steps.push_back(ExplanationStep{"attach", "publisher", publisher.to_string(),
                                                 created ? "a fresh publisher identity was minted"
                                                         : "the stable publisher identity was reused"});
  if (result.fenced_previous) {
    result.outcome.steps.push_back(ExplanationStep{"attach", "fenced-incarnation", previous_boot.to_string(),
                                                   "the previous incarnation is permanently fenced"});
  }
  result.publisher = publisher;
  result.worker_boot = state.publishers.find(publisher)->second.current_boot;
  result.epoch = state.epoch;
  return result;
}

Outcome Registry::detach_publisher(const AuthorityClaim& claim, FenceReason reason) {
  RegistryState& state = impl_->state;
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, claim, RegistrationId{});
  if (!authority.committed()) {
    return authority;
  }
  fence_publisher_internal(state, claim.publisher, reason, "publisher detached");
  Outcome outcome(OutcomeCode::Committed, "publisher detached and its incarnation fenced");
  outcome.state_generation = state.generation;
  outcome.epoch = state.epoch;
  outcome.steps.push_back(ExplanationStep{"detach", "publisher", claim.publisher.to_string(),
                                          std::string("reason: ") + std::string(to_string(reason))});
  return outcome;
}

Outcome Registry::fence_publisher(const PublisherId& publisher, FenceReason reason, std::size_t& demoted) {
  RegistryState& state = impl_->state;
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  if (!publisher_known(state, publisher)) {
    return Outcome(OutcomeCode::StaleAuthority, "the publisher is not known to this registry")
        .field_step("fence", "publisher", publisher.to_string(), "no publisher record exists");
  }
  demoted = fence_publisher_internal(state, publisher, reason, std::string("fenced: ") + std::string(to_string(reason)));
  Outcome outcome(OutcomeCode::Committed, "publisher fenced");
  outcome.epoch = state.epoch;
  outcome.state_generation = state.generation;
  outcome.field_step("fence", "demoted-records", std::to_string(demoted),
                     "records whose current evidence came from the fenced incarnation were moved to revalidation-required");
  return outcome;
}

std::optional<PublisherRecord> Registry::publisher(const PublisherId& id) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const auto entry = impl_->state.publishers.find(id);
  if (entry == impl_->state.publishers.end()) {
    return std::nullopt;
  }
  return entry->second;
}

std::vector<PublisherRecord> Registry::publishers() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  std::vector<PublisherRecord> out;
  out.reserve(impl_->state.publishers.size());
  for (const auto& entry : impl_->state.publishers) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(), [](const PublisherRecord& left, const PublisherRecord& right) {
    return left.id < right.id;
  });
  return out;
}

AuthorityStats Registry::authority_stats() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  AuthorityStats stats;
  stats.publishers = impl_->state.publishers.size();
  for (const auto& entry : impl_->state.publishers) {
    if (entry.second.state == PublisherState::Active) {
      ++stats.active_publishers;
    }
    if (entry.second.state == PublisherState::Fenced) {
      ++stats.fenced_publishers;
    }
    stats.fenced_boots += entry.second.fenced_boots.size();
  }
  stats.epoch = impl_->state.epoch;
  return stats;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

Outcome Registry::lookup(const CanonicalId& id, std::shared_ptr<const EntityRecord>& out) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  if (id.is_null()) {
    return Outcome(OutcomeCode::MalformedRequest, "the lookup identity is null");
  }
  const auto entry = impl_->state.records.find(id);
  if (entry == impl_->state.records.end()) {
    Outcome outcome(OutcomeCode::NotFound, "no record exists for the requested canonical identity");
    outcome.with_record(id);
    outcome.steps.push_back(ExplanationStep{"lookup", "record", id.to_string(), "the canonical identity is not present"});
    return outcome;
  }
  out = entry->second;
  Outcome outcome(OutcomeCode::Committed, "record found");
  outcome.with_record(id);
  outcome.with_generation(entry->second->record_generation);
  outcome.epoch = impl_->state.epoch;
  outcome.state_generation = impl_->state.generation;
  return outcome;
}

Outcome Registry::lookup_by_alias(const AliasKey& key, std::shared_ptr<const EntityRecord>& out) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  if (!alias_is_unique(key.alias_namespace)) {
    return Outcome(OutcomeCode::MalformedRequest,
                   "aliases in this namespace are informational and are never resolved to an identity")
        .field_step("lookup", "namespace", std::string(to_string(key.alias_namespace)),
                    "informational aliases are stored on records but not indexed");
  }
  const auto entry = impl_->state.alias_index.find(key);
  if (entry == impl_->state.alias_index.end()) {
    Outcome outcome(OutcomeCode::NotFound, "no record holds the requested alias");
    outcome.steps.push_back(ExplanationStep{"lookup", "alias", key.to_string(), "the alias is not bound"});
    return outcome;
  }
  const auto record = impl_->state.records.find(entry->second);
  out = record->second;
  Outcome outcome(OutcomeCode::Committed, "record found by alias");
  outcome.with_record(entry->second);
  outcome.with_generation(record->second->record_generation);
  outcome.steps.push_back(ExplanationStep{"lookup", "alias", key.to_string(), "the alias resolves to " + entry->second.to_string()});
  return outcome;
}

Outcome Registry::lookup_by_fact(const IdentityFact& fact, std::vector<CanonicalId>& out) const {
  out.clear();
  const FactResult canonical = canonicalize_fact(fact.kind, fact.scope, fact.value, impl_->state.limits.max_string_bytes);
  if (!canonical) {
    return Outcome(OutcomeCode::MalformedRequest, "the lookup fact is not a usable identity fact")
        .field_step("lookup", "fact", render_fact(fact), std::string(to_string(canonical.issue)));
  }
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const auto entry = impl_->state.fact_index.find(*canonical.fact);
  if (entry == impl_->state.fact_index.end()) {
    return Outcome(OutcomeCode::NotFound, "no record carries the requested identity fact");
  }
  out = entry->second;
  Outcome outcome(OutcomeCode::Committed, "records found by identity fact");
  outcome.related = out;
  return outcome;
}

Outcome Registry::lookup_by_hardware_identity(const StableHardwareIdentity& identity,
                                              std::vector<CanonicalId>& out) const {
  out.clear();
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const auto entry = impl_->state.hardware_index.find(identity);
  if (entry == impl_->state.hardware_index.end()) {
    return Outcome(OutcomeCode::NotFound, "no record carries the requested stable hardware identity");
  }
  out = entry->second;
  Outcome outcome(OutcomeCode::Committed, "records found by stable hardware identity");
  outcome.related = out;
  return outcome;
}

std::vector<CanonicalId> Registry::entities_of_class(EntityClass entity_class, std::size_t limit) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  std::vector<CanonicalId> out;
  const auto entry = impl_->state.by_class.find(entity_class);
  if (entry == impl_->state.by_class.end()) {
    return out;
  }
  const std::size_t bound = std::min({limit, impl_->state.limits.max_enumeration, entry->second.size()});
  out.assign(entry->second.begin(), entry->second.end());
  std::sort(out.begin(), out.end());
  if (out.size() > bound) {
    out.resize(bound);
  }
  return out;
}

std::vector<CanonicalId> Registry::entities_of_lifecycle(Lifecycle lifecycle, std::size_t limit) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  std::vector<CanonicalId> out;
  const auto entry = impl_->state.by_lifecycle.find(lifecycle);
  if (entry == impl_->state.by_lifecycle.end()) {
    return out;
  }
  const std::size_t bound = std::min({limit, impl_->state.limits.max_enumeration, entry->second.size()});
  out.assign(entry->second.begin(), entry->second.end());
  std::sort(out.begin(), out.end());
  if (out.size() > bound) {
    out.resize(bound);
  }
  return out;
}

std::vector<CanonicalId> Registry::all_ids(std::size_t limit) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  std::vector<CanonicalId> out;
  out.reserve(impl_->state.records.size());
  for (const auto& entry : impl_->state.records) {
    out.push_back(entry.first);
  }
  std::sort(out.begin(), out.end());
  const std::size_t bound = std::min({limit, impl_->state.limits.max_enumeration, out.size()});
  if (out.size() > bound) {
    out.resize(bound);
  }
  return out;
}

Outcome Registry::history(const CanonicalId& id, RecordHistory& out) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const auto entry = impl_->state.history.find(id);
  if (entry == impl_->state.history.end()) {
    return Outcome(OutcomeCode::NotFound, "no lineage history exists for the requested identity")
        .with_record(id);
  }
  out = entry->second;
  if (out.entries.size() > impl_->state.limits.max_history_query) {
    out.entries.erase(out.entries.begin(),
                      out.entries.begin() + static_cast<std::ptrdiff_t>(out.entries.size() - impl_->state.limits.max_history_query));
    out.truncated = true;
  }
  Outcome outcome(OutcomeCode::Committed, "lineage history found");
  outcome.with_record(id);
  return outcome;
}

Outcome Registry::validate_reference(const CanonicalId& id, std::optional<RecordGeneration> expected_generation) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const auto entry = impl_->state.records.find(id);
  if (entry == impl_->state.records.end()) {
    Outcome outcome(OutcomeCode::NotFound, "the referenced record does not exist");
    outcome.with_record(id);
    return outcome;
  }
  const RecordPtr& record = entry->second;
  Outcome outcome(OutcomeCode::Committed, "the reference is current");
  outcome.with_record(id);
  outcome.with_generation(record->record_generation);
  outcome.epoch = impl_->state.epoch;
  outcome.state_generation = impl_->state.generation;
  if (!holds_current_authority(record->lifecycle)) {
    outcome.code = OutcomeCode::NotCurrent;
    outcome.message = "the referenced record no longer holds current authority";
    outcome.steps.push_back(ExplanationStep{"validate", "lifecycle", std::string(to_string(record->lifecycle)),
                                            record->status_reason.empty() ? "the record is not current"
                                                                          : record->status_reason});
    return outcome;
  }
  if (expected_generation.has_value() && *expected_generation != record->record_generation) {
    outcome.code = OutcomeCode::StaleGeneration;
    outcome.message = "the referenced record has moved to a newer generation";
    outcome.steps.push_back(ExplanationStep{"validate", "record-generation", expected_generation->to_string(),
                                            "the record is at generation " + record->record_generation.to_string()});
    return outcome;
  }
  return outcome;
}

bool Registry::is_current(const CanonicalId& id, std::optional<RecordGeneration> expected_generation) const {
  return validate_reference(id, expected_generation).committed();
}

bool Registry::snapshot_current(const Snapshot& snapshot) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  return snapshot.generation() == impl_->state.generation && snapshot.epoch() == impl_->state.epoch;
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

Snapshot Registry::snapshot() const {
  RegistryState& state = impl_->state;
  std::shared_lock<std::shared_mutex> guard(state.mutex);
  Snapshot snapshot;
  snapshot.generation_ = state.generation;
  snapshot.epoch_ = state.epoch;
  snapshot.sequence_ = SnapshotSequence(state.snapshot_sequence.fetch_add(1, std::memory_order_relaxed) + 1);
  snapshot.records_.reserve(state.records.size());
  for (const auto& entry : state.records) {
    snapshot.records_.push_back(entry.second);
  }
  std::sort(snapshot.records_.begin(), snapshot.records_.end(),
            [](const RecordPtr& left, const RecordPtr& right) { return left->id < right->id; });
  for (const RecordPtr& record : snapshot.records_) {
    for (const AliasKey& alias : record->aliases) {
      if (alias_is_unique(alias.alias_namespace)) {
        snapshot.alias_index_.insert_or_assign(alias, record->id);
      }
    }
  }
  snapshot.digest_ = compute_state_digest(state);
  return snapshot;
}

bool snapshot_is_current(const Registry& registry, const Snapshot& snapshot) {
  return registry.snapshot_current(snapshot);
}

StateDigest Registry::state_digest() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  return compute_state_digest(impl_->state);
}

Snapshot::RecordPtr Snapshot::find(const CanonicalId& id) const noexcept {
  const auto position = std::lower_bound(
      records_.begin(), records_.end(), id,
      [](const RecordPtr& record, const CanonicalId& target) { return record->id < target; });
  if (position == records_.end() || !((*position)->id == id)) {
    return nullptr;
  }
  return *position;
}

std::optional<CanonicalId> Snapshot::find_by_alias(const AliasKey& key) const noexcept {
  const auto entry = alias_index_.find(key);
  if (entry == alias_index_.end()) {
    return std::nullopt;
  }
  return entry->second;
}

std::vector<Snapshot::RecordPtr> Snapshot::of_class(EntityClass entity_class) const {
  std::vector<RecordPtr> out;
  for (const RecordPtr& record : records_) {
    if (record->entity_class == entity_class) {
      out.push_back(record);
    }
  }
  return out;
}

std::string Snapshot::render() const {
  std::string out;
  out += "snapshot-generation: ";
  out += generation_.to_string();
  out += '\n';
  out += "coordinator-epoch: ";
  out += epoch_.to_string();
  out += '\n';
  out += "snapshot-sequence: ";
  out += sequence_.to_string();
  out += '\n';
  out += "state-digest: ";
  out += digest_.to_string();
  out += '\n';
  out += "records: ";
  out += std::to_string(records_.size());
  out += '\n';
  out += "indexed-aliases: ";
  out += std::to_string(alias_index_.size());
  out += '\n';
  for (const RecordPtr& record : records_) {
    out += render_record(*record);
  }
  return out;
}

std::string Snapshot::render_json() const {
  std::string out = "{\n";
  out += "  \"coordinator_epoch\": ";
  out += epoch_.to_string();
  out += ",\n  \"snapshot_generation\": ";
  out += generation_.to_string();
  out += ",\n  \"snapshot_sequence\": ";
  out += sequence_.to_string();
  out += ",\n  \"state_digest\": \"";
  out += digest_.to_string();
  out += "\",\n  \"record_count\": ";
  out += std::to_string(records_.size());
  out += ",\n  \"alias_count\": ";
  out += std::to_string(alias_index_.size());
  out += ",\n  \"records\": [";
  for (std::size_t i = 0; i < records_.size(); ++i) {
    out += i == 0 ? "\n" : ",\n";
    out += "  ";
    out += render_record_json(*records_[i]);
  }
  if (!records_.empty()) {
    out += "\n  ";
  }
  out += "]\n}\n";
  return out;
}

// ---------------------------------------------------------------------------
// Statistics and validation
// ---------------------------------------------------------------------------

RegistryStats Registry::stats() const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const RegistryState& state = impl_->state;
  RegistryStats stats;
  stats.entities = state.records.size();
  const auto count_lifecycle = [&](Lifecycle lifecycle) -> std::size_t {
    const auto entry = state.by_lifecycle.find(lifecycle);
    return entry == state.by_lifecycle.end() ? 0 : entry->second.size();
  };
  stats.current_entities = count_lifecycle(Lifecycle::Current);
  stats.discovered_entities = count_lifecycle(Lifecycle::Discovered);
  stats.candidate_entities = count_lifecycle(Lifecycle::Candidate);
  stats.revalidation_required_entities = count_lifecycle(Lifecycle::RevalidationRequired);
  stats.superseded_entities = count_lifecycle(Lifecycle::Superseded);
  stats.retired_entities = count_lifecycle(Lifecycle::Retired);
  stats.tombstoned_entities = count_lifecycle(Lifecycle::Tombstoned);
  stats.conflicted_entities = count_lifecycle(Lifecycle::Conflicted);
  stats.rejected_entities = count_lifecycle(Lifecycle::Rejected);
  stats.aliases = 0;
  for (const auto& entry : state.records) {
    stats.aliases += entry.second->aliases.size();
  }
  stats.indexed_aliases = state.alias_index.size();
  stats.publishers = state.publishers.size();
  for (const auto& entry : state.publishers) {
    if (entry.second.state == PublisherState::Active) {
      ++stats.active_publishers;
    }
  }
  stats.lineage_entries = 0;
  for (const auto& entry : state.history) {
    stats.lineage_entries += entry.second.entries.size();
  }
  stats.idempotency_records = state.idempotency.size();
  stats.generation = state.generation;
  stats.epoch = state.epoch;
  return stats;
}

Outcome Registry::validate_state(std::string& report) const {
  std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
  const RegistryState& state = impl_->state;
  std::vector<std::string> problems;

  for (const auto& entry : state.records) {
    const EntityRecord& record = *entry.second;
    if (record.id != entry.first) {
      problems.push_back("record table key does not match the record identity: " + entry.first.to_string());
    }
    if (!record.is_well_formed()) {
      problems.push_back("record violates a structural invariant: " + record.id.to_string());
    }
  }

  // Recompute every index from the record table and compare.
  std::unordered_map<EntityClass, std::unordered_set<CanonicalId>> by_class;
  std::unordered_map<Lifecycle, std::unordered_set<CanonicalId>> by_lifecycle;
  std::unordered_map<AliasKey, CanonicalId, AliasKeyHash> alias_index;
  std::unordered_map<IdentityFact, std::vector<CanonicalId>, IdentityFactHash> fact_index;
  std::unordered_map<StableHardwareIdentity, std::vector<CanonicalId>> hardware_index;
  std::unordered_map<FabricId, std::unordered_set<CanonicalId>> by_fabric;
  std::unordered_map<SiteId, std::unordered_set<CanonicalId>> by_site;
  std::unordered_map<PublisherId, std::unordered_set<CanonicalId>> evidence_by_publisher;

  std::vector<CanonicalId> ids;
  ids.reserve(state.records.size());
  for (const auto& entry : state.records) {
    ids.push_back(entry.first);
  }
  std::sort(ids.begin(), ids.end());
  for (const CanonicalId& id : ids) {
    const EntityRecord& record = *state.records.find(id)->second;
    by_class[record.entity_class].insert(record.id);
    by_lifecycle[record.lifecycle].insert(record.id);
    for (const AliasKey& alias : record.aliases) {
      if (!alias_is_unique(alias.alias_namespace)) {
        continue;
      }
      const auto inserted = alias_index.emplace(alias, record.id);
      if (!inserted.second && inserted.first->second != record.id) {
        problems.push_back("alias " + alias.to_string() + " is bound to more than one record: " +
                           inserted.first->second.to_string() + " and " + record.id.to_string());
      }
    }
    for (const IdentityFact& fact : record.facts) {
      sorted_insert(fact_index[fact], record.id);
    }
    if (!record.hardware_identity.is_null()) {
      sorted_insert(hardware_index[record.hardware_identity], record.id);
    }
    if (record.fabric.has_value()) {
      by_fabric[*record.fabric].insert(record.id);
    }
    if (record.site.has_value()) {
      by_site[*record.site].insert(record.id);
    }
    if (!record.evidence.publisher.is_null()) {
      evidence_by_publisher[record.evidence.publisher].insert(record.id);
    }
    if (state.history.find(record.id) == state.history.end()) {
      problems.push_back("record has no lineage history: " + record.id.to_string());
    }
  }

  const auto compare_sets = [&problems](const char* name,
                                        const auto& live,
                                        const auto& recomputed) {
    if (live.size() != recomputed.size()) {
      problems.push_back(std::string(name) + " index size differs: live " + std::to_string(live.size()) +
                         ", recomputed " + std::to_string(recomputed.size()));
      return;
    }
    for (const auto& entry : recomputed) {
      const auto found = live.find(entry.first);
      if (found == live.end()) {
        problems.push_back(std::string(name) + " index is missing an entry that the record table implies");
        return;
      }
      if (found->second != entry.second) {
        problems.push_back(std::string(name) + " index disagrees with the record table");
        return;
      }
    }
  };
  compare_sets("class", state.by_class, by_class);
  compare_sets("lifecycle", state.by_lifecycle, by_lifecycle);
  compare_sets("alias", state.alias_index, alias_index);
  compare_sets("fact", state.fact_index, fact_index);
  compare_sets("hardware", state.hardware_index, hardware_index);
  compare_sets("fabric", state.by_fabric, by_fabric);
  compare_sets("site", state.by_site, by_site);
  compare_sets("evidence-publisher", state.evidence_by_publisher, evidence_by_publisher);

  for (const auto& entry : state.publishers) {
    if (entry.second.id != entry.first) {
      problems.push_back("publisher table key does not match the publisher identity");
    }
    if (entry.second.state == PublisherState::Active && entry.second.current_boot.is_null()) {
      problems.push_back("publisher is active but holds no worker incarnation: " + entry.first.to_string());
    }
  }

  report.clear();
  report += "entities: ";
  report += std::to_string(state.records.size());
  report += '\n';
  report += "indexed-aliases: ";
  report += std::to_string(state.alias_index.size());
  report += '\n';
  report += "publishers: ";
  report += std::to_string(state.publishers.size());
  report += '\n';
  report += "registry-generation: ";
  report += state.generation.to_string();
  report += '\n';
  report += "coordinator-epoch: ";
  report += state.epoch.to_string();
  report += '\n';
  report += "state-digest: ";
  report += compute_state_digest(state).to_string();
  report += '\n';
  if (problems.empty()) {
    report += "consistent: true\n";
    Outcome outcome(OutcomeCode::Committed, "registry state is internally consistent");
    outcome.state_generation = state.generation;
    return outcome;
  }
  report += "consistent: false\n";
  for (const std::string& problem : problems) {
    report += "problem: ";
    report += problem;
    report += '\n';
  }
  Outcome outcome(OutcomeCode::IntegrityFailure, "registry state is inconsistent");
  outcome.steps.push_back(ExplanationStep{"validate", "problems", std::to_string(problems.size()),
                                          problems.front()});
  return outcome;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

Outcome Registry::save(const std::filesystem::path& path, bool flush_to_disk) const {
  persistence::DurableState durable;
  {
    std::shared_lock<std::shared_mutex> guard(impl_->state.mutex);
    const RegistryState& state = impl_->state;
    durable.generation = state.generation;
    durable.epoch = state.epoch;
    std::vector<CanonicalId> ids;
    ids.reserve(state.records.size());
    for (const auto& entry : state.records) {
      ids.push_back(entry.first);
    }
    std::sort(ids.begin(), ids.end());
    durable.records.reserve(ids.size());
    for (const CanonicalId& id : ids) {
      durable.records.push_back(*state.records.find(id)->second);
    }
    std::vector<PublisherId> publishers;
    publishers.reserve(state.publishers.size());
    for (const auto& entry : state.publishers) {
      publishers.push_back(entry.first);
    }
    std::sort(publishers.begin(), publishers.end());
    durable.publishers.reserve(publishers.size());
    for (const PublisherId& id : publishers) {
      durable.publishers.push_back(state.publishers.find(id)->second);
    }
    durable.lineage.reserve(ids.size());
    for (const CanonicalId& id : ids) {
      const auto entry = state.history.find(id);
      if (entry != state.history.end()) {
        durable.lineage.push_back(entry->second);
      }
    }
    std::vector<IdempotencyEntry> entries;
    entries.reserve(state.idempotency.size());
    for (const auto& entry : state.idempotency) {
      entries.push_back(entry.second);
    }
    std::sort(entries.begin(), entries.end(), [](const IdempotencyEntry& left, const IdempotencyEntry& right) {
      if (left.publisher != right.publisher) {
        return left.publisher < right.publisher;
      }
      return left.attempt < right.attempt;
    });
    durable.idempotency = std::move(entries);
    durable.digest = compute_state_digest(state);
  }
  return persistence::write_state_file(path, durable, impl_->state.limits, flush_to_disk);
}

Outcome Registry::load(const std::filesystem::path& path, RecoveryReport& report) {
  persistence::DurableState durable;
  Outcome read = persistence::read_state_file(path, impl_->state.limits, durable);
  if (!read.committed()) {
    return read;
  }

  RegistryState& state = impl_->state;
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  if (!state.records.empty()) {
    return Outcome(OutcomeCode::MalformedRequest,
                   "durable state may only be loaded into a registry that holds no entity records");
  }

  if (durable.generation > state.generation) {
    state.generation = durable.generation;
  }
  report.format_version = FABRIC_REGISTRY_STATE_FORMAT_VERSION;
  report.stored_generation = durable.generation;
  report.stored_epoch = durable.epoch;
  report.stored_digest = durable.digest;

  const std::optional<CoordinatorEpoch> advanced = durable.epoch.next();
  if (!advanced.has_value()) {
    return Outcome(OutcomeCode::ResourceLimit, "the persisted coordinator epoch space is exhausted");
  }
  state.epoch = *advanced;
  report.new_epoch = state.epoch;

  // Publishers are never restored as live: their incarnations belonged to a
  // process that no longer exists.
  for (PublisherRecord& publisher : durable.publishers) {
    if (publisher.id == state.local_publisher) {
      continue;
    }
    const WorkerBootId boot = publisher.current_boot;
    if (!boot.is_null() &&
        std::find(publisher.fenced_boots.begin(), publisher.fenced_boots.end(), boot) == publisher.fenced_boots.end()) {
      publisher.fenced_boots.push_back(boot);
    }
    publisher.current_boot = WorkerBootId{};
    publisher.state = PublisherState::Fenced;
    publisher.status_reason = "coordinator restart: publisher must reattach with a fresh incarnation";
    ++report.publishers_fenced;
    install_publisher(state, std::move(publisher));
  }
  report.publishers_loaded = durable.publishers.size();

  for (RecordHistory& history : durable.lineage) {
    RecordHistory& target = state.history[history.id];
    target.id = history.id;
    target.entries = std::move(history.entries);
    target.truncated = history.truncated;
    report.lineage_entries_loaded += target.entries.size();
  }

  for (EntityRecord& record : durable.records) {
    if (holds_current_authority(record.lifecycle) && record.evidence.evidence_class != EvidenceClass::DurableAuthority) {
      record.lifecycle = Lifecycle::RevalidationRequired;
      record.evidence.valid = false;
      record.status_reason = "recovered after coordinator restart: process-bound evidence must be revalidated";
      ++report.records_demoted;
    } else {
      if (holds_current_authority(record.lifecycle)) {
        ++report.records_restored_current;
      }
    }
    ++report.records_loaded;
    report.aliases_loaded += record.aliases.size();
    CommitContext context;
    context.reason = ReasonCode::RecoveryDemotion;
    context.publisher = state.local_publisher;
    context.detail = "recovered from durable state at epoch " + state.epoch.to_string();
    const bool is_new_record = state.records.find(record.id) == state.records.end();
    RecordPtr previous = is_new_record ? RecordPtr{} : state.records.find(record.id)->second;
    if (!install_record(state, &previous, std::move(record), context, true)) {
      return Outcome(OutcomeCode::ResourceLimit, "the registry generation space is exhausted during recovery");
    }
  }

  for (const IdempotencyEntry& entry : durable.idempotency) {
    record_idempotency(state, entry);
  }

  report.recomputed_digest = compute_state_digest(state);
  report.detail = "durable identity recovered; live authority was not";
  Outcome outcome(OutcomeCode::Committed, "durable state loaded and recovered");
  outcome.epoch = state.epoch;
  outcome.state_generation = state.generation;
  outcome.field_step("load", "records", std::to_string(report.records_loaded),
                     "records restored; " + std::to_string(report.records_demoted) +
                         " were demoted because their evidence was process-bound");
  outcome.field_step("load", "publishers", std::to_string(report.publishers_loaded),
                     "publishers restored as fenced; each must reattach with a fresh incarnation");
  return outcome;
}

std::string RecoveryReport::render() const {
  std::string out;
  out += "format-version: ";
  out += std::to_string(format_version);
  out += '\n';
  out += "stored-generation: ";
  out += stored_generation.to_string();
  out += '\n';
  out += "stored-epoch: ";
  out += stored_epoch.to_string();
  out += '\n';
  out += "new-epoch: ";
  out += new_epoch.to_string();
  out += '\n';
  out += "records-loaded: ";
  out += std::to_string(records_loaded);
  out += '\n';
  out += "records-restored-current: ";
  out += std::to_string(records_restored_current);
  out += '\n';
  out += "records-demoted: ";
  out += std::to_string(records_demoted);
  out += '\n';
  out += "aliases-loaded: ";
  out += std::to_string(aliases_loaded);
  out += '\n';
  out += "publishers-loaded: ";
  out += std::to_string(publishers_loaded);
  out += '\n';
  out += "publishers-fenced: ";
  out += std::to_string(publishers_fenced);
  out += '\n';
  out += "lineage-entries-loaded: ";
  out += std::to_string(lineage_entries_loaded);
  out += '\n';
  out += "stored-digest: ";
  out += stored_digest.to_string();
  out += '\n';
  out += "recomputed-digest: ";
  out += recomputed_digest.to_string();
  out += '\n';
  out += "detail: ";
  out += detail;
  out += '\n';
  return out;
}

} // namespace fabric_registry
