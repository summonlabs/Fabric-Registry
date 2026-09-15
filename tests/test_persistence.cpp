// Fabric Registry — durable state, recovery and corruption proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every case here touches the real file system through the public persistence
// surface: a registry is saved, the file is read back, mutated byte by byte and
// handed to the decoder again. Nothing is simulated and no failure is faked.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/registry_test_support.hpp"
#include "support/test_harness.hpp"

namespace {

namespace persistence = fabric_registry::persistence;

using persistence::DurableState;
using fabric_registry::CanonicalId;
using fabric_registry::EntityClass;
using fabric_registry::EntityRecord;
using fabric_registry::EvidenceClass;
using fabric_registry::Lifecycle;
using fabric_registry::Outcome;
using fabric_registry::OutcomeCode;
using fabric_registry::PublisherState;
using fabric_registry::RecoveryReport;
using fabric_registry::Registry;
using fabric_registry::RegistryLimits;
using fabric_registry::StateDigest;

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> load_bytes(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    return {};
  }
  std::vector<std::uint8_t> out(static_cast<std::size_t>(size), 0);
  stream.seekg(0, std::ios::beg);
  if (!out.empty()) {
    stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (!stream) {
      return {};
    }
  }
  return out;
}

void store_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!bytes.empty()) {
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
}

std::size_t count_files(const std::filesystem::path& directory) {
  std::size_t count = 0;
  std::error_code error;
  std::filesystem::directory_iterator iterator(directory, error);
  const std::filesystem::directory_iterator end;
  while (!error && iterator != end) {
    if (iterator->is_regular_file()) {
      ++count;
    }
    iterator.increment(error);
  }
  return count;
}

void reset_directory(const std::filesystem::path& directory) {
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  std::filesystem::create_directories(directory, error);
}

bool contains(const std::string& text, const char* needle) {
  return text.find(needle) != std::string::npos;
}

bool has_step_field(const Outcome& outcome, const std::string& field) {
  for (const fabric_registry::ExplanationStep& step : outcome.steps) {
    if (step.field == field) {
      return true;
    }
  }
  return false;
}

std::string step_value(const Outcome& outcome, const std::string& field) {
  for (const fabric_registry::ExplanationStep& step : outcome.steps) {
    if (step.field == field) {
      return step.value;
    }
  }
  return std::string();
}

// ---------------------------------------------------------------------------
// Record comparison
// ---------------------------------------------------------------------------

/// Compares every field a save/load round trip must preserve. last_modified is
/// deliberately excluded: recovery installs the recovered record at the
/// registry generation of the recovery itself, so last_modified always names
/// the recovery, never the original commit.
bool same_record_body(const EntityRecord& left, const EntityRecord& right) {
  if (!(left.id == right.id) || left.entity_class != right.entity_class || left.lifecycle != right.lifecycle) {
    return false;
  }
  if (!(left.record_generation == right.record_generation) ||
      !(left.creation_generation == right.creation_generation) ||
      !(left.evidence_generation == right.evidence_generation)) {
    return false;
  }
  if (!(left.fingerprint == right.fingerprint) || !(left.hardware_identity == right.hardware_identity)) {
    return false;
  }
  if (left.derivation_namespace != right.derivation_namespace || left.friendly_name != right.friendly_name) {
    return false;
  }
  if (left.parent_device != right.parent_device || left.fabric != right.fabric || left.site != right.site ||
      left.control_domain != right.control_domain) {
    return false;
  }
  if (left.facts != right.facts || left.aliases != right.aliases || left.metadata != right.metadata) {
    return false;
  }
  if (left.superseded_by != right.superseded_by || left.supersedes != right.supersedes) {
    return false;
  }
  if (left.status_reason != right.status_reason) {
    return false;
  }
  const fabric_registry::EvidenceState& a = left.evidence;
  const fabric_registry::EvidenceState& b = right.evidence;
  if (!(a.generation == b.generation) || a.evidence_class != b.evidence_class || !(a.provenance == b.provenance) ||
      !(a.epoch == b.epoch) || !(a.publisher == b.publisher) || !(a.publisher_boot == b.publisher_boot) ||
      !(a.accepted_at == b.accepted_at) || a.valid != b.valid) {
    return false;
  }
  return left.created_by == right.created_by && left.created_boot == right.created_boot &&
         left.created_epoch == right.created_epoch;
}

std::shared_ptr<const EntityRecord> require_record(const Registry& registry, const CanonicalId& id) {
  std::shared_ptr<const EntityRecord> record;
  const Outcome outcome = registry.lookup(id, record);
  if (!outcome.committed() || record == nullptr) {
    return nullptr;
  }
  return record;
}

/// Registers one device record and returns its canonical identity.
CanonicalId register_device(Registry& registry,
                            const std::string& label,
                            const std::string& serial,
                            const std::string& derivation_namespace = "test/persistence",
                            EvidenceClass evidence_class = EvidenceClass::DurableAuthority) {
  fabric_registry::RegisterEntityRequest request =
      frtest::device_request(registry, label, serial, EntityClass::Switch, derivation_namespace, evidence_class);
  const Outcome outcome = registry.register_entity(request);
  if (!outcome.committed() || !outcome.record.has_value()) {
    return CanonicalId{};
  }
  return *outcome.record;
}

}  // namespace

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

FR_TEST_CASE(persistence, save_load_round_trip_preserves_records_aliases_and_lineage) {
  const std::filesystem::path path = frtest::temporary_state_path("roundtrip");
  frtest::remove_state(path);

  std::unique_ptr<Registry> source = frtest::make_registry(101);
  const CanonicalId first = register_device(*source, "rt-first", "RT-SERIAL-1");
  const CanonicalId second = register_device(*source, "rt-second", "RT-SERIAL-2");
  const CanonicalId third = register_device(*source, "rt-third", "RT-SERIAL-3");
  FR_CHECK(!first.is_null());
  FR_CHECK(!second.is_null());
  FR_CHECK(!third.is_null());

  // One record receives a second commit so the recovered generations cannot all
  // be explained by "everything starts at one".
  {
    fabric_registry::AliasMutationRequest alias;
    alias.attempt = frtest::attempt_from("rt-second-alias");
    alias.authority = source->local_authority();
    alias.target = second;
    alias.alias = frtest::alias_of(fabric_registry::AliasNamespace::ExternalCmdbId, "cmdb-device-2");
    FR_CHECK_EQ(source->attach_alias(alias).code, OutcomeCode::Committed);
  }
  {
    fabric_registry::UpdateEvidenceRequest update;
    update.attempt = frtest::attempt_from("rt-second-evidence");
    update.authority = source->local_authority();
    update.target = second;
    update.facts = {frtest::serial_fact("RT-SERIAL-2"), frtest::fact_of(fabric_registry::IdentityFactKind::DeviceModel, "model-2")};
    update.provenance = frtest::real_provenance("roundtrip");
    update.evidence_class = EvidenceClass::DurableAuthority;
    update.merge_facts = true;
    FR_CHECK_EQ(source->update_evidence(update).code, OutcomeCode::Committed);
  }

  const std::vector<CanonicalId> ids{first, second, third};
  std::vector<std::shared_ptr<const EntityRecord>> before;
  std::size_t lineage_before = 0;
  for (const CanonicalId& id : ids) {
    std::shared_ptr<const EntityRecord> record = require_record(*source, id);
    FR_CHECK(record != nullptr);
    before.push_back(record);
    fabric_registry::RecordHistory history;
    FR_CHECK_EQ(source->history(id, history).code, OutcomeCode::Committed);
    lineage_before += history.entries.size();
  }
  FR_CHECK_EQ(before[0]->record_generation.value(), std::uint64_t{1});
  FR_CHECK_EQ(before[1]->record_generation.value(), std::uint64_t{3});
  FR_CHECK_EQ(before[1]->aliases.size(), std::size_t{1});

  const StateDigest source_digest = source->state_digest();
  FR_CHECK_EQ(source->save(path).code, OutcomeCode::Committed);

  std::unique_ptr<Registry> target = std::make_unique<Registry>([] {
    fabric_registry::RegistryOptions options = frtest::test_options(202);
    options.create_local_publisher = false;
    return options;
  }());
  RecoveryReport report;
  FR_CHECK_EQ(target->load(path, report).code, OutcomeCode::Committed);

  FR_CHECK_EQ(report.records_loaded, std::size_t{3});
  FR_CHECK_EQ(report.records_restored_current, std::size_t{3});
  FR_CHECK_EQ(report.records_demoted, std::size_t{0});
  FR_CHECK_EQ(report.aliases_loaded, std::size_t{1});
  FR_CHECK_EQ(report.lineage_entries_loaded, lineage_before);
  FR_CHECK_EQ(report.stored_digest, source_digest);
  FR_CHECK_EQ(target->stats().entities, std::size_t{3});

  for (std::size_t index = 0; index < ids.size(); ++index) {
    const std::shared_ptr<const EntityRecord> recovered = require_record(*target, ids[index]);
    FR_CHECK_MSG(recovered != nullptr, "a saved record was not recovered");
    FR_CHECK_MSG(same_record_body(*before[index], *recovered),
                 "a recovered record differs from the record that was saved");
    FR_CHECK_MSG(recovered->record_generation == before[index]->record_generation,
                 "recovery renumbered a record generation");
    FR_CHECK_MSG(recovered->aliases == before[index]->aliases, "recovery changed the alias set");
    FR_CHECK_MSG(recovered->facts == before[index]->facts, "recovery changed the fact set");
    FR_CHECK_EQ(recovered->lifecycle, Lifecycle::Current);

    fabric_registry::RecordHistory original;
    fabric_registry::RecordHistory restored;
    FR_CHECK_EQ(source->history(ids[index], original).code, OutcomeCode::Committed);
    FR_CHECK_EQ(target->history(ids[index], restored).code, OutcomeCode::Committed);
    FR_CHECK_EQ(restored.entries.size(), original.entries.size() + 1);
    for (std::size_t entry = 0; entry < original.entries.size(); ++entry) {
      FR_CHECK_MSG(restored.entries[entry] == original.entries[entry], "a lineage entry was not preserved exactly");
    }
    const fabric_registry::LineageEntry& recovery_entry = restored.entries.back();
    FR_CHECK_EQ(recovery_entry.reason, fabric_registry::ReasonCode::RecoveryDemotion);
    FR_CHECK(recovery_entry.resulting_generation == recovered->record_generation);
    FR_CHECK(!recovery_entry.previous_generation.has_value());
  }

  // The alias survived and still resolves to the same identity.
  std::shared_ptr<const EntityRecord> by_alias;
  fabric_registry::AliasKey key;
  key.alias_namespace = fabric_registry::AliasNamespace::ExternalCmdbId;
  key.value = "cmdb-device-2";
  FR_CHECK_EQ(target->lookup_by_alias(key, by_alias).code, OutcomeCode::Committed);
  FR_CHECK(by_alias != nullptr && by_alias->id == second);

  frtest::remove_state(path);
}

FR_TEST_CASE(persistence, recovery_report_advances_the_epoch_and_leaves_consistent_state) {
  const std::filesystem::path path = frtest::temporary_state_path("epoch");
  frtest::remove_state(path);

  std::unique_ptr<Registry> source = frtest::make_registry(303);
  FR_CHECK(!register_device(*source, "epoch-first", "EPOCH-SERIAL-1").is_null());
  FR_CHECK(!register_device(*source, "epoch-second", "EPOCH-SERIAL-2").is_null());
  const StateDigest source_digest = source->state_digest();
  FR_CHECK_EQ(source->save(path).code, OutcomeCode::Committed);

  std::unique_ptr<Registry> target = frtest::make_registry(404);
  RecoveryReport report;
  const Outcome loaded = target->load(path, report);
  FR_CHECK_EQ(loaded.code, OutcomeCode::Committed);

  FR_CHECK_EQ(report.format_version, fabric_registry::state_format_version());
  FR_CHECK_EQ(report.stored_epoch.value() + 1, report.new_epoch.value());
  FR_CHECK_EQ(target->epoch().value(), report.new_epoch.value());
  FR_CHECK_EQ(report.stored_digest, source_digest);
  FR_CHECK_MSG(!(report.recomputed_digest == report.stored_digest),
               "the recovery digest must differ from the stored digest: the epoch advanced");
  FR_CHECK(report.recomputed_digest == target->state_digest());
  FR_CHECK(!report.detail.empty());

  std::string validation;
  const Outcome consistent = target->validate_state(validation);
  FR_CHECK_MSG(consistent.committed(), "the recovered registry did not validate: " + validation);
  FR_CHECK(contains(validation, "consistent: true"));

  frtest::remove_state(path);
}

FR_TEST_CASE(persistence, durable_evidence_stays_current_and_process_bound_evidence_is_demoted) {
  const std::filesystem::path path = frtest::temporary_state_path("evidence");
  frtest::remove_state(path);

  std::unique_ptr<Registry> source = frtest::make_registry(505);
  const CanonicalId durable =
      register_device(*source, "ev-durable", "EV-DURABLE", "test/persistence-durable", EvidenceClass::DurableAuthority);
  const CanonicalId transient =
      register_device(*source, "ev-process", "EV-PROCESS", "test/persistence-process", EvidenceClass::ProcessBound);
  FR_CHECK(!durable.is_null());
  FR_CHECK(!transient.is_null());
  FR_CHECK_EQ(source->stats().current_entities, std::size_t{2});

  // A second, independent publisher is attached so the file holds a publisher
  // that is live at save time and must not be live after recovery.
  const fabric_registry::PublisherAttachResult attached = source->attach_publisher([&] {
    fabric_registry::PublisherAttachRequest request;
    request.name = "persistence-extra-publisher";
    request.protocol_version = fabric_registry::protocol_version();
    return request;
  }());
  FR_CHECK_EQ(attached.outcome.code, OutcomeCode::Committed);
  FR_CHECK_EQ(source->stats().publishers, std::size_t{2});

  const std::shared_ptr<const EntityRecord> before_durable = require_record(*source, durable);
  const std::shared_ptr<const EntityRecord> before_transient = require_record(*source, transient);
  FR_CHECK(before_durable != nullptr && before_transient != nullptr);
  FR_CHECK_EQ(before_durable->evidence.evidence_class, EvidenceClass::DurableAuthority);
  FR_CHECK_EQ(before_transient->evidence.evidence_class, EvidenceClass::ProcessBound);
  FR_CHECK(before_transient->evidence.valid);

  FR_CHECK_EQ(source->save(path).code, OutcomeCode::Committed);

  std::unique_ptr<Registry> target = std::make_unique<Registry>([] {
    fabric_registry::RegistryOptions options = frtest::test_options(606);
    options.create_local_publisher = false;
    return options;
  }());
  RecoveryReport report;
  FR_CHECK_EQ(target->load(path, report).code, OutcomeCode::Committed);

  FR_CHECK_EQ(report.records_loaded, std::size_t{2});
  FR_CHECK_EQ(report.records_restored_current, std::size_t{1});
  FR_CHECK_EQ(report.records_demoted, std::size_t{1});
  FR_CHECK_EQ(report.publishers_loaded, std::size_t{2});
  FR_CHECK_EQ(report.publishers_fenced, std::size_t{2});

  const std::shared_ptr<const EntityRecord> recovered_durable = require_record(*target, durable);
  const std::shared_ptr<const EntityRecord> recovered_transient = require_record(*target, transient);
  FR_CHECK(recovered_durable != nullptr && recovered_transient != nullptr);

  FR_CHECK_EQ(recovered_durable->lifecycle, Lifecycle::Current);
  FR_CHECK(recovered_durable->evidence.valid);
  FR_CHECK_EQ(recovered_durable->evidence.evidence_class, EvidenceClass::DurableAuthority);
  FR_CHECK(recovered_durable->record_generation == before_durable->record_generation);

  FR_CHECK_EQ(recovered_transient->lifecycle, Lifecycle::RevalidationRequired);
  FR_CHECK_MSG(!recovered_transient->evidence.valid, "process-bound evidence must not survive as valid");
  FR_CHECK(!recovered_transient->status_reason.empty());
  FR_CHECK(recovered_transient->record_generation == before_transient->record_generation);
  FR_CHECK_EQ(target->stats().current_entities, std::size_t{1});
  FR_CHECK_EQ(target->stats().revalidation_required_entities, std::size_t{1});

  const std::vector<fabric_registry::PublisherRecord> publishers = target->publishers();
  FR_CHECK_EQ(publishers.size(), std::size_t{2});
  for (const fabric_registry::PublisherRecord& publisher : publishers) {
    FR_CHECK_MSG(publisher.state == PublisherState::Fenced, "a recovered publisher was not fenced");
    FR_CHECK_MSG(publisher.current_boot.is_null(), "a recovered publisher still holds a live incarnation");
    FR_CHECK(!publisher.fenced_boots.empty());
  }

  std::string validation;
  FR_CHECK_MSG(target->validate_state(validation).committed(), "the recovered registry did not validate: " + validation);

  frtest::remove_state(path);
}

// ---------------------------------------------------------------------------
// Corruption
// ---------------------------------------------------------------------------

FR_TEST_CASE(persistence, corrupted_state_images_are_rejected_with_a_specific_stage) {
  const std::filesystem::path path = frtest::temporary_state_path("corruption");
  frtest::remove_state(path);

  std::unique_ptr<Registry> source = frtest::make_registry(707);
  FR_CHECK(!register_device(*source, "corrupt-a", "CORRUPT-SERIAL-A").is_null());
  FR_CHECK(!register_device(*source, "corrupt-b", "CORRUPT-SERIAL-B").is_null());
  FR_CHECK_EQ(source->save(path).code, OutcomeCode::Committed);

  const RegistryLimits limits = source->limits();
  const std::vector<std::uint8_t> pristine = load_bytes(path);
  FR_CHECK_MSG(pristine.size() > persistence::kHeaderBytes + persistence::kIntegrityBytes + 1,
               "the saved state file is implausibly short");
  {
    DurableState decoded;
    FR_CHECK_EQ(persistence::decode_state(pristine, limits, decoded).code, OutcomeCode::Committed);
  }

  // 1. One flipped payload byte.
  {
    std::vector<std::uint8_t> image = pristine;
    image[persistence::kHeaderBytes + 4] = static_cast<std::uint8_t>(image[persistence::kHeaderBytes + 4] ^ 0x40u);
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "integrity digest"), "the failure did not name the integrity digest");
  }

  // 2. Truncated by exactly one byte: the declared payload length no longer
  //    matches the file size.
  {
    std::vector<std::uint8_t> image(pristine.begin(), pristine.end() - 1);
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "length"), "the failure did not name the payload length");
  }

  // 3. Truncated to ten bytes: shorter than the fixed header.
  {
    std::vector<std::uint8_t> image(pristine.begin(), pristine.begin() + 10);
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::PersistenceFailure);
    FR_CHECK_MSG(contains(outcome.message, "header"), "the failure did not name the fixed header");
  }

  // 4. Changed magic.
  {
    std::vector<std::uint8_t> image = pristine;
    image[0] = static_cast<std::uint8_t>('X');
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "magic"), "the failure did not name the magic");
  }

  // 5. Format version 99.
  {
    std::vector<std::uint8_t> image = pristine;
    image[8] = 99;
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(has_step_field(outcome, "format-version"), "the failure did not name the format version");
    FR_CHECK_EQ(step_value(outcome, "format-version"), std::string("99"));
  }

  // 6. Non-zero reserved header word.
  {
    std::vector<std::uint8_t> image = pristine;
    image[12] = 1;
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "reserved"), "the failure did not name the reserved word");
  }

  // 7. One appended trailing byte.
  {
    std::vector<std::uint8_t> image = pristine;
    image.push_back(0);
    store_bytes(path, image);
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, limits, decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "length"), "the failure did not name the payload length");
  }

  // The untouched image still decodes: the mutations above, not the image, are
  // what the decoder rejected.
  store_bytes(path, pristine);
  {
    DurableState decoded;
    FR_CHECK_EQ(persistence::read_state_file(path, limits, decoded).code, OutcomeCode::Committed);
    FR_CHECK_EQ(decoded.records.size(), std::size_t{2});
  }

  frtest::remove_state(path);
}

FR_TEST_CASE(persistence, decode_state_rejects_duplicate_identity_wrong_digest_and_oversized_count) {
  const std::filesystem::path path = frtest::temporary_state_path("decode");
  frtest::remove_state(path);

  std::unique_ptr<Registry> source = frtest::make_registry(808);
  FR_CHECK(!register_device(*source, "decode-a", "DECODE-SERIAL-A").is_null());
  FR_CHECK(!register_device(*source, "decode-b", "DECODE-SERIAL-B").is_null());
  const RegistryLimits limits = source->limits();
  FR_CHECK_EQ(source->save(path).code, OutcomeCode::Committed);
  const std::vector<std::uint8_t> image = load_bytes(path);

  DurableState decoded;
  FR_CHECK_EQ(persistence::decode_state(image, limits, decoded).code, OutcomeCode::Committed);
  FR_CHECK_EQ(decoded.records.size(), std::size_t{2});
  FR_CHECK(decoded.digest == decoded.recompute_digest());

  // 1. The same canonical identity twice. A canonical image carries its
  //    records in identity order, so a duplicated record is adjacent to its
  //    original; the decoder compares neighbouring identities.
  {
    DurableState duplicate;
    duplicate.generation = decoded.generation;
    duplicate.epoch = decoded.epoch;
    duplicate.publishers = decoded.publishers;
    duplicate.records = {decoded.records.front(), decoded.records.front(), decoded.records.back()};
    duplicate.digest = duplicate.recompute_digest();
    const std::vector<std::uint8_t> bytes = persistence::encode_state(duplicate, limits);
    DurableState out;
    const Outcome outcome = persistence::decode_state(bytes, limits, out);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "canonical identity twice"),
                 "the failure did not name the duplicate canonical identity");
  }

  // 2. A stored state digest that does not match the stored records.
  {
    DurableState wrong_digest = decoded;
    wrong_digest.digest = StateDigest{};
    const std::vector<std::uint8_t> bytes = persistence::encode_state(wrong_digest, limits);
    DurableState out;
    const Outcome outcome = persistence::decode_state(bytes, limits, out);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IntegrityFailure);
    FR_CHECK_MSG(contains(outcome.message, "stored state digest"),
                 "the failure did not name the stored state digest");
    FR_CHECK(has_step_field(outcome, "state-digest"));
  }

  // 3. A declared record count above the configured bound. The count is
  //    validated before a single record is read, so a one-record bound refuses
  //    a two-record image.
  {
    RegistryLimits tight = limits;
    tight.max_entities = 1;
    DurableState out;
    const Outcome outcome = persistence::decode_state(image, tight, out);
    FR_CHECK_EQ(outcome.code, OutcomeCode::ResourceLimit);
    FR_CHECK_MSG(contains(outcome.message, "more records than the configured bound"),
                 "the failure did not name the record bound");
  }

  // A truncated image must never be accepted as a smaller state either.
  {
    const std::vector<std::uint8_t> short_image(image.begin(), image.end() - 40);
    DurableState out;
    FR_CHECK(!persistence::decode_state(short_image, limits, out).committed());
  }

  frtest::remove_state(path);
}

// ---------------------------------------------------------------------------
// Atomic replacement
// ---------------------------------------------------------------------------

FR_TEST_CASE(persistence, replacement_is_atomic_and_leaves_no_temporary_file) {
  const std::filesystem::path path = frtest::temporary_state_path("atomic");
  const std::filesystem::path temporary = persistence::temporary_path_for(path);
  const std::filesystem::path directory = path.parent_path();
  reset_directory(directory);

  std::unique_ptr<Registry> registry = frtest::make_registry(909);
  FR_CHECK(!register_device(*registry, "atomic-a", "ATOMIC-SERIAL-A").is_null());

  FR_CHECK_EQ(registry->save(path).code, OutcomeCode::Committed);
  FR_CHECK_MSG(std::filesystem::exists(path), "the authoritative file was not created");
  FR_CHECK_MSG(!std::filesystem::exists(temporary), "a temporary file survived a successful save");
  FR_CHECK_EQ(count_files(directory), std::size_t{1});

  // A leftover temporary file from a writer that died is removed by the next
  // read, and the authoritative file is still complete.
  store_bytes(temporary, std::vector<std::uint8_t>{1, 2, 3, 4});
  FR_CHECK(std::filesystem::exists(temporary));
  {
    DurableState decoded;
    const Outcome outcome = persistence::read_state_file(path, registry->limits(), decoded);
    FR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    FR_CHECK_EQ(decoded.records.size(), std::size_t{1});
  }
  FR_CHECK_MSG(!std::filesystem::exists(temporary), "read_state_file did not remove the leftover temporary file");
  FR_CHECK_EQ(count_files(directory), std::size_t{1});

  // A second save with a leftover temporary file present still leaves exactly
  // one authoritative file and no temporary.
  store_bytes(temporary, std::vector<std::uint8_t>{9, 9, 9});
  FR_CHECK_EQ(registry->save(path).code, OutcomeCode::Committed);
  FR_CHECK_MSG(!std::filesystem::exists(temporary), "the temporary file survived the second save");
  FR_CHECK_EQ(count_files(directory), std::size_t{1});

  // remove_temporary_file reports the absence of a temporary explicitly.
  FR_CHECK_EQ(persistence::remove_temporary_file(path).code, OutcomeCode::NotFound);

  frtest::remove_state(path);
}

FR_TEST_CASE(persistence, save_into_a_missing_directory_fails_and_leaves_no_temporary) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "fabric-registry-state-missing-directory";
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  const std::filesystem::path path = directory / "state.bin";
  const std::filesystem::path temporary = persistence::temporary_path_for(path);

  std::unique_ptr<Registry> registry = frtest::make_registry(1010);
  FR_CHECK(!register_device(*registry, "missing-dir", "MISSING-DIR-SERIAL").is_null());

  const Outcome outcome = registry->save(path);
  FR_CHECK_EQ(outcome.code, OutcomeCode::PersistenceFailure);
  FR_CHECK_MSG(!std::filesystem::exists(temporary), "a failed save left a temporary file behind");
  FR_CHECK_MSG(!std::filesystem::exists(path), "a failed save created an authoritative file");
  FR_CHECK_MSG(!std::filesystem::exists(directory), "a failed save created a directory");

  // Nothing was half-written: a registry can still save the same state to a
  // usable path afterwards.
  const std::filesystem::path usable = frtest::temporary_state_path("missing-directory-usable");
  frtest::remove_state(usable);
  FR_CHECK_EQ(registry->save(usable).code, OutcomeCode::Committed);
  frtest::remove_state(usable);
}

FR_TEST_CASE(persistence, durable_state_recompute_digest_equals_the_registry_state_digest) {
  const std::filesystem::path path = frtest::temporary_state_path("digest");
  frtest::remove_state(path);

  std::unique_ptr<Registry> registry = frtest::make_registry(1111);
  FR_CHECK(!register_device(*registry, "digest-a", "DIGEST-SERIAL-A").is_null());
  const CanonicalId second = register_device(*registry, "digest-b", "DIGEST-SERIAL-B");
  FR_CHECK(!second.is_null());
  {
    fabric_registry::UpdateEvidenceRequest update;
    update.attempt = frtest::attempt_from("digest-b-evidence");
    update.authority = registry->local_authority();
    update.target = second;
    update.facts = {frtest::serial_fact("DIGEST-SERIAL-B")};
    update.provenance = frtest::real_provenance("digest");
    update.evidence_class = EvidenceClass::DurableAuthority;
    FR_CHECK_EQ(registry->update_evidence(update).code, OutcomeCode::Committed);
  }
  FR_CHECK_EQ(registry->save(path).code, OutcomeCode::Committed);

  const std::vector<std::uint8_t> image = load_bytes(path);
  DurableState decoded;
  FR_CHECK_EQ(persistence::decode_state(image, registry->limits(), decoded).code, OutcomeCode::Committed);
  FR_CHECK_MSG(!decoded.digest.is_null(), "the stored digest is null");
  FR_CHECK_MSG(decoded.digest == decoded.recompute_digest(),
               "DurableState::recompute_digest disagrees with the digest stored in the file");
  FR_CHECK_MSG(decoded.digest == registry->state_digest(),
               "the stored digest disagrees with the live registry state digest");
  FR_CHECK_EQ(decoded.records.size(), std::size_t{2});
  FR_CHECK_EQ(decoded.publishers.size(), std::size_t{1});
  FR_CHECK_EQ(decoded.epoch.value(), registry->epoch().value());

  frtest::remove_state(path);
}

FR_TEST_CASE(persistence, reading_a_state_file_that_does_not_exist_is_not_found) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "fabric-registry-state-absent";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  const std::filesystem::path path = directory / "state.bin";
  frtest::remove_state(path);

  DurableState decoded;
  const Outcome outcome = persistence::read_state_file(path, RegistryLimits{}, decoded);
  FR_CHECK_EQ(outcome.code, OutcomeCode::NotFound);

  std::unique_ptr<Registry> registry = frtest::make_registry(1212);
  RecoveryReport report;
  FR_CHECK_EQ(registry->load(path, report).code, OutcomeCode::NotFound);
  FR_CHECK_EQ(registry->stats().entities, std::size_t{0});
}

int main(int argc, char** argv) { return frtest::run_all(argc, argv); }
