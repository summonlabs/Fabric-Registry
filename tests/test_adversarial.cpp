// Fabric Registry — adversarial proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every case here tries to make the registry accept something it must not, or
// to make it change state while refusing. Each rejection asserts the exact
// OutcomeCode and that the registry generation, entity count and every derived
// count are untouched. Nothing is asserted through a renderer: the enumerators
// are the contract.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/registry_test_support.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::AdmissionMode;
using fabric_registry::AliasNamespace;
using fabric_registry::AuthorityClaim;
using fabric_registry::CanonicalId;
using fabric_registry::Coordinator;
using fabric_registry::CoordinatorEpoch;
using fabric_registry::CoordinatorOptions;
using fabric_registry::Endpoint;
using fabric_registry::EntityClass;
using fabric_registry::EntityRecord;
using fabric_registry::EvidenceClass;
using fabric_registry::FenceReason;
using fabric_registry::IdBytes;
using fabric_registry::IdentityFactKind;
using fabric_registry::MetadataEntry;
using fabric_registry::Outcome;
using fabric_registry::OutcomeCode;
using fabric_registry::PublisherClient;
using fabric_registry::PublisherClientOptions;
using fabric_registry::RecordGeneration;
using fabric_registry::RegisterEntityRequest;
using fabric_registry::Registry;
using fabric_registry::RegistryOptions;
using fabric_registry::RegistryStats;
using fabric_registry::UpdateEvidenceRequest;

// ---------------------------------------------------------------------------
// State fingerprint
// ---------------------------------------------------------------------------

/// Everything a rejected request must leave untouched. The generation alone
/// would miss an index updated without a commit, so every count the registry
/// publishes is compared.
struct StateSnapshot {
  fabric_registry::RegistryGeneration generation;
  CoordinatorEpoch epoch;
  std::size_t entities{0};
  std::size_t current_entities{0};
  std::size_t revalidation_required_entities{0};
  std::size_t publishers{0};
  std::size_t aliases{0};
  std::size_t indexed_aliases{0};
  std::size_t lineage_entries{0};
  std::size_t idempotency_records{0};

  static StateSnapshot capture(const Registry& registry) {
    const RegistryStats stats = registry.stats();
    StateSnapshot snapshot;
    snapshot.generation = stats.generation;
    snapshot.epoch = stats.epoch;
    snapshot.entities = stats.entities;
    snapshot.current_entities = stats.current_entities;
    snapshot.revalidation_required_entities = stats.revalidation_required_entities;
    snapshot.publishers = stats.publishers;
    snapshot.aliases = stats.aliases;
    snapshot.indexed_aliases = stats.indexed_aliases;
    snapshot.lineage_entries = stats.lineage_entries;
    snapshot.idempotency_records = stats.idempotency_records;
    return snapshot;
  }

  bool unchanged(const Registry& registry) const {
    const RegistryStats stats = registry.stats();
    return generation == stats.generation && epoch == stats.epoch && entities == stats.entities &&
           current_entities == stats.current_entities &&
           revalidation_required_entities == stats.revalidation_required_entities &&
           publishers == stats.publishers && aliases == stats.aliases &&
           indexed_aliases == stats.indexed_aliases && lineage_entries == stats.lineage_entries &&
           idempotency_records == stats.idempotency_records;
  }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

bool options_are_rejected(const RegistryOptions& options) {
  try {
    const Registry registry(options);
    (void)registry;
  } catch (const std::invalid_argument&) {
    return true;
  }
  return false;
}

std::string repeated(char value, std::size_t count) {
  return std::string(count, value);
}

/// A registration request that does not depend on a registry instance; used
/// where the authority is supplied by a publisher client.
RegisterEntityRequest client_request(const std::string& label,
                                     const std::string& serial,
                                     const std::string& derivation_namespace) {
  RegisterEntityRequest request;
  request.attempt = frtest::attempt_from(label);
  request.entity_class = EntityClass::Switch;
  request.derivation_namespace = derivation_namespace;
  request.friendly_name = label;
  request.facts = {frtest::serial_fact(serial)};
  request.provenance = frtest::real_provenance();
  request.evidence_class = EvidenceClass::DurableAuthority;
  request.admission = AdmissionMode::RequireCurrent;
  return request;
}

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

/// Registers one record and returns its identity. A rejection yields the null
/// identity, which the caller asserts against: every rejection proof here needs
/// a real record to exist first.
CanonicalId register_one(Registry& registry, const std::string& label, const std::string& serial) {
  const Outcome outcome = registry.register_entity(frtest::device_request(registry, label, serial));
  if (!outcome.committed() || !outcome.record.has_value()) {
    return CanonicalId{};
  }
  return *outcome.record;
}

}  // namespace

// ---------------------------------------------------------------------------
// Empty and malformed identities
// ---------------------------------------------------------------------------

FR_TEST_CASE(adversarial, null_attempt_and_null_canonical_identities_are_malformed) {
  std::unique_ptr<Registry> registry = frtest::make_registry(31);

  {
    RegisterEntityRequest request = frtest::device_request(*registry, "null-attempt", "NULL-ATTEMPT-SERIAL");
    request.attempt = fabric_registry::RegistrationId{};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "a null attempt id changed registry state");
  }
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "null-canonical", "NULL-CANONICAL-SERIAL");
    request.derivation_namespace.clear();
    request.canonical_id = CanonicalId{};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "a null canonical identity changed registry state");
  }
  {
    // A well-formed class with sixteen zero bytes is still the null identity.
    RegisterEntityRequest request = frtest::device_request(*registry, "zero-canonical", "ZERO-CANONICAL-SERIAL");
    request.derivation_namespace.clear();
    request.canonical_id = CanonicalId(EntityClass::Switch, IdBytes{});
    FR_CHECK(request.canonical_id->is_null());
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "an all-zero canonical identity changed registry state");
  }
  {
    std::shared_ptr<const EntityRecord> record;
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->lookup(CanonicalId{}, record).code, OutcomeCode::MalformedRequest);
    FR_CHECK(record == nullptr);
    FR_CHECK_EQ(registry->validate_reference(CanonicalId{}, std::nullopt).code, OutcomeCode::NotFound);
    FR_CHECK_MSG(before.unchanged(*registry), "a null lookup changed registry state");
  }
}

FR_TEST_CASE(adversarial, malformed_canonical_id_text_never_parses) {
  const std::string valid = "0123456789abcdef0123456789abcdef";

  FR_CHECK_MSG(!CanonicalId::parse("swtich:" + valid).has_value(), "a misspelled class name parsed");
  FR_CHECK_MSG(!CanonicalId::parse("switch:" + valid.substr(0, 31)).has_value(), "31 hex characters parsed");
  FR_CHECK_MSG(!CanonicalId::parse("switch:" + valid).has_value() == false, "a valid identity did not parse");
  FR_CHECK_MSG(!CanonicalId::parse("switch:zz" + valid.substr(2)).has_value(), "non-hex characters parsed");
  FR_CHECK_MSG(!CanonicalId::parse("switch:" + repeated('0', 32)).has_value(), "the all-zero identity parsed");
  FR_CHECK_MSG(!CanonicalId::parse(valid).has_value(), "text without a class separator parsed");

  const std::optional<CanonicalId> parsed = CanonicalId::parse("switch:" + valid);
  FR_CHECK(parsed.has_value());
  FR_CHECK_EQ(parsed->entity_class(), EntityClass::Switch);
  FR_CHECK_EQ(parsed->to_string(), std::string("switch:") + valid);
  const std::optional<CanonicalId> router = CanonicalId::parse("router:" + valid);
  FR_CHECK(router.has_value());
  FR_CHECK_EQ(router->entity_class(), EntityClass::Router);
  FR_CHECK_MSG(!(*parsed == *router), "the class name does not take part in identity");

  std::unique_ptr<Registry> registry = frtest::make_registry(32);
  const StateSnapshot before = StateSnapshot::capture(*registry);
  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(*parsed, record).code, OutcomeCode::NotFound);
  FR_CHECK_MSG(before.unchanged(*registry), "a lookup of a parsed but absent identity changed state");
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

FR_TEST_CASE(adversarial, oversized_name_alias_fact_and_metadata_are_rejected_at_the_exact_bound) {
  RegistryOptions options = frtest::test_options(33);
  options.limits.max_string_bytes = 64;
  options.limits.max_metadata_value_bytes = 32;
  options.limits.max_metadata_bytes_per_entity = 64;
  std::unique_ptr<Registry> registry = std::make_unique<Registry>(options);
  FR_CHECK_EQ(registry->limits().max_string_bytes, std::size_t{64});

  // A friendly name one byte over the bound.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "short-label", "OVERSIZE-NAME-SERIAL");
    request.friendly_name = repeated('n', 65);
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::ResourceLimit);
    FR_CHECK_MSG(before.unchanged(*registry), "an oversized friendly name changed registry state");
  }
  // An alias value one byte over the bound.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "short-label", "OVERSIZE-ALIAS-SERIAL");
    request.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, repeated('a', 65)));
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "an oversized alias value changed registry state");
  }
  // A fact value one byte over the bound.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "short-label", "OVERSIZE-FACT-SERIAL");
    request.facts = {frtest::serial_fact(repeated('s', 65))};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "an oversized fact value changed registry state");
  }
  // A metadata value one byte over its own bound.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "short-label", "OVERSIZE-METADATA-SERIAL");
    request.metadata.push_back(MetadataEntry{"role", repeated('m', 33)});
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "an oversized metadata value changed registry state");
  }
  // Control: exactly at every bound is accepted, so the cases above are not
  // refused for some unrelated reason.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, repeated('l', 64), "AT-BOUND-SERIAL");
    request.friendly_name = repeated('n', 64);
    request.facts = {frtest::serial_fact(repeated('s', 64))};
    request.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, repeated('a', 64)));
    request.metadata.push_back(MetadataEntry{"role", repeated('m', 32)});
    const Outcome outcome = registry->register_entity(request);
    FR_CHECK_MSG(outcome.committed(), "a request exactly at every bound was refused: " +
                                          std::string(fabric_registry::to_string(outcome.code)));
    FR_CHECK_EQ(registry->stats().entities, std::size_t{1});
  }
}

FR_TEST_CASE(adversarial, embedded_nul_and_control_characters_are_rejected_everywhere) {
  std::unique_ptr<Registry> registry = frtest::make_registry(34);

  // Friendly name with an embedded NUL.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "nul-name", "NUL-NAME-SERIAL");
    request.friendly_name.assign("ok\0bad", 6);
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "an embedded NUL in a friendly name changed state");
  }
  // Friendly name with a control character.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "control-name", "CONTROL-NAME-SERIAL");
    request.friendly_name = std::string("bad\x01name");
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "a control character in a friendly name changed state");
  }
  // Fact value with a control character.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "control-fact", "CONTROL-FACT-SERIAL");
    request.facts = {frtest::serial_fact(std::string("bad\x01serial"))};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "a control character in a fact value changed state");
  }
  // Alias value with a control character.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "control-alias", "CONTROL-ALIAS-SERIAL");
    request.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, std::string("bad\x01alias")));
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "a control character in an alias value changed state");
  }
  // Metadata value and metadata key with a control character.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "control-metadata", "CONTROL-META-SERIAL");
    request.metadata.push_back(MetadataEntry{"role", std::string("bad\x01value")});
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "a control character in a metadata value changed state");
  }
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "nul-metadata-key", "NUL-META-KEY-SERIAL");
    request.metadata.push_back(MetadataEntry{std::string("ro\0le", 5), "value"});
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "an embedded NUL in a metadata key changed state");
  }
}

FR_TEST_CASE(adversarial, a_fact_value_that_is_not_utf8_is_rejected) {
  std::unique_ptr<Registry> registry = frtest::make_registry(35);

  {
    std::string value = "SERIAL-";
    value.push_back(static_cast<char>(0x80));
    RegisterEntityRequest request = frtest::device_request(*registry, "utf8-fact", "UTF8-FACT-SERIAL");
    request.facts = {frtest::serial_fact(value)};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    const Outcome outcome = registry->register_entity(request);
    FR_CHECK_EQ(outcome.code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "a fact value that is not valid UTF-8 changed state");
  }
  {
    std::string value = "asset-";
    value.push_back(static_cast<char>(0x80));
    RegisterEntityRequest request = frtest::device_request(*registry, "utf8-alias", "UTF8-ALIAS-SERIAL");
    request.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, value));
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "invalid UTF-8 in an alias value changed state");
  }
}

FR_TEST_CASE(adversarial, locally_administered_permanent_mac_and_empty_serial_scope_are_rejected) {
  std::unique_ptr<Registry> registry = frtest::make_registry(36);

  {
    RegisterEntityRequest request = frtest::device_request(*registry, "local-mac", "LOCAL-MAC-SERIAL");
    request.facts.push_back(
        frtest::fact_of(IdentityFactKind::PermanentMac, "02:00:5e:00:53:01"));
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "a locally administered permanent MAC changed state");
  }
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "empty-scope", "EMPTY-SCOPE-SERIAL");
    request.facts = {frtest::serial_fact("SERIAL-WITHOUT-A-SCOPE", std::string())};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "a serial fact without a scope changed state");
  }
  // Control: the same MAC as a non-permanent observation is accepted, and a
  // universally administered permanent MAC is accepted.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "global-mac", "GLOBAL-MAC-SERIAL");
    request.facts.push_back(frtest::fact_of(IdentityFactKind::MacAddress, "02:00:5e:00:53:01"));
    request.facts.push_back(frtest::fact_of(IdentityFactKind::PermanentMac, "00:11:22:33:44:55"));
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::Committed);
  }
}

// ---------------------------------------------------------------------------
// Aliases and duplicate identity
// ---------------------------------------------------------------------------

FR_TEST_CASE(adversarial, a_duplicate_alias_inside_one_request_is_collapsed_not_double_counted) {
  std::unique_ptr<Registry> registry = frtest::make_registry(37);

  // The frozen implementation canonicalises the requested alias set, sorts it
  // and erases exact duplicates before the request is evaluated, so the same
  // alias twice is one alias, never two and never a conflict with itself.
  RegisterEntityRequest request = frtest::device_request(*registry, "duplicate-alias", "DUPLICATE-ALIAS-SERIAL");
  request.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-duplicate"));
  request.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-duplicate"));
  const Outcome outcome = registry->register_entity(request);
  FR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
  FR_CHECK(outcome.record.has_value());
  FR_CHECK_EQ(registry->stats().entities, std::size_t{1});
  FR_CHECK_MSG(registry->stats().aliases == 1, "a duplicate alias was counted twice");
  FR_CHECK_MSG(registry->stats().indexed_aliases == 1, "a duplicate alias was indexed twice");

  std::shared_ptr<const EntityRecord> record;
  FR_CHECK_EQ(registry->lookup(*outcome.record, record).code, OutcomeCode::Committed);
  FR_CHECK(record != nullptr);
  FR_CHECK_EQ(record->aliases.size(), std::size_t{1});

  // Presenting the same alias again through a second mutation is idempotent and
  // produces no new generation.
  fabric_registry::AliasMutationRequest alias;
  alias.attempt = frtest::attempt_from("duplicate-alias-again");
  alias.authority = registry->local_authority();
  alias.target = *outcome.record;
  alias.alias = frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-duplicate");
  const StateSnapshot before = StateSnapshot::capture(*registry);
  FR_CHECK_EQ(registry->attach_alias(alias).code, OutcomeCode::Idempotent);
  FR_CHECK_MSG(before.unchanged(*registry), "an idempotent alias attach changed registry state");
  FR_CHECK_EQ(registry->stats().aliases, std::size_t{1});
}

FR_TEST_CASE(adversarial, two_records_competing_for_one_unique_alias_conflict) {
  std::unique_ptr<Registry> registry = frtest::make_registry(38);

  // The holder binds the unique alias.
  RegisterEntityRequest first = frtest::device_request(*registry, "alias-holder", "ALIAS-HOLDER-SERIAL");
  first.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-shared"));
  const Outcome holder_outcome = registry->register_entity(first);
  FR_CHECK_EQ(holder_outcome.code, OutcomeCode::Committed);
  FR_CHECK(holder_outcome.record.has_value());

  // A genuinely different device claiming the alias is refused, and no second
  // record is created: the alias points at a device whose serial contradicts
  // the claim.
  {
    RegisterEntityRequest claimant = frtest::device_request(*registry, "alias-claimant", "ALIAS-CLAIMANT-SERIAL");
    claimant.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-shared"));
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(claimant).code, OutcomeCode::IdentityConflict);
    FR_CHECK_MSG(before.unchanged(*registry), "a refused alias claim changed registry state");
    FR_CHECK_EQ(registry->stats().entities, std::size_t{1});
  }

  // A second live record cannot take the alias over. The request addresses a
  // record that exists and whose facts it agrees with, so the only thing that
  // can refuse it is the alias already being bound to another record.
  const CanonicalId second = register_one(*registry, "alias-second", "ALIAS-SECOND-SERIAL");
  FR_CHECK(!second.is_null());
  {
    RegisterEntityRequest takeover = frtest::device_request(*registry, "alias-takeover", "ALIAS-SECOND-SERIAL");
    takeover.canonical_id = second;
    takeover.derivation_namespace.clear();
    takeover.aliases.push_back(frtest::alias_of(AliasNamespace::ExternalCmdbId, "asset-shared"));
    const StateSnapshot before = StateSnapshot::capture(*registry);
    const Outcome outcome = registry->register_entity(takeover);
    FR_CHECK_EQ(outcome.code, OutcomeCode::AliasConflict);
    FR_CHECK_MSG(before.unchanged(*registry), "a rejected alias takeover changed registry state");
  }

  // The holder still owns the alias and the registry still holds two records.
  std::shared_ptr<const EntityRecord> holder;
  fabric_registry::AliasKey key;
  key.alias_namespace = AliasNamespace::ExternalCmdbId;
  key.value = "asset-shared";
  FR_CHECK_EQ(registry->lookup_by_alias(key, holder).code, OutcomeCode::Committed);
  FR_CHECK(holder != nullptr);
  FR_CHECK_EQ(holder->id, *holder_outcome.record);
  FR_CHECK_EQ(registry->stats().entities, std::size_t{2});
  FR_CHECK_EQ(registry->stats().indexed_aliases, std::size_t{1});
}

FR_TEST_CASE(adversarial, duplicate_stable_hardware_identity_across_two_live_records_is_rejected) {
  std::unique_ptr<Registry> registry = frtest::make_registry(39);

  const CanonicalId holder = register_one(*registry, "hardware-holder", "SHARED-HARDWARE-SERIAL");
  const CanonicalId other = register_one(*registry, "hardware-other", "OTHER-HARDWARE-SERIAL");
  FR_CHECK(!holder.is_null());
  FR_CHECK(!other.is_null());
  FR_CHECK(!(holder == other));
  FR_CHECK_EQ(registry->stats().entities, std::size_t{2});

  // Giving the second record the first record's strong hardware identity would
  // leave two live records for one physical device.
  UpdateEvidenceRequest update;
  update.attempt = frtest::attempt_from("hardware-collision");
  update.authority = registry->local_authority();
  update.target = other;
  update.facts = {frtest::serial_fact("SHARED-HARDWARE-SERIAL")};
  update.provenance = frtest::real_provenance();
  update.evidence_class = EvidenceClass::DurableAuthority;
  update.merge_facts = false;
  const StateSnapshot before = StateSnapshot::capture(*registry);
  const Outcome outcome = registry->update_evidence(update);
  FR_CHECK_EQ(outcome.code, OutcomeCode::DuplicateIdentity);
  FR_CHECK_MSG(before.unchanged(*registry), "a duplicate hardware identity changed registry state");

  std::shared_ptr<const EntityRecord> stored;
  FR_CHECK_EQ(registry->lookup(other, stored).code, OutcomeCode::Committed);
  FR_CHECK(stored != nullptr);
  FR_CHECK_EQ(stored->record_generation.value(), std::uint64_t{1});
  FR_CHECK_EQ(stored->facts.size(), std::size_t{1});
}

FR_TEST_CASE(adversarial, contradictory_identity_facts_are_rejected) {
  std::unique_ptr<Registry> registry = frtest::make_registry(40);

  // Two facts of the same kind and scope with different values cannot both be
  // true of one device.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "contradictory-facts", "CONTRADICTORY-1");
    request.facts = {frtest::serial_fact("SERIAL-A"), frtest::serial_fact("SERIAL-B")};
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::InvalidEvidence);
    FR_CHECK_MSG(before.unchanged(*registry), "contradictory facts inside one request changed state");
  }
  // The same vendor scope carrying a different serial than the stored record.
  {
    const CanonicalId stored = register_one(*registry, "contradictory-target", "SERIAL-STORED");
    FR_CHECK(!stored.is_null());
    RegisterEntityRequest request = frtest::device_request(*registry, "contradictory-claim", "SERIAL-CLAIMED");
    request.canonical_id = stored;
    request.derivation_namespace.clear();
    const StateSnapshot before = StateSnapshot::capture(*registry);
    const Outcome outcome = registry->register_entity(request);
    FR_CHECK_EQ(outcome.code, OutcomeCode::IdentityConflict);
    FR_CHECK(outcome.match.has_value() && *outcome.match == fabric_registry::MatchClass::Conflicting);
    FR_CHECK_MSG(before.unchanged(*registry), "a contradictory serial changed registry state");
  }
  // Control: the same serial in two different vendor scopes is not a
  // contradiction; the two facts are different facts.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "two-scopes", "SERIAL-TWO-SCOPES");
    request.facts = {frtest::serial_fact("SERIAL-TWO-SCOPES", "vendor:0x15b3/product:0x1017"),
                     frtest::serial_fact("SERIAL-TWO-SCOPES", "vendor:0x9999/product:0x1017")};
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::Committed);
  }
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

FR_TEST_CASE(adversarial, stale_generation_epoch_boot_and_fenced_publisher_are_told_apart) {
  std::unique_ptr<Registry> registry = frtest::make_registry(41);
  const CanonicalId record = register_one(*registry, "authority-target", "AUTHORITY-SERIAL");
  FR_CHECK(!record.is_null());

  // A generation the record has never reached.
  {
    UpdateEvidenceRequest update;
    update.attempt = frtest::attempt_from("stale-generation");
    update.authority = registry->local_authority();
    update.target = record;
    update.expected_generation = RecordGeneration(99);
    update.facts = {frtest::serial_fact("AUTHORITY-SERIAL")};
    update.provenance = frtest::real_provenance();
    update.evidence_class = EvidenceClass::DurableAuthority;
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->update_evidence(update).code, OutcomeCode::StaleGeneration);
    FR_CHECK_MSG(before.unchanged(*registry), "a stale generation changed registry state");
  }

  // An epoch that has been superseded.
  const AuthorityClaim old_epoch_claim = registry->local_authority();
  {
    std::size_t demoted = 0;
    FR_CHECK_EQ(registry->advance_epoch(demoted).code, OutcomeCode::Committed);
    FR_CHECK_EQ(registry->epoch().value(), old_epoch_claim.epoch.value() + 1);
    RegisterEntityRequest request = frtest::device_request(*registry, "stale-epoch", "STALE-EPOCH-SERIAL");
    request.authority = old_epoch_claim;
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::StaleEpoch);
    FR_CHECK_MSG(before.unchanged(*registry), "a stale epoch changed registry state");
  }

  // An incarnation that has been replaced, and then a publisher that has been
  // fenced outright. Both are told apart from the stale-epoch case above.
  fabric_registry::PublisherAttachResult first;
  fabric_registry::PublisherAttachResult second;
  {
    fabric_registry::PublisherAttachRequest request;
    request.name = "authority-publisher";
    request.protocol_version = fabric_registry::protocol_version();
    first = registry->attach_publisher(request);
    FR_CHECK_EQ(first.outcome.code, OutcomeCode::Committed);
    request.publisher = first.publisher;
    second = registry->attach_publisher(request);
    FR_CHECK_EQ(second.outcome.code, OutcomeCode::Committed);
    FR_CHECK(second.fenced_previous);
    FR_CHECK(!(second.worker_boot == first.worker_boot));
  }
  {
    AuthorityClaim stale;
    stale.publisher = first.publisher;
    stale.worker_boot = first.worker_boot;
    stale.epoch = registry->epoch();
    RegisterEntityRequest request = frtest::device_request(*registry, "stale-boot", "STALE-BOOT-SERIAL");
    request.authority = stale;
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::StaleWorkerBoot);
    FR_CHECK_MSG(before.unchanged(*registry), "a stale worker boot changed registry state");
  }
  {
    std::size_t demoted = 0;
    FR_CHECK_EQ(registry->fence_publisher(second.publisher, FenceReason::Administrative, demoted).code,
                OutcomeCode::Committed);
    AuthorityClaim fenced;
    fenced.publisher = second.publisher;
    fenced.worker_boot = second.worker_boot;
    fenced.epoch = registry->epoch();
    RegisterEntityRequest request = frtest::device_request(*registry, "fenced", "FENCED-SERIAL");
    request.authority = fenced;
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::FencedPublisher);
    FR_CHECK_MSG(before.unchanged(*registry), "a fenced publisher changed registry state");
  }
  // A claim that is missing an incarnation is refused before anything else.
  {
    AuthorityClaim incomplete = registry->local_authority();
    incomplete.worker_boot = fabric_registry::WorkerBootId{};
    RegisterEntityRequest request = frtest::device_request(*registry, "incomplete", "INCOMPLETE-SERIAL");
    request.authority = incomplete;
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::NoAuthority);
    FR_CHECK_MSG(before.unchanged(*registry), "an incomplete authority claim changed registry state");
  }
}

FR_TEST_CASE(adversarial, generation_arithmetic_is_checked_and_advances_by_exactly_one_per_commit) {
  // The counter refuses to wrap instead of restarting a generation space.
  FR_CHECK(!RecordGeneration(RecordGeneration::max_value()).next().has_value());
  FR_CHECK_EQ(RecordGeneration(RecordGeneration::max_value() - 1).next()->value(),
              RecordGeneration::max_value());
  FR_CHECK_EQ(RecordGeneration(0).next()->value(), std::uint64_t{1});
  FR_CHECK_EQ(RecordGeneration(RecordGeneration::max_value()).value(), RecordGeneration::max_value());

  std::unique_ptr<Registry> registry = frtest::make_registry(42);
  const CanonicalId record = register_one(*registry, "generation-chain", "GENERATION-SERIAL");
  FR_CHECK(!record.is_null());
  std::shared_ptr<const EntityRecord> stored;
  FR_CHECK_EQ(registry->lookup(record, stored).code, OutcomeCode::Committed);
  FR_CHECK(stored != nullptr);
  FR_CHECK_EQ(stored->record_generation.value(), std::uint64_t{1});

  std::uint64_t expected = stored->record_generation.value();
  for (int commit = 0; commit < 50; ++commit) {
    UpdateEvidenceRequest update;
    update.attempt = frtest::attempt_from("generation-chain-" + std::to_string(commit));
    update.authority = registry->local_authority();
    update.target = record;
    update.facts = {frtest::serial_fact("GENERATION-SERIAL")};
    update.provenance = frtest::real_provenance();
    update.evidence_class = EvidenceClass::DurableAuthority;
    const Outcome outcome = registry->update_evidence(update);
    FR_CHECK_EQ(outcome.code, OutcomeCode::Committed);
    ++expected;
    FR_CHECK_EQ(registry->lookup(record, stored).code, OutcomeCode::Committed);
    if (stored->record_generation.value() != expected) {
      FR_FAIL("a record generation moved by more than one per commit");
    }
  }
  FR_CHECK_EQ(expected, std::uint64_t{51});
  FR_CHECK_EQ(registry->stats().lineage_entries, std::size_t{51});
}

// ---------------------------------------------------------------------------
// Metadata and configuration bounds
// ---------------------------------------------------------------------------

FR_TEST_CASE(adversarial, excessive_metadata_is_rejected_without_changing_state) {
  RegistryOptions options = frtest::test_options(43);
  options.limits.max_metadata_entries = 3;
  options.limits.max_metadata_value_bytes = 8;
  options.limits.max_metadata_bytes_per_entity = 24;
  std::unique_ptr<Registry> registry = std::make_unique<Registry>(options);

  // More entries than the configured bound.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "metadata-count", "META-COUNT-SERIAL");
    for (int index = 0; index < 4; ++index) {
      request.metadata.push_back(MetadataEntry{"key-" + std::to_string(index), "value"});
    }
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "excessive metadata entries changed registry state");
  }
  // A total above the per-entity byte bound.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "metadata-bytes", "META-BYTES-SERIAL");
    request.metadata.push_back(MetadataEntry{"aa", "12345678"});
    request.metadata.push_back(MetadataEntry{"bb", "12345678"});
    request.metadata.push_back(MetadataEntry{"cc", "12345678"});
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "an oversized metadata total changed registry state");
  }
  // A duplicate metadata key.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "metadata-duplicate", "META-DUP-SERIAL");
    request.metadata.push_back(MetadataEntry{"role", "1"});
    request.metadata.push_back(MetadataEntry{"role", "2"});
    const StateSnapshot before = StateSnapshot::capture(*registry);
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::MalformedRequest);
    FR_CHECK_MSG(before.unchanged(*registry), "a duplicate metadata key changed registry state");
  }
  // Control: three entries inside every bound are accepted.
  {
    RegisterEntityRequest request = frtest::device_request(*registry, "metadata-ok", "META-OK-SERIAL");
    request.metadata.push_back(MetadataEntry{"aa", "1234"});
    request.metadata.push_back(MetadataEntry{"bb", "1234"});
    request.metadata.push_back(MetadataEntry{"cc", "1234"});
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::Committed);
    FR_CHECK_EQ(registry->stats().entities, std::size_t{1});
  }
}

FR_TEST_CASE(adversarial, inconsistent_registry_options_throw_invalid_argument) {
  // A valid configuration must not throw, so the failures below are about the
  // specific field and not about construction in general.
  FR_CHECK_MSG(!options_are_rejected(frtest::test_options(44)), "a valid configuration was rejected");

  {
    RegistryOptions options = frtest::test_options(44);
    options.limits.max_string_bytes = 0;
    FR_CHECK_MSG(options_are_rejected(options), "max_string_bytes 0 was accepted");
  }
  {
    RegistryOptions options = frtest::test_options(44);
    options.limits.max_record_bytes = 1;
    FR_CHECK_MSG(options_are_rejected(options), "max_record_bytes 1 was accepted");
  }
  {
    RegistryOptions options = frtest::test_options(44);
    options.limits.max_facts_per_entity = 0;
    FR_CHECK_MSG(options_are_rejected(options), "max_facts_per_entity 0 was accepted");
  }
  {
    RegistryOptions options = frtest::test_options(44);
    options.initial_epoch = CoordinatorEpoch(0);
    FR_CHECK_MSG(options_are_rejected(options), "initial_epoch 0 was accepted");
  }
  {
    RegistryOptions options = frtest::test_options(44);
    options.limits.max_metadata_bytes_per_entity = 1;
    options.limits.max_metadata_value_bytes = 32;
    FR_CHECK_MSG(options_are_rejected(options), "an inconsistent metadata bound was accepted");
  }
  // The small limits used elsewhere in this file are themselves valid.
  {
    RegistryOptions options = frtest::test_options(44);
    options.limits.max_string_bytes = 64;
    options.limits.max_metadata_value_bytes = 8;
    options.limits.max_metadata_bytes_per_entity = 24;
    FR_CHECK_MSG(!options_are_rejected(options), "the small test configuration was rejected");
  }
}

FR_TEST_CASE(adversarial, the_entity_bound_is_enforced_at_the_fifth_record) {
  RegistryOptions options = frtest::test_options(45);
  options.limits.max_entities = 4;
  std::unique_ptr<Registry> registry = std::make_unique<Registry>(options);

  for (int index = 0; index < 4; ++index) {
    const std::string label = "bounded-" + std::to_string(index);
    RegisterEntityRequest request =
        frtest::device_request(*registry, label, "BOUNDED-SERIAL-" + std::to_string(index),
                              EntityClass::Switch, "test/bounded-" + std::to_string(index));
    FR_CHECK_EQ(registry->register_entity(request).code, OutcomeCode::Committed);
  }
  FR_CHECK_EQ(registry->stats().entities, std::size_t{4});

  RegisterEntityRequest fifth =
      frtest::device_request(*registry, "bounded-4", "BOUNDED-SERIAL-4", EntityClass::Switch, "test/bounded-4");
  const StateSnapshot before = StateSnapshot::capture(*registry);
  FR_CHECK_EQ(registry->register_entity(fifth).code, OutcomeCode::ResourceLimit);
  FR_CHECK_MSG(before.unchanged(*registry), "the entity bound changed registry state");
  FR_CHECK_EQ(registry->stats().entities, std::size_t{4});
}

// ---------------------------------------------------------------------------
// Transport and coordinator endurance
// ---------------------------------------------------------------------------

FR_TEST_CASE(adversarial, two_hundred_connect_and_close_cycles_then_a_successful_registration) {
  CoordinatorOptions options;
  options.listen = Endpoint{"127.0.0.1", 0};
  options.registry = frtest::test_options(46);
  options.max_sessions = 256;
  options.frame_limits.max_sessions = 256;
  options.transport.poll_interval = std::chrono::milliseconds(5);
  std::string error;
  std::unique_ptr<Coordinator> coordinator = Coordinator::start(options, error);
  FR_CHECK_MSG(coordinator != nullptr, "the coordinator did not start: " + error);

  for (int cycle = 0; cycle < 200; ++cycle) {
    PublisherClientOptions client_options;
    client_options.coordinator = coordinator->endpoint();
    client_options.name = "cycle-client";
    client_options.transport.poll_interval = std::chrono::milliseconds(5);
    std::unique_ptr<PublisherClient> client = PublisherClient::connect(client_options, error);
    FR_CHECK_MSG(client != nullptr, "a connect cycle failed: " + error + " at cycle " + std::to_string(cycle));
    client->close();
    FR_CHECK_MSG(!client->connected(), "a closed publisher client still reports itself connected");
  }

  // The transport is still healthy: a fresh publisher attaches and registers.
  PublisherClientOptions client_options;
  client_options.coordinator = coordinator->endpoint();
  client_options.name = "cycle-final";
  client_options.transport.poll_interval = std::chrono::milliseconds(5);
  std::unique_ptr<PublisherClient> client = PublisherClient::connect(client_options, error);
  FR_CHECK_MSG(client != nullptr, "the publisher could not attach after the cycles: " + error);
  FR_CHECK_MSG(client->authority().is_complete(), "the attached publisher holds no complete claim");
  const fabric_registry::RemoteOutcome remote =
      client->register_entity(client_request("cycle-final", "CYCLE-SERIAL", "test/cycles"));
  FR_CHECK_EQ(remote.outcome.code, OutcomeCode::Committed);
  FR_CHECK(remote.succeeded());
  FR_CHECK_EQ(coordinator->stats().entities, std::size_t{1});
  FR_CHECK(client->detach().succeeded());

  coordinator->stop();
  FR_CHECK_EQ(coordinator->active_sessions(), std::size_t{0});
}

FR_TEST_CASE(adversarial, twenty_five_coordinator_start_stop_iterations_leave_nothing_behind) {
  for (int iteration = 0; iteration < 25; ++iteration) {
    CoordinatorOptions options;
    options.listen = Endpoint{"127.0.0.1", 0};
    options.registry = frtest::test_options(static_cast<std::uint64_t>(100 + iteration));
    options.transport.poll_interval = std::chrono::milliseconds(5);
    std::string error;
    std::unique_ptr<Coordinator> coordinator = Coordinator::start(options, error);
    FR_CHECK_MSG(coordinator != nullptr, "iteration " + std::to_string(iteration) + ": " + error);
    FR_CHECK_EQ(coordinator->active_sessions(), std::size_t{0});

    PublisherClientOptions client_options;
    client_options.coordinator = coordinator->endpoint();
    client_options.name = "iteration-client";
    client_options.transport.poll_interval = std::chrono::milliseconds(5);
    std::unique_ptr<PublisherClient> client = PublisherClient::connect(client_options, error);
    FR_CHECK_MSG(client != nullptr, "iteration " + std::to_string(iteration) + ": " + error);
    const std::string label = "iteration-" + std::to_string(iteration);
    const fabric_registry::RemoteOutcome remote =
        client->register_entity(client_request(label, "ITERATION-SERIAL-" + std::to_string(iteration), "test/iterations"));
    FR_CHECK_MSG(remote.outcome.committed(), "iteration " + std::to_string(iteration) +
                                                 ": " + std::string(fabric_registry::to_string(remote.outcome.code)));
    FR_CHECK_EQ(coordinator->stats().entities, std::size_t{1});
    FR_CHECK(client->detach().succeeded());

    coordinator->stop();
    FR_CHECK_MSG(coordinator->active_sessions() == 0,
                 "iteration " + std::to_string(iteration) + " left a session behind");
  }
}

FR_TEST_CASE(adversarial, a_coordinator_refuses_to_start_on_a_corrupt_state_file) {
  const std::filesystem::path path = frtest::temporary_state_path("coordinator-corrupt");
  frtest::remove_state(path);
  {
    std::unique_ptr<Registry> registry = frtest::make_registry(47);
    FR_CHECK(!register_one(*registry, "corrupt-start", "CORRUPT-START-SERIAL").is_null());
    FR_CHECK_EQ(registry->save(path).code, OutcomeCode::Committed);
  }
  std::vector<std::uint8_t> image = load_bytes(path);
  FR_CHECK(image.size() > fabric_registry::persistence::kHeaderBytes + 8);
  image[fabric_registry::persistence::kHeaderBytes + 8] =
      static_cast<std::uint8_t>(image[fabric_registry::persistence::kHeaderBytes + 8] ^ 0x10u);
  store_bytes(path, image);

  CoordinatorOptions options;
  options.listen = Endpoint{"127.0.0.1", 0};
  options.state_path = path;
  std::string error;
  std::unique_ptr<Coordinator> coordinator = Coordinator::start(options, error);
  FR_CHECK_MSG(coordinator == nullptr, "the coordinator started on a corrupt state file");
  FR_CHECK(!error.empty());
  FR_CHECK_MSG(error.find("integrity-failure") != std::string::npos,
               "the refusal did not name the integrity failure: " + error);

  // Control: a state path with no file at all is not corruption; the
  // coordinator starts empty and reports that it did. The path is removed
  // first because a stopped coordinator writes its final state there.
  CoordinatorOptions fresh_options = options;
  const std::filesystem::path absent = path.parent_path() / "absent-state.bin";
  fresh_options.state_path = absent;
  frtest::remove_state(absent);
  std::unique_ptr<Coordinator> fresh = Coordinator::start(fresh_options, error);
  FR_CHECK_MSG(fresh != nullptr, "the coordinator refused to start without a state file: " + error);
  FR_CHECK_EQ(fresh->stats().entities, std::size_t{0});
  FR_CHECK_MSG(fresh->recovery_report().detail.find("empty") != std::string::npos,
               "a fresh coordinator did not report that it started empty: " + fresh->recovery_report().detail);
  fresh->stop();
  FR_CHECK_EQ(fresh->active_sessions(), std::size_t{0});

  frtest::remove_state(absent);
  frtest::remove_state(path);
}

int main(int argc, char** argv) { return frtest::run_all(argc, argv); }
