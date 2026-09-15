// Fabric Registry — the mutation pipeline.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every mutation follows the same deterministic pipeline:
//
//   decode / validate            (outside the lock; no shared state is touched)
//   resolve authority            (exclusive lock; epoch, publisher, incarnation)
//   idempotency                  (exclusive lock)
//   resolve identity + reconcile (exclusive lock)
//   check expected generation    (exclusive lock)
//   validate conflicts           (exclusive lock)
//   prepare indexes              (exclusive lock; nothing is published yet)
//   commit atomically            (exclusive lock; one generation transition)
//   persist if required          (coordinator level, outside the lock)
//   emit structured outcome
//
// A failed mutation leaves no partial state: every index update happens inside
// install_record, which is the single point at which a record becomes visible.
// The alias table and the record table can therefore never diverge.

#include <algorithm>
#include <cstring>

#include "fabric_registry/digest.hpp"
#include "fabric_registry/record_codec.hpp"
#include "fabric_registry/serialization.hpp"
#include "registry_internal.hpp"

namespace fabric_registry {

namespace {

// ---------------------------------------------------------------------------
// Request digests
// ---------------------------------------------------------------------------

/// Digest over the semantic content of a request. The authority that carried
/// the request is deliberately excluded: a publisher that reattaches with a new
/// incarnation must still be able to replay its own attempt idempotently.
class RequestHasher {
public:
  explicit RequestHasher(const char* domain) { hasher_.begin(domain); }

  void scope(const ScopeRef& value) {
    hasher_.u8(value.fabric.has_value() ? 1 : 0);
    if (value.fabric.has_value()) {
      hasher_.bytes(value.fabric->bytes());
    }
    hasher_.u8(value.site.has_value() ? 1 : 0);
    if (value.site.has_value()) {
      hasher_.bytes(value.site->bytes());
    }
    hasher_.u8(value.control_domain.has_value() ? 1 : 0);
    if (value.control_domain.has_value()) {
      hasher_.bytes(value.control_domain->bytes());
    }
    hasher_.u8(value.parent_device.has_value() ? 1 : 0);
    if (value.parent_device.has_value()) {
      hasher_.u8(static_cast<std::uint8_t>(value.parent_device->entity_class()));
      hasher_.bytes(value.parent_device->bytes());
    }
  }

  void facts(const std::vector<IdentityFact>& value) {
    hasher_.sequence(static_cast<std::uint64_t>(value.size()));
    for (const IdentityFact& fact : value) {
      hasher_.u8(static_cast<std::uint8_t>(fact.kind));
      hasher_.text(fact.scope);
      hasher_.text(fact.value);
    }
  }

  void aliases(const std::vector<AliasInput>& value) {
    hasher_.sequence(static_cast<std::uint64_t>(value.size()));
    for (const AliasInput& alias : value) {
      hasher_.u8(static_cast<std::uint8_t>(alias.alias_namespace));
      hasher_.text(alias.value);
    }
  }

  void metadata(const std::vector<MetadataEntry>& value) {
    hasher_.sequence(static_cast<std::uint64_t>(value.size()));
    for (const MetadataEntry& entry : value) {
      hasher_.text(entry.key);
      hasher_.text(entry.value);
    }
  }

  void provenance(const Provenance& value) {
    hasher_.u8(static_cast<std::uint8_t>(value.source));
    hasher_.u8(static_cast<std::uint8_t>(value.validity_class));
    hasher_.text(value.mechanism);
    hasher_.text(value.source_identity);
  }

  void generation(const std::optional<RecordGeneration>& value) {
    hasher_.u8(value.has_value() ? 1 : 0);
    if (value.has_value()) {
      hasher_.u64(value->value());
    }
  }

  void canonical_id(const std::optional<CanonicalId>& value) {
    hasher_.u8(value.has_value() ? 1 : 0);
    if (value.has_value()) {
      hasher_.u8(static_cast<std::uint8_t>(value->entity_class()));
      hasher_.bytes(value->bytes());
    }
  }

  void class_value(EntityClass value) { hasher_.u8(static_cast<std::uint8_t>(value)); }
  void u8_value(std::uint8_t value) { hasher_.u8(value); }
  void text(std::string_view value) { hasher_.text(value); }
  void identifier(const OpaqueId<RegistrationTag>& value) { hasher_.bytes(value.bytes()); }

  RequestDigest finish() { return RequestDigest::from_bytes(hasher_.finish()); }

private:
  CanonicalHasher hasher_;
};

} // namespace

RequestDigest digest_registration_request(const RegisterEntityRequest& request) {
  RequestHasher hasher("fabric-registry/request/register-entity/1");
  hasher.identifier(request.attempt);
  hasher.class_value(request.entity_class);
  hasher.canonical_id(request.canonical_id);
  hasher.text(request.derivation_namespace);
  hasher.text(request.friendly_name);
  hasher.facts(request.facts);
  hasher.aliases(request.aliases);
  hasher.metadata(request.metadata);
  hasher.scope(request.scope);
  hasher.provenance(request.provenance);
  hasher.u8_value(static_cast<std::uint8_t>(request.evidence_class));
  hasher.u8_value(static_cast<std::uint8_t>(request.admission));
  hasher.generation(request.expected_generation);
  hasher.u8_value(static_cast<std::uint8_t>(request.resolution));
  hasher.canonical_id(request.resolve_to);
  hasher.u8_value(request.record_conflict ? 1 : 0);
  return hasher.finish();
}

RequestDigest digest_update_evidence_request(const UpdateEvidenceRequest& request) {
  RequestHasher hasher("fabric-registry/request/update-evidence/1");
  hasher.identifier(request.attempt);
  hasher.u8_value(static_cast<std::uint8_t>(request.target.entity_class()));
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.facts(request.facts);
  hasher.provenance(request.provenance);
  hasher.u8_value(static_cast<std::uint8_t>(request.evidence_class));
  hasher.u8_value(request.merge_facts ? 1 : 0);
  return hasher.finish();
}

RequestDigest digest_alias_request(const AliasMutationRequest& request) {
  RequestHasher hasher("fabric-registry/request/alias-mutation/1");
  hasher.identifier(request.attempt);
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.u8_value(static_cast<std::uint8_t>(request.alias.alias_namespace));
  hasher.text(request.alias.value);
  return hasher.finish();
}

RequestDigest digest_supersede_request(const SupersedeEntityRequest& request) {
  RequestHasher hasher("fabric-registry/request/supersede/1");
  hasher.identifier(request.attempt);
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.canonical_id(request.successor);
  hasher.text(request.reason);
  return hasher.finish();
}

RequestDigest digest_retire_request(const RetireEntityRequest& request) {
  RequestHasher hasher("fabric-registry/request/retire/1");
  hasher.identifier(request.attempt);
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.text(request.reason);
  return hasher.finish();
}

RequestDigest digest_tombstone_request(const TombstoneEntityRequest& request) {
  RequestHasher hasher("fabric-registry/request/tombstone/1");
  hasher.identifier(request.attempt);
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.text(request.reason);
  return hasher.finish();
}

RequestDigest digest_revalidate_request(const RevalidateEntityRequest& request) {
  RequestHasher hasher("fabric-registry/request/revalidate/1");
  hasher.identifier(request.attempt);
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.facts(request.facts);
  hasher.provenance(request.provenance);
  hasher.u8_value(static_cast<std::uint8_t>(request.evidence_class));
  hasher.u8_value(request.merge_facts ? 1 : 0);
  return hasher.finish();
}

RequestDigest digest_resolve_conflict_request(const ResolveConflictRequest& request) {
  RequestHasher hasher("fabric-registry/request/resolve-conflict/1");
  hasher.identifier(request.attempt);
  hasher.text(request.target.to_string());
  hasher.generation(request.expected_generation);
  hasher.u8_value(static_cast<std::uint8_t>(request.resolution));
  hasher.text(request.reason);
  return hasher.finish();
}

RequestDigest digest_reconcile_request(const ReconcileObservationRequest& request) {
  RequestHasher hasher("fabric-registry/request/reconcile/1");
  hasher.identifier(request.attempt);
  hasher.class_value(request.entity_class);
  hasher.facts(request.facts);
  hasher.aliases(request.aliases);
  hasher.scope(request.scope);
  hasher.provenance(request.provenance);
  hasher.u8_value(static_cast<std::uint8_t>(request.resolution));
  hasher.canonical_id(request.resolve_to);
  return hasher.finish();
}

namespace {

// ---------------------------------------------------------------------------
// Shared preparation
// ---------------------------------------------------------------------------

StableHardwareIdentity hardware_identity_or_null(const std::vector<IdentityFact>& facts) {
  if (!has_strong_fact(facts)) {
    return StableHardwareIdentity{};
  }
  return compute_stable_hardware_identity(facts);
}

/// A record-shaped description built entirely before the lock is taken.
struct PreparedRecord {
  EntityClass entity_class{EntityClass::Unknown};
  CanonicalId canonical_id{};
  bool explicit_id{false};
  std::string derivation_namespace;
  std::string friendly_name;
  std::vector<IdentityFact> facts;
  StableHardwareIdentity hardware_identity{};
  std::vector<AliasKey> aliases;
  std::vector<MetadataEntry> metadata;
  ScopeRef scope;
  Provenance provenance;
  EvidenceClass evidence_class{EvidenceClass::Unspecified};
  RequestDigest digest{};
};

Outcome prepare_scope(const ScopeRef& scope, EntityClass entity_class) {
  if (scope.fabric.has_value() && scope.fabric->is_null()) {
    return Outcome(OutcomeCode::MalformedRequest, "the request carries a null fabric reference");
  }
  if (scope.site.has_value() && scope.site->is_null()) {
    return Outcome(OutcomeCode::MalformedRequest, "the request carries a null site reference");
  }
  if (scope.control_domain.has_value() && scope.control_domain->is_null()) {
    return Outcome(OutcomeCode::MalformedRequest, "the request carries a null control-domain reference");
  }
  if (scope.parent_device.has_value()) {
    if (scope.parent_device->is_null()) {
      return Outcome(OutcomeCode::MalformedRequest, "the request carries a null parent device reference");
    }
    if (!is_device_class(scope.parent_device->entity_class())) {
      return Outcome(OutcomeCode::MalformedRequest, "the parent device reference is not a device class")
          .field_step("validate", "parent-device", scope.parent_device->to_string(),
                      "only device-bearing entity classes may be a parent device");
    }
  }
  if (requires_parent_device(entity_class) && !scope.parent_device.has_value()) {
    return Outcome(OutcomeCode::MalformedRequest,
                   "records of this entity class must name the device that owns them")
        .field_step("validate", "parent-device", std::string(to_string(entity_class)),
                    "a port or endpoint without its parent device would have no anchorable identity");
  }
  return Outcome(OutcomeCode::Committed, "scope accepted");
}

Outcome prepare_text(std::string_view value, const char* field, std::size_t max_string_bytes, std::string& out) {
  if (value.size() > max_string_bytes) {
    return Outcome(OutcomeCode::ResourceLimit, std::string(field) + " exceeds the configured string bound")
        .field_step("validate", field, std::to_string(value.size()), "the bound is " + std::to_string(max_string_bytes));
  }
  if (!is_valid_identity_text(value)) {
    return Outcome(OutcomeCode::MalformedRequest, std::string(field) + " is not valid identity text")
        .field_step("validate", field, std::string(value), "the text is not valid UTF-8 or contains a control character");
  }
  out.assign(trim_ascii(value));
  return Outcome(OutcomeCode::Committed, "text accepted");
}

OutcomeCode outcome_for_alias_issue(AliasIssue issue) {
  switch (issue) {
    case AliasIssue::UnknownNamespace:
    case AliasIssue::MissingFabricScope:
    case AliasIssue::MissingSiteScope:
    case AliasIssue::MissingEntityClassScope:
    case AliasIssue::MissingParentDeviceScope:
      return OutcomeCode::MalformedRequest;
    default:
      return OutcomeCode::InvalidEvidence;
  }
}

/// Builds everything a registration needs without touching shared state.
Outcome prepare_registration(const RegistryState& state, const RegisterEntityRequest& request, PreparedRecord& out) {
  const RegistryLimits& limits = state.limits;
  if (request.attempt.is_null()) {
    return Outcome(OutcomeCode::MalformedRequest,
                   "a registration attempt must carry a non-null attempt identifier; it is the idempotency key");
  }
  if (!is_valid_entity_class(request.entity_class)) {
    return Outcome(OutcomeCode::MalformedRequest, "the request names an entity class that does not exist");
  }
  if (request.evidence_class == EvidenceClass::Unspecified) {
    return Outcome(OutcomeCode::InvalidEvidence,
                   "the request does not say whether its evidence is process-bound or a durable authority act");
  }

  PreparedRecord prepared;
  prepared.entity_class = request.entity_class;

  std::vector<IdentityFact> facts;
  const IdentityIssue fact_issue =
      normalize_fact_set(request.facts, limits.max_facts_per_entity, limits.max_string_bytes, facts);
  if (fact_issue != IdentityIssue::None) {
    return Outcome(OutcomeCode::InvalidEvidence, "the request carries a fact set that cannot be used")
        .field_step("validate", "facts", std::string(to_string(fact_issue)),
                    "one of the supplied identity facts is invalid, duplicated or contradictory");
  }
  prepared.facts = std::move(facts);
  prepared.hardware_identity = hardware_identity_or_null(prepared.facts);

  const ValidationResult provenance_result = validate_provenance(request.provenance, limits.max_string_bytes);
  if (!provenance_result) {
    return Outcome(OutcomeCode::InvalidEvidence, "the request provenance is not usable")
        .field_step("validate", "provenance", provenance_result.message, "every record must carry explicit provenance");
  }
  prepared.provenance = request.provenance;

  std::string name;
  Outcome text = prepare_text(request.friendly_name, "friendly-name", limits.max_string_bytes, name);
  if (!text.committed()) {
    return text;
  }
  prepared.friendly_name = std::move(name);

  if (request.canonical_id.has_value()) {
    if (!request.derivation_namespace.empty()) {
      return Outcome(OutcomeCode::MalformedRequest,
                     "a request may either name a canonical identity or derive one, never both");
    }
    if (request.canonical_id->is_null()) {
      return Outcome(OutcomeCode::MalformedRequest, "the request carries a null canonical identity");
    }
    if (request.canonical_id->entity_class() != request.entity_class) {
      return Outcome(OutcomeCode::MalformedRequest, "the canonical identity does not belong to the named entity class")
          .field_step("validate", "canonical-id", request.canonical_id->to_string(),
                      std::string("the request declares entity class ") + std::string(to_string(request.entity_class)));
    }
    prepared.canonical_id = *request.canonical_id;
    prepared.explicit_id = true;
  } else {
    const CanonicalIdResult derived = derive_canonical_id(request.entity_class, request.derivation_namespace,
                                                          prepared.facts, limits.max_string_bytes);
    if (!derived) {
      return Outcome(OutcomeCode::InvalidEvidence, "the canonical identity could not be derived")
          .field_step("validate", "derivation", std::string(to_string(derived.issue)),
                      "a derived identity requires a non-empty namespace and at least one strong identity fact");
    }
    prepared.canonical_id = *derived.id;
    prepared.derivation_namespace = request.derivation_namespace;
  }

  const Outcome scope_result = prepare_scope(request.scope, request.entity_class);
  if (!scope_result.committed()) {
    return scope_result;
  }
  prepared.scope = request.scope;

  const AliasIssue alias_issue =
      build_alias_keys(request.aliases, scope_input_for(request.scope, request.entity_class), limits.max_string_bytes,
                       prepared.aliases);
  if (alias_issue != AliasIssue::None) {
    return Outcome(outcome_for_alias_issue(alias_issue), "the request carries an alias that cannot be used")
        .field_step("validate", "alias", std::string(to_string(alias_issue)),
                    "the alias value or its required scope is missing or malformed");
  }
  if (prepared.aliases.size() > limits.max_aliases_per_entity) {
    return Outcome(OutcomeCode::ResourceLimit, "the request carries more aliases than an entity may hold");
  }

  const ValidationResult metadata_result = normalize_metadata(request.metadata, limits, prepared.metadata);
  if (!metadata_result) {
    return Outcome(OutcomeCode::MalformedRequest, "the request metadata is not usable")
        .field_step("validate", "metadata", metadata_result.message, "metadata failed validation");
  }

  prepared.evidence_class = request.evidence_class;
  prepared.digest = digest_registration_request(request);

  CanonicalHasher size_hasher;
  size_hasher.begin("fabric-registry/record-size/1");
  if (prepared.explicit_id) {
    size_hasher.text("explicit");
  } else {
    size_hasher.text(prepared.derivation_namespace);
  }
  size_hasher.text(prepared.friendly_name);
  size_hasher.sequence(static_cast<std::uint64_t>(prepared.facts.size()));
  std::size_t approximate = prepared.friendly_name.size() + prepared.derivation_namespace.size() + 64;
  for (const IdentityFact& fact : prepared.facts) {
    approximate += fact.value.size() + fact.scope.size() + 8;
  }
  for (const AliasKey& alias : prepared.aliases) {
    approximate += alias.value.size() + alias.scope.size() + 8;
  }
  for (const MetadataEntry& entry : prepared.metadata) {
    approximate += entry.key.size() + entry.value.size() + 8;
  }
  if (approximate > limits.max_record_bytes) {
    return Outcome(OutcomeCode::ResourceLimit, "the resulting record would exceed the configured record bound")
        .field_step("validate", "record-size", std::to_string(approximate),
                    "the bound is " + std::to_string(limits.max_record_bytes));
  }

  out = std::move(prepared);
  return Outcome(OutcomeCode::Committed, "request validated");
}

// ---------------------------------------------------------------------------
// Identity resolution
// ---------------------------------------------------------------------------

struct Resolution {
  MatchClass match{MatchClass::NoMatch};
  RecordPtr target;
  std::vector<CanonicalId> candidates;
  std::vector<IdentityFact> conflicting_facts;
  std::vector<AliasKey> conflicting_aliases;
  std::string detail;
};

bool fact_present(const std::vector<IdentityFact>& facts, const IdentityFact& probe) {
  return std::binary_search(facts.begin(), facts.end(), probe);
}

/// Facts of the observation that disagree with a stored fact of the same
/// (kind, scope).
std::vector<IdentityFact> contradictions(const EntityRecord& record, const std::vector<IdentityFact>& facts) {
  std::vector<IdentityFact> out;
  for (const IdentityFact& fact : facts) {
    const auto position = std::lower_bound(
        record.facts.begin(), record.facts.end(), fact,
        [](const IdentityFact& left, const IdentityFact& right) {
          if (left.kind != right.kind) {
            return left.kind < right.kind;
          }
          return left.scope < right.scope;
        });
    if (position == record.facts.end() || position->kind != fact.kind || position->scope != fact.scope) {
      continue;
    }
    if (position->value != fact.value) {
      out.push_back(fact);
    }
  }
  return out;
}

std::vector<IdentityFact> strong_facts_of(const std::vector<IdentityFact>& facts) {
  std::vector<IdentityFact> out;
  for (const IdentityFact& fact : facts) {
    if (fact_strength(fact.kind) == FactStrength::Strong) {
      out.push_back(fact);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool strong_facts_are_comparable(const std::vector<IdentityFact>& observation, const EntityRecord& record) {
  const std::vector<IdentityFact> observation_strong = strong_facts_of(observation);
  const std::vector<IdentityFact> record_strong = strong_facts_of(record.facts);
  if (observation_strong.empty() || record_strong.empty()) {
    return false;
  }
  const bool observation_subset =
      std::includes(record_strong.begin(), record_strong.end(), observation_strong.begin(), observation_strong.end());
  const bool record_subset =
      std::includes(observation_strong.begin(), observation_strong.end(), record_strong.begin(), record_strong.end());
  return observation_subset || record_subset;
}

std::vector<CanonicalId> sorted_unique(std::vector<CanonicalId> values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
  return values;
}

Resolution resolve_identity(const RegistryState& state, const PreparedRecord& prepared) {
  Resolution resolution;
  resolution.conflicting_aliases = prepared.aliases;

  // Step 1: the canonical identity itself.
  const auto by_id = state.records.find(prepared.canonical_id);
  if (by_id != state.records.end()) {
    const RecordPtr& record = by_id->second;
    resolution.conflicting_facts = contradictions(*record, prepared.facts);
    resolution.candidates = {record->id};
    if (!resolution.conflicting_facts.empty()) {
      resolution.match = MatchClass::Conflicting;
      resolution.detail = "the canonical identity exists but the observation contradicts its stored facts";
      return resolution;
    }
    resolution.match = MatchClass::ExactCanonical;
    resolution.target = record;
    resolution.detail = "the canonical identity exists and the observation agrees with it";
    return resolution;
  }

  // Collect every record that shares at least one fact with the observation.
  std::vector<CanonicalId> touched;
  bool truncated = false;
  for (const IdentityFact& fact : prepared.facts) {
    const auto entry = state.fact_index.find(fact);
    if (entry == state.fact_index.end()) {
      continue;
    }
    if (entry->second.size() > state.limits.max_enumeration) {
      truncated = true;
      break;
    }
    touched.insert(touched.end(), entry->second.begin(), entry->second.end());
  }
  touched = sorted_unique(std::move(touched));
  if (truncated) {
    resolution.match = MatchClass::Ambiguous;
    resolution.detail = "the observation shares facts with more records than the configured enumeration bound";
    return resolution;
  }

  // Step 2: stable hardware identity matching.
  std::vector<CanonicalId> hardware_matches;
  std::vector<CanonicalId> contradicting;
  for (const CanonicalId& id : touched) {
    const RecordPtr& record = state.records.find(id)->second;
    const std::vector<IdentityFact> conflicts = contradictions(*record, prepared.facts);
    if (!conflicts.empty()) {
      contradicting.push_back(id);
      continue;
    }
    if (strong_facts_are_comparable(prepared.facts, *record)) {
      hardware_matches.push_back(id);
    }
  }
  if (hardware_matches.size() == 1) {
    resolution.match = MatchClass::StableHardware;
    resolution.target = state.records.find(hardware_matches.front())->second;
    resolution.candidates = hardware_matches;
    resolution.detail = "strong hardware facts matched exactly with no contradicting fact";
    return resolution;
  }
  if (hardware_matches.size() > 1) {
    resolution.match = MatchClass::Ambiguous;
    resolution.candidates = hardware_matches;
    resolution.detail = "more than one record matched at equal hardware strength";
    return resolution;
  }
  if (!contradicting.empty()) {
    resolution.match = MatchClass::Conflicting;
    resolution.candidates = contradicting;
    const RecordPtr& record = state.records.find(contradicting.front())->second;
    resolution.conflicting_facts = contradictions(*record, prepared.facts);
    resolution.detail = "the observation contradicts an existing record";
    return resolution;
  }

  // Step 3: proven alias matching.
  std::vector<CanonicalId> alias_matches;
  std::vector<AliasKey> alias_conflicts;
  for (const AliasKey& alias : prepared.aliases) {
    if (!alias_is_unique(alias.alias_namespace)) {
      continue;
    }
    const auto entry = state.alias_index.find(alias);
    if (entry != state.alias_index.end()) {
      alias_matches.push_back(entry->second);
    }
  }
  alias_matches = sorted_unique(std::move(alias_matches));
  if (alias_matches.size() == 1) {
    const RecordPtr& record = state.records.find(alias_matches.front())->second;
    resolution.conflicting_facts = contradictions(*record, prepared.facts);
    resolution.candidates = alias_matches;
    if (!resolution.conflicting_facts.empty()) {
      resolution.match = MatchClass::Conflicting;
      resolution.detail = "a unique alias matched but the observation contradicts that record";
      return resolution;
    }
    if (strong_facts_are_comparable(prepared.facts, *record)) {
      resolution.match = MatchClass::ProvenAlias;
      resolution.target = record;
      resolution.detail = "a unique alias resolved to exactly one record whose strong facts corroborate it";
      return resolution;
    }
    resolution.match = MatchClass::ProbableInsufficient;
    resolution.target = record;
    resolution.detail = "a unique alias resolved to exactly one record but no strong fact corroborates the match";
    return resolution;
  }
  if (alias_matches.size() > 1) {
    resolution.match = MatchClass::Ambiguous;
    resolution.candidates = alias_matches;
    resolution.detail = "unique aliases resolved to more than one record";
    return resolution;
  }

  // Step 4: weak corroboration only.
  if (!touched.empty()) {
    resolution.match = MatchClass::ProbableInsufficient;
    resolution.candidates = touched;
    resolution.detail = "the observation shares facts with existing records, but none of them is strong";
    return resolution;
  }

  resolution.match = MatchClass::NoMatch;
  resolution.detail = "nothing in the registry refers to this observation";
  return resolution;
}

Outcome outcome_for_match(const Resolution& resolution, const PreparedRecord& prepared) {
  Outcome outcome(OutcomeCode::Committed, resolution.detail);
  outcome.match = resolution.match;
  for (const CanonicalId& id : resolution.candidates) {
    outcome.related.push_back(id);
  }
  for (const IdentityFact& fact : resolution.conflicting_facts) {
    outcome.steps.push_back(ExplanationStep{"conflict", render_fact(fact), fact.value,
                                            "the stored record disagrees with this value"});
  }
  (void)prepared;
  return outcome;
}

std::vector<AliasKey> aliases_bound_elsewhere(const RegistryState& state,
                                              const std::vector<AliasKey>& aliases,
                                              const CanonicalId& owner) {
  std::vector<AliasKey> conflicts;
  for (const AliasKey& alias : aliases) {
    if (!alias_is_unique(alias.alias_namespace)) {
      continue;
    }
    const auto entry = state.alias_index.find(alias);
    if (entry != state.alias_index.end() && entry->second != owner) {
      conflicts.push_back(alias);
    }
  }
  return conflicts;
}

/// The registry generation install_record is about to assign.
RegistryGeneration predicted_next_generation(const RegistryState& state) {
  const std::optional<RegistryGeneration> next = state.generation.next();
  return next.has_value() ? *next : state.generation;
}

void fill_evidence(EvidenceState& evidence,
                   EvidenceClass evidence_class,
                   const Provenance& provenance,
                   const RegistryState& state,
                   const AuthorityClaim& claim,
                   std::optional<EvidenceGeneration> previous) {
  EvidenceGeneration generation = EvidenceGeneration::first();
  if (previous.has_value()) {
    generation = previous->next().value_or(*previous);
  }
  evidence.generation = generation;
  evidence.evidence_class = evidence_class;
  evidence.provenance = provenance;
  evidence.epoch = state.epoch;
  evidence.publisher = claim.publisher;
  evidence.publisher_boot = claim.worker_boot;
  evidence.accepted_at = predicted_next_generation(state);
  evidence.valid = true;
}

void merge_facts(std::vector<IdentityFact>& target, const std::vector<IdentityFact>& additions) {
  for (const IdentityFact& fact : additions) {
    if (!fact_present(target, fact)) {
      target.push_back(fact);
    }
  }
  std::sort(target.begin(), target.end());
}

void merge_aliases(std::vector<AliasKey>& target, const std::vector<AliasKey>& additions) {
  for (const AliasKey& alias : additions) {
    if (std::find(target.begin(), target.end(), alias) == target.end()) {
      target.push_back(alias);
    }
  }
  std::sort(target.begin(), target.end());
}

Outcome outcome_generation_exhausted() {
  return Outcome(OutcomeCode::ResourceLimit, "the registry generation space is exhausted");
}

/// Common tail of every mutation: record the outcome in the idempotency log.
Outcome finish_mutation(RegistryState& state,
                        Outcome outcome,
                        const RegistrationId& attempt,
                        const AuthorityClaim& claim,
                        const RequestDigest& digest) {
  outcome.request_digest = digest;
  outcome.epoch = state.epoch;
  outcome.state_generation = state.generation;
  if (outcome.committed()) {
    IdempotencyEntry entry;
    entry.publisher = claim.publisher;
    entry.producer_boot = claim.worker_boot;
    entry.attempt = attempt;
    entry.digest = digest;
    entry.code = outcome.code;
    if (outcome.record.has_value()) {
      entry.record = *outcome.record;
    }
    if (outcome.record_generation.has_value()) {
      entry.record_generation = *outcome.record_generation;
    }
    entry.accepted_at = state.generation;
    entry.message = outcome.message;
    record_idempotency(state, entry);
  }
  return outcome;
}

/// Returns the replayed outcome when the attempt was already committed, or an
/// empty optional when the request must be evaluated normally.
std::optional<Outcome> replay_previous_outcome(const RegistryState& state,
                                               const AuthorityClaim& claim,
                                               const RegistrationId& attempt,
                                               const RequestDigest& digest) {
  const IdempotencyEntry* previous = find_idempotency(state, claim.publisher, attempt);
  if (previous == nullptr) {
    return std::nullopt;
  }
  if (!(previous->digest == digest)) {
    Outcome outcome(OutcomeCode::ConflictingReplay,
                    "the attempt identifier was already used with different content");
    outcome.steps.push_back(ExplanationStep{"idempotency", "attempt", attempt.to_string(),
                                            "the recorded request digest differs from this request"});
    outcome.request_digest = digest;
    return outcome;
  }
  Outcome outcome(OutcomeCode::Idempotent, "the request was already committed; no new generation was produced");
  outcome.record = previous->record.is_null() ? std::nullopt : std::optional<CanonicalId>(previous->record);
  if (!previous->record_generation.is_zero()) {
    outcome.record_generation = previous->record_generation;
  }
  outcome.request_digest = digest;
  outcome.epoch = state.epoch;
  outcome.state_generation = state.generation;
  outcome.steps.push_back(ExplanationStep{"idempotency", "attempt", attempt.to_string(),
                                          "the recorded outcome was replayed without mutating state"});
  return outcome;
}

Outcome lifecycle_gate(const EntityRecord& record) {
  switch (record.lifecycle) {
    case Lifecycle::Tombstoned:
      return Outcome(OutcomeCode::Tombstoned, "the identity is tombstoned and permanently closed")
          .with_record(record.id)
          .with_generation(record.record_generation);
    case Lifecycle::Rejected:
      return Outcome(OutcomeCode::IllegalTransition, "the record was rejected and cannot be mutated")
          .with_record(record.id)
          .with_generation(record.record_generation);
    case Lifecycle::Retired:
      return Outcome(OutcomeCode::Retired, "the record is retired and cannot regain authority")
          .with_record(record.id)
          .with_generation(record.record_generation);
    case Lifecycle::Superseded:
      return Outcome(OutcomeCode::Superseded, "the record was superseded by a newer identity")
          .with_record(record.id)
          .with_generation(record.record_generation);
    case Lifecycle::Conflicted:
      return Outcome(OutcomeCode::ConflictUnresolved, "the record is conflicted and must be resolved explicitly")
          .with_record(record.id)
          .with_generation(record.record_generation);
    default:
      break;
  }
  return Outcome(OutcomeCode::Committed, "lifecycle accepts mutation");
}

Outcome generation_gate(const EntityRecord& record, const std::optional<RecordGeneration>& expected) {
  if (!expected.has_value()) {
    return Outcome(OutcomeCode::Committed, "no generation was expected");
  }
  if (*expected != record.record_generation) {
    return Outcome(OutcomeCode::StaleGeneration, "the expected record generation is no longer current")
        .with_record(record.id)
        .with_generation(record.record_generation)
        .field_step("generation", "record-generation", expected->to_string(),
                    "the record is at generation " + record.record_generation.to_string());
  }
  return Outcome(OutcomeCode::Committed, "generation matched");
}

Lifecycle target_lifecycle_for(AdmissionMode admission) {
  switch (admission) {
    case AdmissionMode::RequireCurrent:
      return Lifecycle::Current;
    case AdmissionMode::AllowCandidate:
      return Lifecycle::Candidate;
    case AdmissionMode::AllowObservation:
      return Lifecycle::Discovered;
  }
  return Lifecycle::Discovered;
}

/// Merges prepared metadata into a record, replacing duplicate keys, and
/// enforces every metadata bound on the result.
bool merge_metadata(EntityRecord& record, const std::vector<MetadataEntry>& additions, const RegistryLimits& limits) {
  for (const MetadataEntry& entry : additions) {
    const auto position = std::lower_bound(
        record.metadata.begin(), record.metadata.end(), entry.key,
        [](const MetadataEntry& item, const std::string& key) { return item.key < key; });
    if (position != record.metadata.end() && position->key == entry.key) {
      *position = entry;
    } else {
      record.metadata.insert(position, entry);
    }
  }
  if (record.metadata.size() > limits.max_metadata_entries) {
    return false;
  }
  std::size_t total = 0;
  for (const MetadataEntry& entry : record.metadata) {
    total += entry.key.size() + entry.value.size();
  }
  return total <= limits.max_metadata_bytes_per_entity;
}

} // namespace

// ---------------------------------------------------------------------------
// register_entity
// ---------------------------------------------------------------------------

Outcome Registry::register_entity(const RegisterEntityRequest& request) {
  RegistryState& state = impl_->state;
  PreparedRecord prepared;
  const Outcome preparation = prepare_registration(state, request, prepared);
  if (!preparation.committed()) {
    return preparation;
  }

  std::unique_lock<std::shared_mutex> guard(state.mutex);

  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = prepared.digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, prepared.digest);
      replayed.has_value()) {
    return *replayed;
  }

  Resolution resolution = resolve_identity(state, prepared);
  if (request.resolution == ReconcileResolution::ForceExisting) {
    if (!request.resolve_to.has_value()) {
      return Outcome(OutcomeCode::MalformedRequest, "force-existing requires the identity to attach to");
    }
    const auto entry = state.records.find(*request.resolve_to);
    if (entry == state.records.end()) {
      return Outcome(OutcomeCode::NotFound, "the identity named by force-existing does not exist")
          .with_record(*request.resolve_to);
    }
    const std::vector<IdentityFact> conflicts = contradictions(*entry->second, prepared.facts);
    if (!conflicts.empty()) {
      Outcome outcome(OutcomeCode::IdentityConflict,
                      "the observation contradicts the record it was explicitly attached to");
      outcome.match = MatchClass::Conflicting;
      outcome.with_record(entry->second->id);
      for (const IdentityFact& fact : conflicts) {
        outcome.steps.push_back(ExplanationStep{"conflict", render_fact(fact), fact.value,
                                                "the stored record disagrees with this value"});
      }
      return outcome;
    }
    resolution.match = MatchClass::ExactCanonical;
    resolution.target = entry->second;
    resolution.candidates = {entry->second->id};
    resolution.detail = "the caller explicitly attached the observation to an existing record";
  }

  if (request.resolution == ReconcileResolution::ForceNew &&
      (resolution.match == MatchClass::Ambiguous || resolution.match == MatchClass::ProbableInsufficient ||
       resolution.match == MatchClass::Conflicting)) {
    // The caller takes responsibility for the weaker evidence. The candidates are
    // kept so the explanation still names what the registry thought it saw, but
    // the request proceeds down the creation path.
    resolution.detail = "the caller forced a new record despite a " +
                        std::string(to_string(resolution.match)) + " match: " + resolution.detail;
    resolution.match = MatchClass::NoMatch;
    resolution.target = nullptr;
  }

  if (resolution.match == MatchClass::Ambiguous) {
    Outcome outcome(OutcomeCode::AmbiguousMatch,
                    "the observation matched more than one record at equal strength; no state was changed");
    outcome.match = resolution.match;
    for (const CanonicalId& id : resolution.candidates) {
      outcome.related.push_back(id);
    }
    outcome.steps.push_back(ExplanationStep{"reconcile", "candidates", std::to_string(resolution.candidates.size()),
                                            resolution.detail});
    outcome.request_digest = prepared.digest;
    return outcome;
  }

  if (resolution.match == MatchClass::ProbableInsufficient && request.resolution == ReconcileResolution::Auto) {
    Outcome outcome(OutcomeCode::ProbableMatch,
                    "the observation probably refers to an existing record but the evidence is not strong enough");
    outcome.match = resolution.match;
    if (resolution.target != nullptr) {
      outcome.with_record(resolution.target->id);
      outcome.with_generation(resolution.target->record_generation);
    }
    for (const CanonicalId& id : resolution.candidates) {
      outcome.related.push_back(id);
    }
    outcome.steps.push_back(ExplanationStep{"reconcile", "evidence", resolution.detail,
                                            "supply stronger evidence or resolve explicitly with force-new or force-existing"});
    outcome.request_digest = prepared.digest;
    return outcome;
  }

  if (resolution.match == MatchClass::Conflicting) {
    if (!request.record_conflict) {
      Outcome outcome = outcome_for_match(resolution, prepared);
      outcome.code = OutcomeCode::IdentityConflict;
      outcome.message = "the observation contradicts an existing record; no state was changed";
      outcome.request_digest = prepared.digest;
      return outcome;
    }
    if (resolution.target == nullptr && resolution.candidates.empty()) {
      return Outcome(OutcomeCode::IdentityConflict, "a conflict was detected but no record could be named");
    }
    const CanonicalId conflicted_id =
        resolution.target != nullptr ? resolution.target->id : resolution.candidates.front();
    const RecordPtr existing = state.records.find(conflicted_id)->second;
    if (existing->lifecycle == Lifecycle::Conflicted) {
      Outcome outcome = outcome_for_match(resolution, prepared);
      outcome.code = OutcomeCode::Idempotent;
      outcome.message = "the record is already conflicted; no new generation was produced";
      outcome.request_digest = prepared.digest;
      return outcome;
    }
    const Outcome gate = lifecycle_gate(*existing);
    if (!gate.committed()) {
      return gate;
    }
    EntityRecord next = *existing;
    if (!lifecycle_transition_allowed(next.lifecycle, Lifecycle::Conflicted)) {
      return Outcome(OutcomeCode::IllegalTransition, "the record cannot move to the conflicted state")
          .with_record(next.id);
    }
    next.lifecycle = Lifecycle::Conflicted;
    next.status_reason = "conflicting observation registered by " + request.authority.publisher.to_string();
    CommitContext context;
    context.reason = ReasonCode::ConflictRaised;
    context.attempt = request.attempt;
    context.publisher = request.authority.publisher;
    context.boot = request.authority.worker_boot;
    context.detail = "conflicting facts: " + describe_facts(resolution.conflicting_facts);
    if (!install_record(state, &existing, std::move(next), context)) {
      return outcome_generation_exhausted();
    }
    Outcome outcome(OutcomeCode::Committed, "the record was frozen as conflicted");
    outcome.match = MatchClass::Conflicting;
    outcome.with_record(conflicted_id);
    outcome.with_generation(state.records.find(conflicted_id)->second->record_generation);
    return finish_mutation(state, outcome, request.attempt, request.authority, prepared.digest);
  }

  if (resolution.target != nullptr) {
    const RecordPtr existing = resolution.target;
    const Outcome gate = lifecycle_gate(*existing);
    if (!gate.committed()) {
      return gate;
    }
    const Outcome generation = generation_gate(*existing, request.expected_generation);
    if (!generation.committed()) {
      return generation;
    }
    const std::vector<AliasKey> alias_conflicts = aliases_bound_elsewhere(state, prepared.aliases, existing->id);
    if (!alias_conflicts.empty()) {
      Outcome outcome(OutcomeCode::AliasConflict, "a requested alias is already bound to a different record");
      outcome.with_record(existing->id);
      for (const AliasKey& alias : alias_conflicts) {
        outcome.steps.push_back(ExplanationStep{"conflict", "alias", alias.to_string(),
                                                "the alias is held by " +
                                                    state.alias_index.find(alias)->second.to_string()});
      }
      outcome.request_digest = prepared.digest;
      return outcome;
    }

    EntityRecord next = *existing;
    const bool observation_only = request.admission == AdmissionMode::AllowObservation;
    if (!observation_only) {
      const Lifecycle from = next.lifecycle;
      if (request.admission == AdmissionMode::AllowCandidate && from == Lifecycle::Discovered) {
        if (!lifecycle_transition_allowed(from, Lifecycle::Candidate)) {
          return Outcome(OutcomeCode::IllegalTransition, "the observation cannot be promoted to a candidate")
              .with_record(next.id);
        }
        next.lifecycle = Lifecycle::Candidate;
        next.status_reason.clear();
      } else if (request.admission == AdmissionMode::RequireCurrent && from != Lifecycle::Current) {
        if (!lifecycle_transition_allowed(from, Lifecycle::Current)) {
          return Outcome(OutcomeCode::IllegalTransition,
                         "the record cannot be promoted to current from its present lifecycle")
              .with_record(next.id)
              .field_step("lifecycle", "lifecycle", std::string(to_string(from)),
                          "no legal transition to current exists from this state");
        }
        next.lifecycle = Lifecycle::Current;
        next.status_reason.clear();
      }
      if (!request.friendly_name.empty()) {
        next.friendly_name = prepared.friendly_name;
      }
      if (request.scope.fabric.has_value()) {
        next.fabric = request.scope.fabric;
      }
      if (request.scope.site.has_value()) {
        next.site = request.scope.site;
      }
      if (request.scope.control_domain.has_value()) {
        next.control_domain = request.scope.control_domain;
      }
      if (request.scope.parent_device.has_value()) {
        next.parent_device = request.scope.parent_device;
      }
      merge_facts(next.facts, prepared.facts);
      next.hardware_identity = hardware_identity_or_null(next.facts);
      if (!merge_metadata(next, prepared.metadata, state.limits)) {
        return Outcome(OutcomeCode::ResourceLimit, "the record would hold more metadata than the configured bound")
            .with_record(next.id);
      }
      const std::optional<EvidenceGeneration> previous_evidence =
          next.evidence.generation.is_zero() ? std::nullopt : std::optional<EvidenceGeneration>(next.evidence.generation);
      fill_evidence(next.evidence, prepared.evidence_class, prepared.provenance, state, request.authority,
                    previous_evidence);
      next.evidence_generation = next.evidence.generation;
    }
    merge_aliases(next.aliases, prepared.aliases);
    if (next.aliases.size() > state.limits.max_aliases_per_entity) {
      return Outcome(OutcomeCode::ResourceLimit, "the record would hold more aliases than the configured bound")
          .with_record(next.id);
    }
    CommitContext context;
    context.reason = observation_only ? ReasonCode::EvidenceUpdate : ReasonCode::Registration;
    context.attempt = request.attempt;
    context.publisher = request.authority.publisher;
    context.boot = request.authority.worker_boot;
    context.detail = resolution.detail;
    if (!install_record(state, &existing, std::move(next), context)) {
      return outcome_generation_exhausted();
    }
    Outcome outcome(OutcomeCode::Committed, "the record was updated");
    outcome.match = resolution.match;
    outcome.with_record(existing->id);
    outcome.with_generation(state.records.find(existing->id)->second->record_generation);
    outcome.evidence_generation = state.records.find(existing->id)->second->evidence.generation;
    outcome.steps.push_back(ExplanationStep{"reconcile", "match", std::string(to_string(resolution.match)),
                                            resolution.detail});
    return finish_mutation(state, outcome, request.attempt, request.authority, prepared.digest);
  }

  // Creation path.
  if (state.records.find(prepared.canonical_id) != state.records.end()) {
    // Unreachable through the resolution above, but the creation path must never
    // be able to overwrite a record and reset its generation.
    Outcome outcome(OutcomeCode::DuplicateIdentity,
                    "the canonical identity already exists; creating it again would renumber an existing record");
    outcome.with_record(prepared.canonical_id);
    outcome.request_digest = prepared.digest;
    return outcome;
  }
  if (!prepared.hardware_identity.is_null()) {
    const auto entry = state.hardware_index.find(prepared.hardware_identity);
    if (entry != state.hardware_index.end()) {
      for (const CanonicalId& id : entry->second) {
        const RecordPtr& other = state.records.find(id)->second;
        if (other->lifecycle == Lifecycle::Retired || other->lifecycle == Lifecycle::Tombstoned ||
            other->lifecycle == Lifecycle::Superseded) {
          continue;
        }
        Outcome outcome(OutcomeCode::DuplicateIdentity,
                        "another live record already carries this stable hardware identity");
        outcome.match = MatchClass::Conflicting;
        outcome.with_record(other->id);
        outcome.with_generation(other->record_generation);
        outcome.steps.push_back(ExplanationStep{"conflict", "hardware-identity",
                                                prepared.hardware_identity.to_string(),
                                                "a second live record for the same physical identity would be a duplicate"});
        outcome.request_digest = prepared.digest;
        return outcome;
      }
    }
  }
  const std::vector<AliasKey> alias_conflicts =
      aliases_bound_elsewhere(state, prepared.aliases, prepared.canonical_id);
  if (!alias_conflicts.empty()) {
    Outcome outcome(OutcomeCode::AliasConflict, "a requested alias is already bound to a different record");
    for (const AliasKey& alias : alias_conflicts) {
      outcome.steps.push_back(ExplanationStep{"conflict", "alias", alias.to_string(),
                                              "the alias is held by " +
                                                  state.alias_index.find(alias)->second.to_string()});
    }
    outcome.request_digest = prepared.digest;
    return outcome;
  }
  if (state.records.size() >= state.limits.max_entities) {
    return Outcome(OutcomeCode::ResourceLimit, "the registry holds the maximum number of entities");
  }
  if (state.alias_index.size() + prepared.aliases.size() > state.limits.max_alias_entries) {
    return Outcome(OutcomeCode::ResourceLimit, "the registry holds the maximum number of aliases");
  }

  EntityRecord next;
  next.id = prepared.canonical_id;
  next.entity_class = prepared.entity_class;
  next.lifecycle = target_lifecycle_for(request.admission);
  next.fingerprint = prepared.explicit_id
                         ? FingerprintDigest{}
                         : compute_identity_fingerprint(prepared.entity_class, prepared.derivation_namespace,
                                                        prepared.facts);
  next.hardware_identity = prepared.hardware_identity;
  next.derivation_namespace = prepared.derivation_namespace;
  next.friendly_name = prepared.friendly_name;
  next.parent_device = request.scope.parent_device;
  next.fabric = request.scope.fabric;
  next.site = request.scope.site;
  next.control_domain = request.scope.control_domain;
  next.facts = prepared.facts;
  next.aliases = prepared.aliases;
  next.metadata = prepared.metadata;
  fill_evidence(next.evidence, prepared.evidence_class, prepared.provenance, state, request.authority, std::nullopt);
  next.evidence_generation = next.evidence.generation;
  next.created_by = request.authority.publisher;
  next.created_boot = request.authority.worker_boot;
  next.created_epoch = state.epoch;

  CommitContext context;
  context.reason = ReasonCode::Registration;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = "registered as " + std::string(to_string(next.lifecycle));
  const RecordPtr previous;
  if (!install_record(state, &previous, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  const RecordPtr stored = state.records.find(prepared.canonical_id)->second;
  Outcome outcome(OutcomeCode::Committed, "a new canonical record was created");
  outcome.match = resolution.match;
  outcome.with_record(stored->id);
  outcome.with_generation(stored->record_generation);
  outcome.evidence_generation = stored->evidence.generation;
  outcome.steps.push_back(ExplanationStep{"reconcile", "match", std::string(to_string(resolution.match)),
                                          resolution.detail});
  return finish_mutation(state, outcome, request.attempt, request.authority, prepared.digest);
}

namespace {

/// True when the registry has room for \`count\` more generation transitions.
bool has_generation_room(const RegistryState& state, std::uint64_t count) {
  return state.generation.value() <= UINT64_MAX - count;
}

Outcome lookup_target(const RegistryState& state, const CanonicalId& id, RecordPtr& out) {
  if (id.is_null()) {
    return Outcome(OutcomeCode::MalformedRequest, "the request does not name a target record");
  }
  const auto entry = state.records.find(id);
  if (entry == state.records.end()) {
    Outcome outcome(OutcomeCode::NotFound, "the addressed record does not exist");
    outcome.with_record(id);
    return outcome;
  }
  out = entry->second;
  return Outcome(OutcomeCode::Committed, "target found");
}

Outcome lifecycle_gate_mutable(const EntityRecord& record) {
  return lifecycle_gate(record);
}

/// Detaching an alias is an administrative cleanup action, so it remains
/// available on retired and superseded records. It is refused on tombstoned and
/// rejected records, whose aliases are permanently reserved.
Outcome lifecycle_gate_alias_release(const EntityRecord& record) {
  switch (record.lifecycle) {
    case Lifecycle::Tombstoned:
      return Outcome(OutcomeCode::Tombstoned, "the identity is tombstoned; its aliases are permanently reserved")
          .with_record(record.id)
          .with_generation(record.record_generation);
    case Lifecycle::Rejected:
      return Outcome(OutcomeCode::IllegalTransition, "the record was rejected and holds no releasable alias")
          .with_record(record.id);
    default:
      break;
  }
  return Outcome(OutcomeCode::Committed, "lifecycle accepts alias release");
}

Outcome build_single_alias_key(const RegistryState& state,
                               const EntityRecord& record,
                               const AliasInput& input,
                               AliasKey& out) {
  const AliasNameResult name = canonicalize_alias(input.alias_namespace, input.value, state.limits.max_string_bytes);
  if (!name) {
    return Outcome(outcome_for_alias_issue(name.issue), "the alias cannot be used")
        .field_step("validate", "alias", std::string(to_string(name.issue)),
                    "the alias value or its required scope is missing or malformed");
  }
  AliasScopeInput scope;
  scope.fabric = record.fabric;
  scope.site = record.site;
  scope.entity_class = record.entity_class;
  scope.parent_device = record.parent_device;
  const AliasKeyResult key = make_alias_key(*name.name, scope);
  if (!key) {
    return Outcome(outcome_for_alias_issue(key.issue), "the alias cannot be qualified")
        .field_step("validate", "alias", std::string(to_string(key.issue)),
                    "the record does not carry the scope this alias namespace requires");
  }
  out = *key.key;
  return Outcome(OutcomeCode::Committed, "alias accepted");
}

Outcome prepare_mutation_attempt(const RegistryState& state,
                                 const RegistrationId& attempt) {
  if (attempt.is_null()) {
    return Outcome(OutcomeCode::MalformedRequest,
                   "the attempt identifier must be non-null; it is the idempotency key for this mutation");
  }
  (void)state;
  return Outcome(OutcomeCode::Committed, "attempt accepted");
}

Outcome prepare_evidence_payload(const RegistryState& state,
                                 const std::vector<IdentityFact>& facts,
                                 const Provenance& provenance,
                                 EvidenceClass evidence_class,
                                 std::vector<IdentityFact>& out_facts,
                                 Provenance& out_provenance) {
  const IdentityIssue issue =
      normalize_fact_set(facts, state.limits.max_facts_per_entity, state.limits.max_string_bytes, out_facts);
  if (issue != IdentityIssue::None) {
    return Outcome(OutcomeCode::InvalidEvidence, "the request carries a fact set that cannot be used")
        .field_step("validate", "facts", std::string(to_string(issue)),
                    "one of the supplied identity facts is invalid, duplicated or contradictory");
  }
  const ValidationResult result = validate_provenance(provenance, state.limits.max_string_bytes);
  if (!result) {
    return Outcome(OutcomeCode::InvalidEvidence, "the request provenance is not usable")
        .field_step("validate", "provenance", result.message, "every record must carry explicit provenance");
  }
  if (evidence_class == EvidenceClass::Unspecified) {
    return Outcome(OutcomeCode::InvalidEvidence,
                   "the request does not say whether its evidence is process-bound or a durable authority act");
  }
  out_provenance = provenance;
  return Outcome(OutcomeCode::Committed, "evidence accepted");
}

} // namespace

// ---------------------------------------------------------------------------
// update_evidence
// ---------------------------------------------------------------------------

Outcome Registry::update_evidence(const UpdateEvidenceRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_update_evidence_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::vector<IdentityFact> facts;
  Provenance provenance;
  check = prepare_evidence_payload(state, request.facts, request.provenance, request.evidence_class, facts, provenance);
  if (!check.committed()) {
    return check;
  }

  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  check = lifecycle_gate_mutable(*target);
  if (!check.committed()) {
    return check;
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }

  EntityRecord next = *target;
  if (request.merge_facts) {
    merge_facts(next.facts, facts);
  } else {
    next.facts = facts;
  }
  const StableHardwareIdentity hardware = hardware_identity_or_null(next.facts);
  if (!hardware.is_null()) {
    const auto entry = state.hardware_index.find(hardware);
    if (entry != state.hardware_index.end()) {
      for (const CanonicalId& id : entry->second) {
        if (id == next.id) {
          continue;
        }
        const RecordPtr& other = state.records.find(id)->second;
        if (other->lifecycle == Lifecycle::Retired || other->lifecycle == Lifecycle::Tombstoned ||
            other->lifecycle == Lifecycle::Superseded) {
          continue;
        }
        Outcome outcome(OutcomeCode::DuplicateIdentity,
                        "the resulting fact set would give two live records the same stable hardware identity");
        outcome.with_record(other->id);
        outcome.request_digest = digest;
        return outcome;
      }
    }
  }
  next.hardware_identity = hardware;
  const std::optional<EvidenceGeneration> previous_evidence =
      next.evidence.generation.is_zero() ? std::nullopt : std::optional<EvidenceGeneration>(next.evidence.generation);
  fill_evidence(next.evidence, request.evidence_class, provenance, state, request.authority, previous_evidence);
  next.evidence_generation = next.evidence.generation;

  CommitContext context;
  context.reason = ReasonCode::EvidenceUpdate;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = request.merge_facts ? "evidence extended" : "evidence replaced";
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  const RecordPtr stored = state.records.find(request.target)->second;
  Outcome outcome(OutcomeCode::Committed, "evidence updated");
  outcome.with_record(stored->id);
  outcome.with_generation(stored->record_generation);
  outcome.evidence_generation = stored->evidence.generation;
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

// ---------------------------------------------------------------------------
// attach_alias / detach_alias
// ---------------------------------------------------------------------------

Outcome Registry::attach_alias(const AliasMutationRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_alias_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  check = lifecycle_gate_mutable(*target);
  if (!check.committed()) {
    return check;
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  AliasKey key;
  check = build_single_alias_key(state, *target, request.alias, key);
  if (!check.committed()) {
    return check;
  }
  if (std::find(target->aliases.begin(), target->aliases.end(), key) != target->aliases.end()) {
    Outcome outcome(OutcomeCode::Idempotent, "the record already holds this alias; no new generation was produced");
    outcome.with_record(target->id);
    outcome.with_generation(target->record_generation);
    outcome.request_digest = digest;
    outcome.epoch = state.epoch;
    outcome.state_generation = state.generation;
    return outcome;
  }
  if (alias_is_unique(key.alias_namespace)) {
    const auto holder = state.alias_index.find(key);
    if (holder != state.alias_index.end() && holder->second != target->id) {
      Outcome outcome(OutcomeCode::AliasConflict, "the alias is already bound to a different record");
      outcome.with_record(holder->second);
      outcome.steps.push_back(ExplanationStep{"conflict", "alias", key.to_string(),
                                              "the alias is held by " + holder->second.to_string()});
      outcome.request_digest = digest;
      return outcome;
    }
  }
  if (target->aliases.size() + 1 > state.limits.max_aliases_per_entity) {
    return Outcome(OutcomeCode::ResourceLimit, "the record would hold more aliases than the configured bound")
        .with_record(target->id);
  }
  if (alias_is_unique(key.alias_namespace) && state.alias_index.size() + 1 > state.limits.max_alias_entries) {
    return Outcome(OutcomeCode::ResourceLimit, "the registry holds the maximum number of aliases");
  }

  EntityRecord next = *target;
  next.aliases.push_back(key);
  std::sort(next.aliases.begin(), next.aliases.end());
  CommitContext context;
  context.reason = ReasonCode::AliasAttach;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = "alias attached: " + key.to_string();
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  const RecordPtr stored = state.records.find(request.target)->second;
  Outcome outcome(OutcomeCode::Committed, "alias attached");
  outcome.with_record(stored->id);
  outcome.with_generation(stored->record_generation);
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

Outcome Registry::detach_alias(const AliasMutationRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_alias_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  check = lifecycle_gate_alias_release(*target);
  if (!check.committed()) {
    return check;
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  AliasKey key;
  check = build_single_alias_key(state, *target, request.alias, key);
  if (!check.committed()) {
    return check;
  }
  const auto position = std::find(target->aliases.begin(), target->aliases.end(), key);
  if (position == target->aliases.end()) {
    Outcome outcome(OutcomeCode::NotFound, "the record does not hold this alias; nothing was changed");
    outcome.with_record(target->id);
    outcome.with_generation(target->record_generation);
    outcome.request_digest = digest;
    return outcome;
  }

  EntityRecord next = *target;
  next.aliases.erase(next.aliases.begin() + (position - target->aliases.begin()));
  CommitContext context;
  context.reason = ReasonCode::AliasDetach;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = "alias detached: " + key.to_string();
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  const RecordPtr stored = state.records.find(request.target)->second;
  Outcome outcome(OutcomeCode::Committed, "alias detached");
  outcome.with_record(stored->id);
  outcome.with_generation(stored->record_generation);
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

// ---------------------------------------------------------------------------
// supersede / retire / tombstone
// ---------------------------------------------------------------------------

Outcome Registry::supersede_entity(const SupersedeEntityRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_supersede_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  if (target->lifecycle == Lifecycle::Superseded) {
    Outcome outcome(OutcomeCode::Idempotent, "the record is already superseded");
    outcome.with_record(target->id);
    outcome.with_generation(target->record_generation);
    outcome.request_digest = digest;
    return outcome;
  }
  if (target->lifecycle == Lifecycle::Tombstoned) {
    return Outcome(OutcomeCode::Tombstoned, "the identity is tombstoned").with_record(target->id);
  }
  if (target->lifecycle == Lifecycle::Rejected) {
    return Outcome(OutcomeCode::IllegalTransition, "the record was rejected").with_record(target->id);
  }
  if (target->lifecycle != Lifecycle::Current && target->lifecycle != Lifecycle::RevalidationRequired) {
    return Outcome(OutcomeCode::IllegalTransition,
                   "only a current or revalidation-required record can be superseded")
        .with_record(target->id)
        .field_step("lifecycle", "lifecycle", std::string(to_string(target->lifecycle)),
                    "the record does not hold authority that could be superseded");
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  if (!has_generation_room(state, request.successor.has_value() ? 2u : 1u)) {
    return outcome_generation_exhausted();
  }

  RecordPtr successor;
  if (request.successor.has_value()) {
    if (request.successor->is_null()) {
      return Outcome(OutcomeCode::MalformedRequest, "the named successor identity is null");
    }
    if (*request.successor == target->id) {
      return Outcome(OutcomeCode::MalformedRequest, "a record cannot supersede itself").with_record(target->id);
    }
    check = lookup_target(state, *request.successor, successor);
    if (!check.committed()) {
      return check;
    }
    if (successor->lifecycle == Lifecycle::Tombstoned || successor->lifecycle == Lifecycle::Rejected) {
      return Outcome(OutcomeCode::IllegalTransition, "the named successor cannot receive authority")
          .with_record(successor->id);
    }
    if (successor->entity_class != target->entity_class) {
      return Outcome(OutcomeCode::MalformedRequest, "a successor must have the same entity class")
          .with_record(successor->id);
    }
  }

  if (successor != nullptr) {
    EntityRecord replacement = *successor;
    std::vector<AliasKey> moved;
    for (const AliasKey& alias : target->aliases) {
      if (std::find(replacement.aliases.begin(), replacement.aliases.end(), alias) != replacement.aliases.end()) {
        continue;
      }
      if (alias_is_unique(alias.alias_namespace)) {
        const auto holder = state.alias_index.find(alias);
        if (holder != state.alias_index.end() && holder->second != target->id) {
          continue;
        }
      }
      moved.push_back(alias);
    }
    if (replacement.aliases.size() + moved.size() > state.limits.max_aliases_per_entity) {
      return Outcome(OutcomeCode::ResourceLimit,
                     "transferring the superseded record's aliases would exceed the configured alias bound")
          .with_record(successor->id);
    }
    for (const AliasKey& alias : moved) {
      replacement.aliases.push_back(alias);
    }
    std::sort(replacement.aliases.begin(), replacement.aliases.end());
    replacement.supersedes = target->id;
    CommitContext successor_context;
    successor_context.reason = ReasonCode::Supersede;
    successor_context.attempt = request.attempt;
    successor_context.publisher = request.authority.publisher;
    successor_context.boot = request.authority.worker_boot;
    successor_context.detail = "became the successor of " + target->id.to_string();
    if (!install_record(state, &successor, std::move(replacement), successor_context)) {
      return outcome_generation_exhausted();
    }
  }

  const RecordPtr refreshed_target = state.records.find(request.target)->second;
  EntityRecord retired = *refreshed_target;
  retired.lifecycle = Lifecycle::Superseded;
  retired.superseded_by = request.successor;
  retired.status_reason = request.reason.empty() ? "superseded" : request.reason;
  if (successor != nullptr) {
    // Compare against the record as it was actually installed: the pre-commit
    // snapshot does not yet carry the transferred aliases.
    const RecordPtr installed_successor = state.records.find(successor->id)->second;
    std::vector<AliasKey> remaining;
    for (const AliasKey& alias : retired.aliases) {
      if (std::find(installed_successor->aliases.begin(), installed_successor->aliases.end(), alias) ==
          installed_successor->aliases.end()) {
        remaining.push_back(alias);
      }
    }
    retired.aliases = std::move(remaining);
  }
  CommitContext context;
  context.reason = ReasonCode::Supersede;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = retired.status_reason;
  if (!install_record(state, &refreshed_target, std::move(retired), context)) {
    return outcome_generation_exhausted();
  }
  Outcome outcome(OutcomeCode::Committed, "the record was superseded");
  outcome.with_record(request.target);
  outcome.with_generation(state.records.find(request.target)->second->record_generation);
  outcome.match = MatchClass::ExactCanonical;
  if (successor != nullptr) {
    outcome.related.push_back(successor->id);
    outcome.steps.push_back(ExplanationStep{"supersede", "successor", successor->id.to_string(),
                                            "aliases were transferred to the successor"});
  }
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

Outcome Registry::retire_entity(const RetireEntityRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_retire_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  if (target->lifecycle == Lifecycle::Retired) {
    Outcome outcome(OutcomeCode::Idempotent, "the record is already retired");
    outcome.with_record(target->id);
    outcome.with_generation(target->record_generation);
    outcome.request_digest = digest;
    return outcome;
  }
  if (target->lifecycle == Lifecycle::Tombstoned) {
    return Outcome(OutcomeCode::Tombstoned, "the identity is tombstoned and can only be tombstoned further")
        .with_record(target->id);
  }
  if (target->lifecycle == Lifecycle::Rejected) {
    return Outcome(OutcomeCode::IllegalTransition, "the record was rejected").with_record(target->id);
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  if (!lifecycle_transition_allowed(target->lifecycle, Lifecycle::Retired)) {
    return Outcome(OutcomeCode::IllegalTransition, "the record cannot be retired from its present lifecycle")
        .with_record(target->id)
        .field_step("lifecycle", "lifecycle", std::string(to_string(target->lifecycle)),
                    "no legal transition to retired exists from this state");
  }
  EntityRecord next = *target;
  next.lifecycle = Lifecycle::Retired;
  next.status_reason = request.reason.empty() ? "retired" : request.reason;
  CommitContext context;
  context.reason = ReasonCode::Retire;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = next.status_reason;
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  Outcome outcome(OutcomeCode::Committed, "the record was retired");
  outcome.with_record(request.target);
  outcome.with_generation(state.records.find(request.target)->second->record_generation);
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

Outcome Registry::tombstone_entity(const TombstoneEntityRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_tombstone_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  if (target->lifecycle == Lifecycle::Tombstoned) {
    Outcome outcome(OutcomeCode::Idempotent, "the identity is already tombstoned");
    outcome.with_record(target->id);
    outcome.with_generation(target->record_generation);
    outcome.request_digest = digest;
    return outcome;
  }
  if (target->lifecycle == Lifecycle::Rejected) {
    return Outcome(OutcomeCode::IllegalTransition, "a rejected record cannot be tombstoned").with_record(target->id);
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  if (!lifecycle_transition_allowed(target->lifecycle, Lifecycle::Tombstoned)) {
    return Outcome(OutcomeCode::IllegalTransition, "the record cannot be tombstoned from its present lifecycle")
        .with_record(target->id)
        .field_step("lifecycle", "lifecycle", std::string(to_string(target->lifecycle)),
                    "no legal transition to tombstoned exists from this state");
  }
  EntityRecord next = *target;
  next.lifecycle = Lifecycle::Tombstoned;
  next.evidence.valid = false;
  next.status_reason = request.reason.empty() ? "tombstoned" : request.reason;
  CommitContext context;
  context.reason = ReasonCode::Tombstone;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = next.status_reason;
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  Outcome outcome(OutcomeCode::Committed, "the identity was tombstoned");
  outcome.with_record(request.target);
  outcome.with_generation(state.records.find(request.target)->second->record_generation);
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

// ---------------------------------------------------------------------------
// revalidate / resolve_conflict
// ---------------------------------------------------------------------------

Outcome Registry::revalidate_entity(const RevalidateEntityRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_revalidate_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::vector<IdentityFact> facts;
  Provenance provenance;
  check = prepare_evidence_payload(state, request.facts, request.provenance, request.evidence_class, facts, provenance);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  if (target->lifecycle != Lifecycle::RevalidationRequired && target->lifecycle != Lifecycle::Current) {
    return Outcome(OutcomeCode::IllegalTransition,
                   "only a current or revalidation-required record can be revalidated")
        .with_record(target->id)
        .field_step("lifecycle", "lifecycle", std::string(to_string(target->lifecycle)),
                    "the record is in a state that cannot be revalidated");
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  const StableHardwareIdentity candidate_hardware =
      hardware_identity_or_null(request.merge_facts ? [&] {
        std::vector<IdentityFact> merged = target->facts;
        merge_facts(merged, facts);
        return merged;
      }() : facts);
  if (!candidate_hardware.is_null()) {
    const auto entry = state.hardware_index.find(candidate_hardware);
    if (entry != state.hardware_index.end()) {
      for (const CanonicalId& id : entry->second) {
        if (id == target->id) {
          continue;
        }
        const RecordPtr& other = state.records.find(id)->second;
        if (other->lifecycle == Lifecycle::Retired || other->lifecycle == Lifecycle::Tombstoned ||
            other->lifecycle == Lifecycle::Superseded) {
          continue;
        }
        Outcome outcome(OutcomeCode::DuplicateIdentity,
                        "revalidation would give two live records the same stable hardware identity");
        outcome.with_record(other->id);
        outcome.request_digest = digest;
        return outcome;
      }
    }
  }

  EntityRecord next = *target;
  if (request.merge_facts) {
    merge_facts(next.facts, facts);
  } else {
    next.facts = facts;
  }
  next.hardware_identity = hardware_identity_or_null(next.facts);
  const std::optional<EvidenceGeneration> previous_evidence =
      next.evidence.generation.is_zero() ? std::nullopt : std::optional<EvidenceGeneration>(next.evidence.generation);
  fill_evidence(next.evidence, request.evidence_class, provenance, state, request.authority, previous_evidence);
  next.evidence_generation = next.evidence.generation;
  next.lifecycle = Lifecycle::Current;
  next.status_reason.clear();

  CommitContext context;
  context.reason = ReasonCode::Revalidation;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = "evidence revalidated";
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  const RecordPtr stored = state.records.find(request.target)->second;
  Outcome outcome(OutcomeCode::Committed, "the record holds current authority again");
  outcome.with_record(stored->id);
  outcome.with_generation(stored->record_generation);
  outcome.evidence_generation = stored->evidence.generation;
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

Outcome Registry::resolve_conflict(const ResolveConflictRequest& request) {
  RegistryState& state = impl_->state;
  const RequestDigest digest = digest_resolve_conflict_request(request);
  Outcome check = prepare_mutation_attempt(state, request.attempt);
  if (!check.committed()) {
    return check;
  }
  std::unique_lock<std::shared_mutex> guard(state.mutex);
  const Outcome authority = check_authority(state, request.authority, request.attempt);
  if (!authority.committed()) {
    Outcome outcome = authority;
    outcome.request_digest = digest;
    return outcome;
  }
  if (const std::optional<Outcome> replayed =
          replay_previous_outcome(state, request.authority, request.attempt, digest);
      replayed.has_value()) {
    return *replayed;
  }
  RecordPtr target;
  check = lookup_target(state, request.target, target);
  if (!check.committed()) {
    return check;
  }
  if (target->lifecycle != Lifecycle::Conflicted) {
    return Outcome(OutcomeCode::IllegalTransition, "the record is not conflicted and needs no resolution")
        .with_record(target->id)
        .field_step("lifecycle", "lifecycle", std::string(to_string(target->lifecycle)),
                    "only a conflicted record can be resolved");
  }
  check = generation_gate(*target, request.expected_generation);
  if (!check.committed()) {
    return check;
  }
  Lifecycle destination = Lifecycle::Current;
  ReasonCode reason = ReasonCode::ConflictResolved;
  switch (request.resolution) {
    case ConflictResolution::KeepCurrent:
      destination = Lifecycle::Current;
      break;
    case ConflictResolution::Retire:
      destination = Lifecycle::Retired;
      reason = ReasonCode::Retire;
      break;
    case ConflictResolution::Reject:
      destination = Lifecycle::Rejected;
      break;
  }
  if (!lifecycle_transition_allowed(Lifecycle::Conflicted, destination)) {
    return Outcome(OutcomeCode::IllegalTransition, "the requested resolution is not a legal transition")
        .with_record(target->id);
  }
  EntityRecord next = *target;
  next.lifecycle = destination;
  next.status_reason = request.reason.empty() ? "conflict resolved" : request.reason;
  if (destination != Lifecycle::Current) {
    next.evidence.valid = false;
  }
  CommitContext context;
  context.reason = reason;
  context.attempt = request.attempt;
  context.publisher = request.authority.publisher;
  context.boot = request.authority.worker_boot;
  context.detail = next.status_reason;
  if (!install_record(state, &target, std::move(next), context)) {
    return outcome_generation_exhausted();
  }
  Outcome outcome(OutcomeCode::Committed, "the conflict was resolved");
  outcome.with_record(request.target);
  outcome.with_generation(state.records.find(request.target)->second->record_generation);
  outcome.match = MatchClass::ExactCanonical;
  return finish_mutation(state, outcome, request.attempt, request.authority, digest);
}

// ---------------------------------------------------------------------------
// reconcile_observation
// ---------------------------------------------------------------------------

ReconcileResult Registry::reconcile_observation(const ReconcileObservationRequest& request) {
  RegistryState& state = impl_->state;
  ReconcileResult result;
  if (request.attempt.is_null()) {
    result.outcome = Outcome(OutcomeCode::MalformedRequest,
                             "a reconciliation attempt must carry a non-null attempt identifier");
    return result;
  }
  if (!is_valid_entity_class(request.entity_class)) {
    result.outcome = Outcome(OutcomeCode::MalformedRequest, "the request names an entity class that does not exist");
    return result;
  }
  PreparedRecord prepared;
  prepared.entity_class = request.entity_class;
  const IdentityIssue fact_issue =
      normalize_fact_set(request.facts, state.limits.max_facts_per_entity, state.limits.max_string_bytes, prepared.facts);
  if (fact_issue != IdentityIssue::None) {
    result.outcome = Outcome(OutcomeCode::InvalidEvidence, "the observation carries a fact set that cannot be used")
                         .field_step("validate", "facts", std::string(to_string(fact_issue)),
                                     "one of the supplied identity facts is invalid, duplicated or contradictory");
    return result;
  }
  const ValidationResult provenance_result = validate_provenance(request.provenance, state.limits.max_string_bytes);
  if (!provenance_result) {
    result.outcome = Outcome(OutcomeCode::InvalidEvidence, "the observation provenance is not usable")
                         .field_step("validate", "provenance", provenance_result.message,
                                     "every observation must carry explicit provenance");
    return result;
  }
  const Outcome scope_result = prepare_scope(request.scope, request.entity_class);
  if (!scope_result.committed()) {
    result.outcome = scope_result;
    return result;
  }
  const AliasIssue alias_issue =
      build_alias_keys(request.aliases, scope_input_for(request.scope, request.entity_class),
                       state.limits.max_string_bytes, prepared.aliases);
  if (alias_issue != AliasIssue::None) {
    result.outcome = Outcome(outcome_for_alias_issue(alias_issue), "the observation carries an alias that cannot be used")
                         .field_step("validate", "alias", std::string(to_string(alias_issue)),
                                     "the alias value or its required scope is missing or malformed");
    return result;
  }
  prepared.provenance = request.provenance;
  prepared.derivation_namespace = "fabric-registry/reconcile";
  prepared.canonical_id = derive_canonical_id(request.entity_class, prepared.derivation_namespace, prepared.facts,
                                              state.limits.max_string_bytes)
                              .id.value_or(CanonicalId{});
  prepared.digest = digest_reconcile_request(request);

  std::shared_lock<std::shared_mutex> guard(state.mutex);
  if (request.authority.is_complete()) {
    const Outcome authority = check_authority(state, request.authority, request.attempt);
    if (!authority.committed()) {
      result.outcome = authority;
      return result;
    }
  }
  Resolution resolution = resolve_identity(state, prepared);
  if (request.resolution == ReconcileResolution::ForceExisting) {
    if (!request.resolve_to.has_value()) {
      result.outcome = Outcome(OutcomeCode::MalformedRequest, "force-existing requires the identity to attach to");
      return result;
    }
    const auto entry = state.records.find(*request.resolve_to);
    if (entry == state.records.end()) {
      result.outcome = Outcome(OutcomeCode::NotFound, "the identity named by force-existing does not exist")
                           .with_record(*request.resolve_to);
      return result;
    }
    resolution.match = MatchClass::ExactCanonical;
    resolution.target = entry->second;
    resolution.candidates = {entry->second->id};
    resolution.detail = "the caller explicitly attached the observation to an existing record";
  }

  result.detail.match = resolution.match;
  result.detail.matched = resolution.target != nullptr ? std::optional<CanonicalId>(resolution.target->id) : std::nullopt;
  result.detail.candidates = resolution.candidates;
  result.detail.conflicting_facts = resolution.conflicting_facts;
  for (const AliasKey& alias : prepared.aliases) {
    if (!alias_is_unique(alias.alias_namespace)) {
      continue;
    }
    const auto holder = state.alias_index.find(alias);
    if (holder != state.alias_index.end() &&
        (resolution.target == nullptr || holder->second != resolution.target->id)) {
      result.detail.conflicting_aliases.push_back(alias);
    }
  }
  result.detail.observation_fingerprint =
      compute_identity_fingerprint(request.entity_class, prepared.derivation_namespace, prepared.facts);

  OutcomeCode code = OutcomeCode::Committed;
  switch (resolution.match) {
    case MatchClass::NoMatch:
      code = OutcomeCode::NotFound;
      break;
    case MatchClass::ExactCanonical:
    case MatchClass::ProvenAlias:
    case MatchClass::StableHardware:
      code = OutcomeCode::Committed;
      break;
    case MatchClass::ProbableInsufficient:
      code = OutcomeCode::ProbableMatch;
      break;
    case MatchClass::Conflicting:
      code = OutcomeCode::IdentityConflict;
      break;
    case MatchClass::Ambiguous:
      code = OutcomeCode::AmbiguousMatch;
      break;
  }
  result.outcome = Outcome(code, resolution.detail);
  result.outcome.match = resolution.match;
  result.outcome.request_digest = prepared.digest;
  result.outcome.epoch = state.epoch;
  result.outcome.state_generation = state.generation;
  if (resolution.target != nullptr) {
    result.outcome.with_record(resolution.target->id);
    result.outcome.with_generation(resolution.target->record_generation);
  }
  for (const CanonicalId& id : resolution.candidates) {
    result.outcome.related.push_back(id);
  }
  for (const IdentityFact& fact : resolution.conflicting_facts) {
    result.outcome.steps.push_back(ExplanationStep{"conflict", render_fact(fact), fact.value,
                                                   "the stored record disagrees with this value"});
  }
  for (const AliasKey& alias : result.detail.conflicting_aliases) {
    result.outcome.steps.push_back(ExplanationStep{"conflict", "alias", alias.to_string(),
                                                   "the alias is held by " +
                                                       state.alias_index.find(alias)->second.to_string()});
  }
  return result;
}

} // namespace fabric_registry

