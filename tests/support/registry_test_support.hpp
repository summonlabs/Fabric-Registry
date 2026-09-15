// Fabric Registry — shared helpers for the registry test translation units.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FABRIC_REGISTRY_TESTS_SUPPORT_REGISTRY_TEST_SUPPORT_HPP
#define FABRIC_REGISTRY_TESTS_SUPPORT_REGISTRY_TEST_SUPPORT_HPP

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"

namespace frtest {

/// A deterministic entropy source. Tests inject this so that a failure can be
/// reproduced exactly; production code always uses the operating system CSPRNG.
class DeterministicEntropy {
public:
  explicit DeterministicEntropy(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  void operator()(std::uint8_t* out, std::size_t size) noexcept {
    for (std::size_t index = 0; index < size; ++index) {
      state_ += 0x9E3779B97F4A7C15ull;
      std::uint64_t mixed = state_;
      mixed = (mixed ^ (mixed >> 30)) * 0xBF58476D1CE4E5B9ull;
      mixed = (mixed ^ (mixed >> 27)) * 0x94D049BB133111EBull;
      mixed = mixed ^ (mixed >> 31);
      out[index] = static_cast<std::uint8_t>(mixed & 0xFFu);
    }
  }

private:
  std::uint64_t state_;
};

inline fabric_registry::RegistryOptions test_options(std::uint64_t seed = 1) {
  fabric_registry::RegistryOptions options;
  options.entropy_source = DeterministicEntropy(seed);
  return options;
}

inline std::unique_ptr<fabric_registry::Registry> make_registry(std::uint64_t seed = 1) {
  return std::make_unique<fabric_registry::Registry>(test_options(seed));
}

/// Deterministic attempt identifier derived from a label.
inline fabric_registry::RegistrationId attempt_from(const std::string& label) {
  fabric_registry::Sha256 hasher;
  hasher.update("fabric-registry/test-attempt/1");
  hasher.update(label);
  const fabric_registry::DigestBytes digest = hasher.finish();
  fabric_registry::IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
  }
  if (bytes[0] == 0 && bytes[1] == 0) {
    bytes[0] = 0x7C;
  }
  return fabric_registry::RegistrationId::from_bytes(bytes);
}

inline fabric_registry::IdentityFact serial_fact(const std::string& serial,
                                                 const std::string& scope = "vendor:0x15b3/product:0x1017") {
  fabric_registry::IdentityFact fact;
  fact.kind = fabric_registry::IdentityFactKind::SerialNumber;
  fact.scope = scope;
  fact.value = serial;
  return fact;
}

inline fabric_registry::IdentityFact fact_of(fabric_registry::IdentityFactKind kind,
                                             const std::string& value,
                                             const std::string& scope = std::string()) {
  fabric_registry::IdentityFact fact;
  fact.kind = kind;
  fact.scope = scope;
  fact.value = value;
  return fact;
}

inline fabric_registry::Provenance real_provenance(const std::string& source = "test") {
  fabric_registry::Provenance provenance;
  provenance.source = fabric_registry::ObservationSource::DeviceAgent;
  provenance.validity_class = fabric_registry::ProvenanceClass::Real;
  provenance.mechanism = "test-harness";
  provenance.source_identity = source;
  return provenance;
}

inline fabric_registry::Provenance synthetic_provenance(const std::string& source = "test") {
  fabric_registry::Provenance provenance;
  provenance.source = fabric_registry::ObservationSource::SyntheticFixture;
  provenance.validity_class = fabric_registry::ProvenanceClass::Synthetic;
  provenance.mechanism = "test-harness";
  provenance.source_identity = source;
  return provenance;
}

/// A registration request shaped for a device entity with one serial fact.
inline fabric_registry::RegisterEntityRequest device_request(fabric_registry::Registry& registry,
                                                             const std::string& label,
                                                             const std::string& serial,
                                                             fabric_registry::EntityClass entity_class =
                                                                 fabric_registry::EntityClass::Switch,
                                                             const std::string& derivation_namespace =
                                                                 "test/namespace-a",
                                                             fabric_registry::EvidenceClass evidence_class =
                                                                 fabric_registry::EvidenceClass::DurableAuthority) {
  fabric_registry::RegisterEntityRequest request;
  request.attempt = attempt_from(label);
  request.authority = registry.local_authority();
  request.entity_class = entity_class;
  request.derivation_namespace = derivation_namespace;
  request.friendly_name = label;
  request.facts.push_back(serial_fact(serial));
  request.provenance = real_provenance();
  request.evidence_class = evidence_class;
  request.admission = fabric_registry::AdmissionMode::RequireCurrent;
  return request;
}

inline fabric_registry::AliasInput alias_of(fabric_registry::AliasNamespace alias_namespace,
                                            const std::string& value) {
  fabric_registry::AliasInput alias;
  alias.alias_namespace = alias_namespace;
  alias.value = value;
  return alias;
}

/// A filesystem path unique to one test case.
inline std::filesystem::path temporary_state_path(const std::string& label) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / ("fabric-registry-state-" + label);
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory / "state.bin";
}

inline void remove_state(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
  std::filesystem::remove(fabric_registry::persistence::temporary_path_for(path), error);
}

} // namespace frtest

#endif // FABRIC_REGISTRY_TESTS_SUPPORT_REGISTRY_TEST_SUPPORT_HPP
