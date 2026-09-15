// Shared helpers for the Fabric Registry examples.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FABRIC_REGISTRY_EXAMPLES_SUPPORT_HPP
#define FABRIC_REGISTRY_EXAMPLES_SUPPORT_HPP

#include <iostream>
#include <string>

#include "fabric_registry/fabric_registry.hpp"

namespace example {

/// Mints a deterministic attempt identifier from a label so an example can be
/// replayed byte for byte.
inline fabric_registry::RegistrationId attempt_from(const std::string& label) {
  fabric_registry::Sha256 hasher;
  hasher.update("fabric-registry/example-attempt/1");
  hasher.update(label);
  const fabric_registry::DigestBytes digest = hasher.finish();
  fabric_registry::IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
  }
  if (bytes[0] == 0 && bytes[1] == 0) {
    bytes[0] = 0xE1;
  }
  return fabric_registry::RegistrationId::from_bytes(bytes);
}

/// A real, globally meaningful serial number fact. The scope records the
/// vendor/product namespace that issued it, because a bare serial is not a
/// global identity.
inline fabric_registry::IdentityFact serial_fact(const std::string& serial) {
  fabric_registry::IdentityFact fact;
  fact.kind = fabric_registry::IdentityFactKind::SerialNumber;
  fact.scope = "vendor:0x15b3/product:0x1017";
  fact.value = serial;
  return fact;
}

inline fabric_registry::Provenance real_provenance(const std::string& mechanism, const std::string& source) {
  fabric_registry::Provenance provenance;
  provenance.source = fabric_registry::ObservationSource::DeviceAgent;
  provenance.validity_class = fabric_registry::ProvenanceClass::Real;
  provenance.mechanism = mechanism;
  provenance.source_identity = source;
  return provenance;
}

inline void report(const fabric_registry::Outcome& outcome, const std::string& label) {
  std::cout << label << ": " << fabric_registry::to_string(outcome.code) << " - " << outcome.message << "\n";
}

inline int fail(const std::string& message) {
  std::cerr << "example failed: " << message << "\n";
  return 1;
}

} // namespace example

#endif // FABRIC_REGISTRY_EXAMPLES_SUPPORT_HPP
