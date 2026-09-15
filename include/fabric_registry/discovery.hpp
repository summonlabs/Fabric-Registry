// Fabric Registry — platform discovery adapters.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Discovery is not authority. An adapter produces observations; it never
// mutates the registry and never claims that a discovered device is registered.
// Every observation carries explicit provenance so a consumer can tell a real
// enumeration of this host apart from generated fixture data.
//
// The core library does not depend on any platform facility. The Windows
// adapter is compiled only on Windows and links only against system libraries;
// on other platforms the same entry points report Unsupported capability with a
// specific reason rather than failing to build.

#ifndef FABRIC_REGISTRY_DISCOVERY_HPP
#define FABRIC_REGISTRY_DISCOVERY_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "fabric_registry/export.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/registry.hpp"

namespace fabric_registry {

/// A discovery capability the runtime may or may not have in this environment.
enum class DiscoveryCapability : std::uint8_t {
  HostNetworkAdapters = 0,
  PciNetworkDevices = 1,
  HostIdentity = 2,
  AcceleratorDevices = 3,
  RdmaDevices = 4,
  PhysicalSwitches = 5,
  OpticalLinks = 6,
  SmartNicDpu = 7,
};

inline constexpr std::uint8_t kDiscoveryCapabilityCount = 8;

FABRIC_REGISTRY_API std::string_view to_string(DiscoveryCapability value) noexcept;

enum class CapabilityStatus : std::uint8_t {
  /// The capability is implemented and was exercised in this environment.
  Available = 0,
  /// The capability is implemented but the environment has nothing to report.
  Empty = 1,
  /// The capability cannot be provided truthfully in this environment.
  Unsupported = 2,
};

FABRIC_REGISTRY_API std::string_view to_string(CapabilityStatus value) noexcept;

struct CapabilityReport {
  DiscoveryCapability capability{DiscoveryCapability::HostNetworkAdapters};
  CapabilityStatus status{CapabilityStatus::Unsupported};
  std::string detail;

  friend bool operator==(const CapabilityReport&, const CapabilityReport&) = default;
};

/// One observation produced by discovery.
struct DiscoveryObservation {
  EntityClass entity_class{EntityClass::Unknown};
  std::string friendly_name;
  std::vector<IdentityFact> facts;
  std::vector<AliasInput> aliases;
  std::vector<MetadataEntry> metadata;
  ScopeRef scope;
  Provenance provenance;
  /// Free-form platform detail, e.g. the device instance id.
  std::string platform_detail;
};

struct DiscoveryOptions {
  /// Maximum number of observations produced.
  std::size_t max_observations{1024};
  /// Maximum facts per observation.
  std::size_t max_facts{32};
  /// Maximum length of any produced string.
  std::size_t max_string_bytes{1024};
  /// Administrative scope assigned to every observation.
  ScopeRef scope;
  /// Derivation namespace assigned to every observation.
  std::string derivation_namespace{"fabric-registry/host"};
  /// Enumerate PCI/PnP network device identities in addition to the operating
  /// system adapter list.
  bool include_pci_devices{true};
  /// Produce a host identity observation.
  bool include_host_identity{true};
};

struct FABRIC_REGISTRY_API DiscoveryReport {
  std::string platform;
  ObservationSource source{ObservationSource::Unspecified};
  ProvenanceClass validity_class{ProvenanceClass::Unknown};
  std::vector<DiscoveryObservation> observations;
  std::vector<CapabilityReport> capabilities;
  std::vector<std::string> diagnostics;
  /// True when the observation bound was reached and the enumeration stopped.
  bool truncated{false};

  /// Canonical deterministic rendering.
  std::string render() const;
};

/// Enumerates host-visible network device identity on this machine.
///
/// The returned observations are labelled Real when they came from an operating
/// system enumeration, and Unsupported with an explanatory detail when the
/// platform provides no such facility in this build.
FABRIC_REGISTRY_API DiscoveryReport discover_local_host(const DiscoveryOptions& options = DiscoveryOptions{});

/// Reports, without enumerating anything, which capabilities this build and this
/// host can truthfully provide.
FABRIC_REGISTRY_API std::vector<CapabilityReport> discovery_capabilities();

/// Host directory that discovery used to identify the local system, when
/// available. Empty when unknown.
FABRIC_REGISTRY_API std::string local_host_identity();

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_DISCOVERY_HPP
