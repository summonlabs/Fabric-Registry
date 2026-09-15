// Fabric Registry — portable discovery stub.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// No platform discovery adapter is implemented for this platform. The stub says
// exactly that and nothing else: every capability is Unsupported, the host
// identity is unknown, and the report carries no observation and never claims
// Real provenance. Reporting a capability as available here would be a lie, and
// fabricating an observation would be worse.
//
// This translation unit is compiled only on platforms other than Windows.

#if !defined(_WIN32)

#include "fabric_registry/discovery.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fabric_registry {
namespace {

#if defined(__unix__) || defined(__unix) || defined(__linux__) || defined(__APPLE__) || defined(__posix__)
constexpr std::string_view kPlatformName = "posix";
#else
constexpr std::string_view kPlatformName = "unknown";
#endif

} // namespace

std::string_view to_string(DiscoveryCapability value) noexcept {
  switch (value) {
    case DiscoveryCapability::HostNetworkAdapters:
      return "host-network-adapters";
    case DiscoveryCapability::PciNetworkDevices:
      return "pci-network-devices";
    case DiscoveryCapability::HostIdentity:
      return "host-identity";
    case DiscoveryCapability::AcceleratorDevices:
      return "accelerator-devices";
    case DiscoveryCapability::RdmaDevices:
      return "rdma-devices";
    case DiscoveryCapability::PhysicalSwitches:
      return "physical-switches";
    case DiscoveryCapability::OpticalLinks:
      return "optical-links";
    case DiscoveryCapability::SmartNicDpu:
      return "smart-nic-dpu";
  }
  return "unknown";
}

std::string_view to_string(CapabilityStatus value) noexcept {
  switch (value) {
    case CapabilityStatus::Available:
      return "available";
    case CapabilityStatus::Empty:
      return "empty";
    case CapabilityStatus::Unsupported:
      return "unsupported";
  }
  return "unknown";
}

std::vector<CapabilityReport> discovery_capabilities() {
  std::vector<CapabilityReport> reports;
  reports.reserve(kDiscoveryCapabilityCount);
  for (std::uint8_t value = 0; value < kDiscoveryCapabilityCount; ++value) {
    CapabilityReport report;
    report.capability = static_cast<DiscoveryCapability>(value);
    report.status = CapabilityStatus::Unsupported;
    report.detail = std::string(to_string(report.capability));
    report.detail += ": the discovery adapter for platform '";
    report.detail += kPlatformName;
    report.detail += "' is not implemented in this build";
    reports.push_back(std::move(report));
  }
  return reports;
}

std::string local_host_identity() {
  return {};
}

DiscoveryReport discover_local_host(const DiscoveryOptions& options) {
  // The stub has no enumeration to bound, so the options are not consulted.
  static_cast<void>(options);
  DiscoveryReport report;
  report.platform.assign(kPlatformName);
  report.source = ObservationSource::LocalHostEnumeration;
  report.validity_class = ProvenanceClass::Unsupported;
  report.capabilities = discovery_capabilities();
  report.diagnostics.push_back("no discovery adapter is implemented for platform '" + std::string(kPlatformName) +
                               "' in this build; no observation was produced and no capability is claimed");
  return report;
}

} // namespace fabric_registry

#endif // !defined(_WIN32)
