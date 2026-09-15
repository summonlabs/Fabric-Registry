// Fabric Registry — version identity.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/version.hpp"

namespace fabric_registry {

std::string_view version_string() noexcept { return "1.0.0"; }

std::uint32_t version_number() noexcept {
  return static_cast<std::uint32_t>(FABRIC_REGISTRY_VERSION_MAJOR) * 10000u +
         static_cast<std::uint32_t>(FABRIC_REGISTRY_VERSION_MINOR) * 100u +
         static_cast<std::uint32_t>(FABRIC_REGISTRY_VERSION_PATCH);
}

std::uint32_t state_format_version() noexcept {
  return static_cast<std::uint32_t>(FABRIC_REGISTRY_STATE_FORMAT_VERSION);
}

std::uint16_t protocol_version() noexcept {
  return static_cast<std::uint16_t>(FABRIC_REGISTRY_PROTOCOL_VERSION);
}

} // namespace fabric_registry
