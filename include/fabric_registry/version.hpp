// Fabric Registry — version identity.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FABRIC_REGISTRY_VERSION_HPP
#define FABRIC_REGISTRY_VERSION_HPP

#include <cstdint>
#include <string_view>

#include "fabric_registry/export.hpp"

#define FABRIC_REGISTRY_VERSION_MAJOR 1
#define FABRIC_REGISTRY_VERSION_MINOR 0
#define FABRIC_REGISTRY_VERSION_PATCH 0

// Incremented whenever the persisted on-disk state format changes in a way that
// older readers cannot interpret. Persisted files carry this number and a file
// whose format version is not exactly the supported one is rejected.
#define FABRIC_REGISTRY_STATE_FORMAT_VERSION 1

// Incremented whenever the wire protocol changes incompatibly. Peers negotiate
// by exchanging this value in the HELLO handshake; a mismatch is rejected.
#define FABRIC_REGISTRY_PROTOCOL_VERSION 1

namespace fabric_registry {

/// Semantic version of the runtime, as "major.minor.patch".
FABRIC_REGISTRY_API std::string_view version_string() noexcept;

/// Numeric version triple, packed as (major * 10000 + minor * 100 + patch).
FABRIC_REGISTRY_API std::uint32_t version_number() noexcept;

/// Persisted state format version understood by this build.
FABRIC_REGISTRY_API std::uint32_t state_format_version() noexcept;

/// Wire protocol version understood by this build.
FABRIC_REGISTRY_API std::uint16_t protocol_version() noexcept;

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_VERSION_HPP
