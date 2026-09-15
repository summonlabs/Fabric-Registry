// Fabric Registry — entity class taxonomy.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FABRIC_REGISTRY_ENTITY_CLASS_HPP
#define FABRIC_REGISTRY_ENTITY_CLASS_HPP

#include <cstdint>
#include <optional>
#include <string_view>

#include "fabric_registry/export.hpp"

namespace fabric_registry {

/// The classes of infrastructure entity whose canonical identity Fabric
/// Registry owns.
///
/// The enumerator values are part of the persisted state format and the wire
/// protocol: they must never be renumbered. New classes are appended.
enum class EntityClass : std::uint8_t {
  /// Sentinel meaning "no class". Never valid in a request or a record.
  Unknown = 0,
  /// An administrative fabric: the authority domain that owns a device set.
  Fabric = 1,
  /// A physical or administrative site within a fabric.
  Site = 2,
  /// A control-plane domain: a set of control participants that share one
  /// coordinator authority boundary.
  ControlDomain = 3,
  Switch = 4,
  Router = 5,
  /// A network interface controller that is a first-class fabric endpoint.
  Nic = 6,
  SmartNic = 7,
  /// A data processing unit acting as a network/control-plane participant.
  Dpu = 8,
  /// A host or node, registered only to anchor network identities.
  Host = 9,
  /// A physical or logical port belonging to a device.
  Port = 10,
  /// A canonical link identity. Link *state* belongs to Link State Fabric.
  Link = 11,
  /// A logical endpoint: a stable addressable attachment point.
  Endpoint = 12,
  /// A control-plane participant: registry worker, discovery agent,
  /// controller, device agent or topology publisher.
  ControlParticipant = 13,
  /// An implementation-defined vendor device class whose identity requires a
  /// registry record.
  VendorDevice = 14,
  /// A partition of a fabric that has its own administrative namespace.
  SubFabric = 15,
};

/// Number of enumerators in EntityClass that denote a real class (that is,
/// everything except Unknown). Used to size index tables.
inline constexpr std::uint8_t kEntityClassCount = 15;

/// Stable lowercase wire/persistence name, e.g. "switch".
FABRIC_REGISTRY_API std::string_view to_string(EntityClass value) noexcept;

/// Parses the stable lowercase name. Returns nullopt for unknown names; never
/// guesses.
FABRIC_REGISTRY_API std::optional<EntityClass> entity_class_from_string(std::string_view text) noexcept;

/// True when the class denotes a device-bearing infrastructure element that can
/// own ports and be a device identity for matching purposes.
FABRIC_REGISTRY_API bool is_device_class(EntityClass value) noexcept;

/// True when the class denotes an administrative scope (fabric, site,
/// control domain, sub-fabric) rather than a physical element.
FABRIC_REGISTRY_API bool is_administrative_scope_class(EntityClass value) noexcept;

/// True when the class may legitimately carry a parent-device reference.
FABRIC_REGISTRY_API bool requires_parent_device(EntityClass value) noexcept;

/// True when a record of this class is allowed to hold a fabric reference.
FABRIC_REGISTRY_API bool may_reference_fabric(EntityClass value) noexcept;

/// True when the class may be the successor of a superseded record.
FABRIC_REGISTRY_API bool is_valid_entity_class(EntityClass value) noexcept;

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_ENTITY_CLASS_HPP
