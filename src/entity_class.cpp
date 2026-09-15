// Fabric Registry — entity class taxonomy.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/entity_class.hpp"

namespace fabric_registry {
namespace {

struct EntityClassName {
  EntityClass value;
  std::string_view name;
};

// The table order is irrelevant to correctness; lookup scans it linearly, which
// is faster than any map for fifteen entries.
constexpr EntityClassName kEntityClassNames[] = {
    {EntityClass::Fabric, "fabric"},
    {EntityClass::Site, "site"},
    {EntityClass::SubFabric, "sub-fabric"},
    {EntityClass::ControlDomain, "control-domain"},
    {EntityClass::Switch, "switch"},
    {EntityClass::Router, "router"},
    {EntityClass::Nic, "nic"},
    {EntityClass::SmartNic, "smartnic"},
    {EntityClass::Dpu, "dpu"},
    {EntityClass::Host, "host"},
    {EntityClass::Port, "port"},
    {EntityClass::Link, "link"},
    {EntityClass::Endpoint, "endpoint"},
    {EntityClass::ControlParticipant, "control-participant"},
    {EntityClass::VendorDevice, "vendor-device"},
};

} // namespace

std::string_view to_string(EntityClass value) noexcept {
  for (const EntityClassName& entry : kEntityClassNames) {
    if (entry.value == value) {
      return entry.name;
    }
  }
  return "unknown";
}

std::optional<EntityClass> entity_class_from_string(std::string_view text) noexcept {
  for (const EntityClassName& entry : kEntityClassNames) {
    if (entry.name == text) {
      return entry.value;
    }
  }
  return std::nullopt;
}

bool is_valid_entity_class(EntityClass value) noexcept {
  return value != EntityClass::Unknown &&
         static_cast<std::uint8_t>(value) <= kEntityClassCount;
}

bool is_device_class(EntityClass value) noexcept {
  switch (value) {
    case EntityClass::Switch:
    case EntityClass::Router:
    case EntityClass::Nic:
    case EntityClass::SmartNic:
    case EntityClass::Dpu:
    case EntityClass::Host:
    case EntityClass::VendorDevice:
      return true;
    default:
      return false;
  }
}

bool is_administrative_scope_class(EntityClass value) noexcept {
  switch (value) {
    case EntityClass::Fabric:
    case EntityClass::Site:
    case EntityClass::SubFabric:
    case EntityClass::ControlDomain:
      return true;
    default:
      return false;
  }
}

bool requires_parent_device(EntityClass value) noexcept {
  switch (value) {
    case EntityClass::Port:
    case EntityClass::Endpoint:
      return true;
    default:
      return false;
  }
}

bool may_reference_fabric(EntityClass value) noexcept {
  return is_valid_entity_class(value) && value != EntityClass::Fabric;
}

} // namespace fabric_registry
