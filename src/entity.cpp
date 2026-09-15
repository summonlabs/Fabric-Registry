// Fabric Registry — entity records and lifecycle.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/entity.hpp"

namespace fabric_registry {

std::string_view to_string(Lifecycle value) noexcept {
  switch (value) {
    case Lifecycle::Discovered:
      return "discovered";
    case Lifecycle::Candidate:
      return "candidate";
    case Lifecycle::Current:
      return "current";
    case Lifecycle::RevalidationRequired:
      return "revalidation-required";
    case Lifecycle::Superseded:
      return "superseded";
    case Lifecycle::Retired:
      return "retired";
    case Lifecycle::Tombstoned:
      return "tombstoned";
    case Lifecycle::Conflicted:
      return "conflicted";
    case Lifecycle::Rejected:
      return "rejected";
  }
  return "unknown";
}

std::optional<Lifecycle> lifecycle_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw < kLifecycleCount; ++raw) {
    const Lifecycle value = static_cast<Lifecycle>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

bool is_terminal_lifecycle(Lifecycle value) noexcept {
  return value == Lifecycle::Tombstoned || value == Lifecycle::Rejected;
}

bool holds_current_authority(Lifecycle value) noexcept {
  return value == Lifecycle::Current;
}

bool lifecycle_transition_allowed(Lifecycle from, Lifecycle to) noexcept {
  if (from == to) {
    // A transition to the same state is not a transition; callers treat it as a
    // no-op before reaching here.
    return false;
  }
  switch (from) {
    case Lifecycle::Discovered:
      return to == Lifecycle::Candidate || to == Lifecycle::Conflicted || to == Lifecycle::Rejected;
    case Lifecycle::Candidate:
      return to == Lifecycle::Current || to == Lifecycle::Conflicted || to == Lifecycle::Rejected;
    case Lifecycle::Current:
      return to == Lifecycle::RevalidationRequired || to == Lifecycle::Superseded ||
             to == Lifecycle::Retired || to == Lifecycle::Conflicted;
    case Lifecycle::RevalidationRequired:
      return to == Lifecycle::Current || to == Lifecycle::Superseded || to == Lifecycle::Retired ||
             to == Lifecycle::Conflicted;
    case Lifecycle::Conflicted:
      return to == Lifecycle::Current || to == Lifecycle::Retired || to == Lifecycle::Rejected;
    case Lifecycle::Superseded:
      return to == Lifecycle::Retired || to == Lifecycle::Tombstoned;
    case Lifecycle::Retired:
      return to == Lifecycle::Tombstoned;
    case Lifecycle::Tombstoned:
      return false;
    case Lifecycle::Rejected:
      return false;
  }
  return false;
}

std::string_view to_string(ReasonCode value) noexcept {
  switch (value) {
    case ReasonCode::Registration:
      return "registration";
    case ReasonCode::EvidenceUpdate:
      return "evidence-update";
    case ReasonCode::AliasAttach:
      return "alias-attach";
    case ReasonCode::AliasDetach:
      return "alias-detach";
    case ReasonCode::Revalidation:
      return "revalidation";
    case ReasonCode::Supersede:
      return "supersede";
    case ReasonCode::Retire:
      return "retire";
    case ReasonCode::Tombstone:
      return "tombstone";
    case ReasonCode::ConflictRaised:
      return "conflict-raised";
    case ReasonCode::ConflictResolved:
      return "conflict-resolved";
    case ReasonCode::Promotion:
      return "promotion";
    case ReasonCode::RecoveryDemotion:
      return "recovery-demotion";
    case ReasonCode::PublisherFenced:
      return "publisher-fenced";
    case ReasonCode::EpochAdvance:
      return "epoch-advance";
  }
  return "unknown";
}

bool EntityRecord::is_well_formed() const noexcept {
  if (!is_valid_entity_class(entity_class)) {
    return false;
  }
  if (id.is_null()) {
    return false;
  }
  if (id.entity_class() != entity_class) {
    return false;
  }
  if (record_generation.is_zero() || creation_generation.is_zero()) {
    return false;
  }
  if (creation_generation > record_generation) {
    return false;
  }
  if (static_cast<std::uint8_t>(lifecycle) >= kLifecycleCount) {
    return false;
  }
  if (requires_parent_device(entity_class) && !parent_device.has_value()) {
    return false;
  }
  return true;
}

} // namespace fabric_registry
