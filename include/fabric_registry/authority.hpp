// Fabric Registry — registration authority and process incarnation.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Registration is authority-bound. A mutation is accepted only when the
// publisher is known, is active, presents the worker incarnation currently
// bound to that publisher, and presents the current coordinator epoch. A
// publisher that restarts receives a freshly minted WorkerBootId; every boot id
// it previously held is fenced permanently.

#ifndef FABRIC_REGISTRY_AUTHORITY_HPP
#define FABRIC_REGISTRY_AUTHORITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/entity.hpp"
#include "fabric_registry/export.hpp"

namespace fabric_registry {

enum class PublisherState : std::uint8_t {
  Unregistered = 0,
  Active = 1,
  /// Lost or explicitly fenced. May reattach with a new incarnation.
  Fenced = 2,
  /// Administratively closed. May not reattach.
  Retired = 3,
};

FABRIC_REGISTRY_API std::string_view to_string(PublisherState value) noexcept;

/// The authority a mutation presents.
///
/// A claim is bound to a live process incarnation: presenting a publisher id
/// alone is never sufficient.
struct AuthorityClaim {
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};

  bool is_complete() const noexcept { return !publisher.is_null() && !worker_boot.is_null() && !epoch.is_zero(); }

  friend bool operator==(const AuthorityClaim&, const AuthorityClaim&) = default;
};

/// Durable state of one publisher principal.
struct PublisherRecord {
  PublisherId id{};
  std::string name;
  /// The control-plane participant entity that represents this publisher, when
  /// one was registered.
  std::optional<CanonicalId> participant;

  /// The incarnation currently entitled to act. Null when the publisher is not
  /// attached.
  WorkerBootId current_boot{};
  /// Epoch under which the current incarnation attached.
  CoordinatorEpoch attached_epoch{};
  PublisherState state{PublisherState::Unregistered};
  /// Number of times this publisher has attached. Never decremented, never
  /// recycled.
  std::uint64_t attach_count{0};
  /// Registry generation at which the publisher last changed state.
  RegistryGeneration last_modified{};
  /// Bounded, oldest-first list of fenced incarnations. Traffic from any of
  /// these is rejected permanently.
  std::vector<WorkerBootId> fenced_boots;
  std::string status_reason;
};

/// Request to attach a publisher incarnation.
struct PublisherAttachRequest {
  /// Stable publisher identity. Null requests a freshly minted publisher.
  PublisherId publisher{};
  /// Human-readable publisher name. Bounded; not an identity.
  std::string name;
  /// Protocol version the client speaks.
  std::uint16_t protocol_version{0};
};

/// Result of an attach.
struct PublisherAttachResult {
  Outcome outcome;
  PublisherId publisher{};
  WorkerBootId worker_boot{};
  CoordinatorEpoch epoch{};
  /// True when this attach fenced a previous incarnation.
  bool fenced_previous{false};
};

/// Why a publisher stopped being authoritative.
enum class FenceReason : std::uint8_t {
  SessionLost = 0,
  HeartbeatExpired = 1,
  ExplicitDetach = 2,
  EpochAdvanced = 3,
  Administrative = 4,
};

FABRIC_REGISTRY_API std::string_view to_string(FenceReason value) noexcept;

/// Statistics about the authority domain.
struct AuthorityStats {
  std::size_t publishers{0};
  std::size_t active_publishers{0};
  std::size_t fenced_publishers{0};
  std::size_t fenced_boots{0};
  CoordinatorEpoch epoch{};
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_AUTHORITY_HPP
