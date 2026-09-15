// Fabric Registry — the publisher (worker) client.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A PublisherClient owns one connection to a coordinator and one worker
// incarnation. Every mutation it sends is stamped with that incarnation, so
// traffic from a previous incarnation of the same stable publisher identity is
// rejected by the coordinator for the rest of time.

#ifndef FABRIC_REGISTRY_PUBLISHER_HPP
#define FABRIC_REGISTRY_PUBLISHER_HPP

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "fabric_registry/authority.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/registry.hpp"
#include "fabric_registry/transport.hpp"

namespace fabric_registry {

struct PublisherClientOptions {
  Endpoint coordinator{"127.0.0.1", 0};
  /// Stable publisher name. Used for diagnostics only; it is not an identity.
  std::string name{"publisher"};
  /// Stable publisher identity to reattach with. Null requests a fresh one.
  PublisherId publisher{};
  TransportConfig transport{};
};

/// Result of one remote operation.
struct RemoteOutcome {
  Outcome outcome;
  /// Round-trip time of the request.
  std::chrono::milliseconds elapsed{0};

  bool succeeded() const noexcept { return outcome.succeeded(); }
};

class FABRIC_REGISTRY_API PublisherClient {
public:
  /// Connects, performs the HELLO handshake and attaches a fresh incarnation.
  /// Returns nullptr and fills `error` when any step fails.
  static std::unique_ptr<PublisherClient> connect(const PublisherClientOptions& options, std::string& error);

  ~PublisherClient();
  PublisherClient(const PublisherClient&) = delete;
  PublisherClient& operator=(const PublisherClient&) = delete;
  PublisherClient(PublisherClient&&) = delete;
  PublisherClient& operator=(PublisherClient&&) = delete;

  /// The incarnation this client currently holds.
  const AuthorityClaim& authority() const noexcept;
  CoordinatorEpoch coordinator_epoch() const noexcept;

  /// Sends one heartbeat and waits for the acknowledgement.
  bool heartbeat(std::string& error);

  RemoteOutcome register_entity(RegisterEntityRequest request);
  RemoteOutcome update_evidence(UpdateEvidenceRequest request);
  RemoteOutcome attach_alias(AliasMutationRequest request);
  RemoteOutcome detach_alias(AliasMutationRequest request);
  RemoteOutcome supersede_entity(SupersedeEntityRequest request);
  RemoteOutcome retire_entity(RetireEntityRequest request);
  RemoteOutcome tombstone_entity(TombstoneEntityRequest request);
  RemoteOutcome revalidate_entity(RevalidateEntityRequest request);
  RemoteOutcome resolve_conflict(ResolveConflictRequest request);

  /// Reconciles an observation and receives the full match detail.
  bool reconcile_observation(ReconcileObservationRequest request, ReconcileResult& out, std::string& error);

  /// Looks a record up on the coordinator.
  bool lookup(const CanonicalId& target, Outcome& outcome, std::shared_ptr<const EntityRecord>& record, std::string& error);

  /// Reads the coordinator's snapshot summary over the wire.
  bool snapshot_summary(SnapshotSummary& out, std::string& error);

  /// Reads the coordinator's statistics.
  bool statistics(StatsPayload& out, std::string& error);

  /// Detaches the current incarnation and closes the connection. Idempotent.
  Outcome detach();

  void close() noexcept;
  bool connected() const noexcept;

private:
  PublisherClient();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_PUBLISHER_HPP
