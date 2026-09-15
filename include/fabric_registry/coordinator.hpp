// Fabric Registry — the coordinator process.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The coordinator owns one Registry and serves it over the framed protocol. It
// runs one acceptor thread and a bounded pool of session threads. Session
// threads never hold the registry lock while performing socket I/O, and the
// registry never invokes session code while holding its lock, so the two layers
// cannot deadlock against each other.
//
// A publisher is fenced when its session ends for any reason, including the
// death of the publishing process. Fencing invalidates every process-bound item
// of evidence that publisher supplied and moves the affected records to
// REVALIDATION_REQUIRED.

#ifndef FABRIC_REGISTRY_COORDINATOR_HPP
#define FABRIC_REGISTRY_COORDINATOR_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

#include "fabric_registry/export.hpp"
#include "fabric_registry/registry.hpp"
#include "fabric_registry/transport.hpp"

namespace fabric_registry {

struct CoordinatorOptions {
  /// Address to listen on. Port 0 selects an ephemeral port.
  Endpoint listen{"127.0.0.1", 0};
  /// Durable state file. Empty keeps the coordinator in memory only.
  std::filesystem::path state_path;
  /// Persist after every committed mutation.
  bool persist_on_commit{true};
  /// Maximum simultaneous sessions.
  std::size_t max_sessions{64};
  /// Server name reported in the HELLO handshake.
  std::string server_name{"fabric-registry-coordinator"};
  FrameLimits frame_limits{};
  TransportConfig transport{};
  RegistryOptions registry{};

  ValidationResult validate() const;
};

class FABRIC_REGISTRY_API Coordinator {
public:
  /// Starts the coordinator. Returns nullptr and fills `error` when the
  /// listener cannot be bound or the options are invalid.
  static std::unique_ptr<Coordinator> start(const CoordinatorOptions& options, std::string& error);

  ~Coordinator();
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;
  Coordinator(Coordinator&&) = delete;
  Coordinator& operator=(Coordinator&&) = delete;

  /// Stops the coordinator: stops accepting, stops every session, fences every
  /// still-attached publisher, joins every thread and, when a state path is
  /// configured, writes the final durable state. Idempotent and safe to call
  /// from any thread other than a session thread.
  void stop() noexcept;

  /// Actual bound port.
  std::uint16_t port() const noexcept;
  Endpoint endpoint() const;

  RegistryStats stats() const;
  std::size_t active_sessions() const noexcept;
  CoordinatorEpoch epoch() const noexcept;

  /// Writes the durable state now. Returns TransportFailure when no state path
  /// is configured.
  Outcome save_now();

  /// Fences every publisher whose heartbeat has expired. Exposed so a test or
  /// an operator can drive the same code path the reaper uses.
  Outcome reap_expired_publishers();

  /// Number of publishers fenced since start.
  std::uint64_t fenced_publisher_count() const noexcept;

  /// Number of durable writes that failed since start. A failed write is always
  /// reported on standard error as well; this counter exists so a supervisor can
  /// assert on it.
  std::uint64_t persist_failure_count() const noexcept;

  /// What happened when durable state was recovered at start. When no state
  /// path was configured or no state file existed, the report is default
  /// constructed and detail explains that the registry started empty.
  const RecoveryReport& recovery_report() const noexcept;

private:
  Coordinator();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_COORDINATOR_HPP
