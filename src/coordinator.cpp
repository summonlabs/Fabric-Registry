// Fabric Registry — the coordinator process.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Threading model
// ---------------
//  * one acceptor thread owns the listener and nothing else;
//  * one reaper thread joins finished session threads and erases them;
//  * one session thread per connection handles that connection's frames.
//
// A session thread never takes the session table mutex, so the session table can
// always be locked, inspected and joined from the acceptor, the reaper and
// stop(). A session thread fences the publisher it carried as its last action,
// after it has stopped using the connection, and never while holding any lock
// other than the registry's own. The registry never calls back into a session,
// so the two lock domains cannot deadlock against each other. Session threads
// are only ever joined by the reaper or by stop(), never by themselves.

#include "fabric_registry/coordinator.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "fabric_registry/version.hpp"

namespace fabric_registry {

namespace {

std::int64_t now_ticks() noexcept {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

} // namespace

ValidationResult CoordinatorOptions::validate() const {
  const ValidationResult registry_result = registry.validate();
  if (!registry_result) {
    return ValidationResult::failure("registry options are invalid: " + registry_result.message);
  }
  const ValidationResult frame_result = frame_limits.validate();
  if (!frame_result) {
    return ValidationResult::failure("frame limits are invalid: " + frame_result.message);
  }
  const ValidationResult transport_result = transport.validate();
  if (!transport_result) {
    return ValidationResult::failure("transport configuration is invalid: " + transport_result.message);
  }
  if (!is_bindable_host(listen.host)) {
    return ValidationResult::failure("listen.host is not a bindable address");
  }
  if (max_sessions < 1 || max_sessions > hard_limits::kMaxSessions) {
    return ValidationResult::failure("max_sessions is out of range");
  }
  if (max_sessions > frame_limits.max_sessions) {
    return ValidationResult::failure("max_sessions exceeds frame_limits.max_sessions");
  }
  if (server_name.size() > registry.limits.max_string_bytes) {
    return ValidationResult::failure("server_name exceeds the configured string bound");
  }
  if (!is_valid_identity_text(server_name)) {
    return ValidationResult::failure("server_name is not valid identity text");
  }
  return ValidationResult::success();
}

struct Coordinator::Impl {
  struct Session {
    std::shared_ptr<Connection> connection;
    std::thread thread;
    std::atomic<bool> finished{false};
    std::atomic<std::int64_t> last_activity{0};
    std::atomic<bool> has_authority{false};
    PublisherId publisher{};
    WorkerBootId boot{};
    std::string name;
  };

  CoordinatorOptions options;
  Registry registry;
  std::atomic<bool> stop{false};
  std::unique_ptr<TcpListener> listener;
  std::thread acceptor;
  std::thread reaper;
  mutable std::mutex sessions_mutex;
  std::vector<std::shared_ptr<Session>> sessions;
  std::mutex persist_mutex;
  std::atomic<std::uint64_t> fenced_publishers{0};
  std::atomic<std::uint64_t> request_counter{0};
  std::atomic<std::uint64_t> persist_failures{0};
  RecoveryReport recovery;

  explicit Impl(const CoordinatorOptions& options_in)
      : options(options_in), registry(options_in.registry) {}

  // ----- outbound helpers (never called while holding sessions_mutex) -----

  void send_outcome(const std::shared_ptr<Connection>& connection, std::uint64_t request_id, const Outcome& outcome) {
    std::string error;
    connection->send(MessageType::OperationAck, request_id, encode_outcome(outcome), error);
  }

  void send_error(const std::shared_ptr<Connection>& connection, std::uint64_t request_id, OutcomeCode code,
                  const std::string& message) {
    ErrorPayload payload;
    payload.code = code;
    payload.message = message;
    std::string error;
    connection->send(MessageType::Error, request_id, encode_error(payload), error);
  }

  void persist_if_needed(const Outcome& outcome) {
    if (!options.persist_on_commit || options.state_path.empty() || !outcome.committed()) {
      return;
    }
    // Serialised because two sessions may commit concurrently and the state file
    // has exactly one authoritative writer.
    std::lock_guard<std::mutex> guard(persist_mutex);
    const Outcome saved = registry.save(options.state_path);
    if (!saved.committed()) {
      // A failed durable write is reported, never swallowed: the commit is
      // already visible in memory and an operator must know the durable copy
      // lagged behind.
      ++persist_failures;
      std::fprintf(stderr, "fabric-registry-coordinator: durable state was not written: %s: %s\n",
                   std::string(to_string(saved.code)).c_str(), saved.message.c_str());
      std::fflush(stderr);
    }
  }

  // ----- frame handling -----

  void handle_frame(const std::shared_ptr<Session>& session, const Frame& frame) {
    const std::shared_ptr<Connection>& connection = session->connection;
    const std::uint64_t request_id = frame.request_id;
    const std::span<const std::uint8_t> payload(frame.payload.data(), frame.payload.size());
    std::string error;

    switch (frame.type) {
      case MessageType::Hello: {
        HelloRequest request;
        if (!decode_hello_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        HelloResponse response;
        response.protocol_version = protocol_version();
        response.coordinator_epoch = registry.epoch();
        response.registry_generation = registry.stats().generation;
        response.server_name = options.server_name;
        response.accepted = request.protocol_version == response.protocol_version;
        if (!response.accepted) {
          response.reason = "protocol version mismatch: server speaks " + std::to_string(response.protocol_version);
        }
        connection->send(MessageType::HelloAck, request_id, encode_hello_response(response), error);
        return;
      }
      case MessageType::AttachPublisher: {
        if (session->has_authority.load(std::memory_order_acquire)) {
          send_error(connection, request_id, OutcomeCode::MalformedRequest,
                     "this session already carries a publisher incarnation");
          return;
        }
        PublisherAttachRequest request;
        if (!decode_attach_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const PublisherAttachResult result = registry.attach_publisher(request);
        if (result.outcome.committed()) {
          session->publisher = result.publisher;
          session->boot = result.worker_boot;
          session->name = request.name;
          session->has_authority.store(true, std::memory_order_release);
        }
        connection->send(MessageType::AttachPublisherAck, request_id, encode_attach_response(result), error);
        persist_if_needed(result.outcome);
        return;
      }
      case MessageType::DetachPublisher: {
        AuthorityClaim claim;
        FenceReason reason = FenceReason::ExplicitDetach;
        if (!decode_detach_request(payload, claim, reason, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.detach_publisher(claim, reason);
        if (outcome.committed()) {
          ++fenced_publishers;
          session->has_authority.store(false, std::memory_order_release);
        }
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::RegisterEntity: {
        RegisterEntityRequest request;
        if (!decode_register_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.register_entity(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::UpdateEvidence: {
        UpdateEvidenceRequest request;
        if (!decode_update_evidence_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.update_evidence(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::AttachAlias:
      case MessageType::DetachAlias: {
        AliasMutationRequest request;
        if (!decode_alias_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = frame.type == MessageType::AttachAlias ? registry.attach_alias(request)
                                                                       : registry.detach_alias(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::SupersedeEntity: {
        SupersedeEntityRequest request;
        if (!decode_supersede_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.supersede_entity(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::RetireEntity: {
        RetireEntityRequest request;
        if (!decode_retire_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.retire_entity(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::TombstoneEntity: {
        TombstoneEntityRequest request;
        if (!decode_tombstone_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.tombstone_entity(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::RevalidateEntity: {
        RevalidateEntityRequest request;
        if (!decode_revalidate_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.revalidate_entity(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::ResolveConflict: {
        ResolveConflictRequest request;
        if (!decode_resolve_conflict_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const Outcome outcome = registry.resolve_conflict(request);
        send_outcome(connection, request_id, outcome);
        persist_if_needed(outcome);
        return;
      }
      case MessageType::ReconcileObservation: {
        ReconcileObservationRequest request;
        if (!decode_reconcile_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        const ReconcileResult result = registry.reconcile_observation(request);
        ByteWriter writer(256);
        const std::vector<std::uint8_t> outcome_bytes = encode_outcome(result.outcome);
        const std::vector<std::uint8_t> detail_bytes = encode_reconcile_detail(result.detail);
        writer.blob(outcome_bytes);
        writer.blob(detail_bytes);
        connection->send(MessageType::ReconcileAck, request_id, writer.bytes(), error);
        return;
      }
      case MessageType::LookupEntity: {
        LookupRequest request;
        if (!decode_lookup_request(payload, request, error)) {
          send_error(connection, request_id, OutcomeCode::ProtocolViolation, error);
          return;
        }
        std::shared_ptr<const EntityRecord> record;
        const Outcome outcome = registry.lookup(request.target, record);
        connection->send(MessageType::LookupAck, request_id, encode_lookup_response(outcome, record), error);
        return;
      }
      case MessageType::SnapshotRequest: {
        const Snapshot current = registry.snapshot();
        SnapshotSummary summary;
        summary.generation = current.generation();
        summary.epoch = current.epoch();
        summary.sequence = current.sequence();
        summary.digest = current.digest();
        summary.record_count = current.size();
        summary.alias_count = current.alias_count();
        connection->send(MessageType::SnapshotAck, request_id, encode_snapshot_summary(summary), error);
        return;
      }
      case MessageType::StatsRequest: {
        StatsPayload payload_out;
        payload_out.stats = registry.stats();
        connection->send(MessageType::StatsAck, request_id, encode_stats(payload_out), error);
        return;
      }
      case MessageType::Heartbeat: {
        const CoordinatorEpoch epoch = registry.epoch();
        ByteWriter writer(16);
        writer.u64(epoch.value());
        connection->send(MessageType::HeartbeatAck, request_id, writer.bytes(), error);
        return;
      }
      case MessageType::Shutdown: {
        Outcome outcome(OutcomeCode::Committed, "the coordinator accepted the shutdown request");
        outcome.epoch = registry.epoch();
        send_outcome(connection, request_id, outcome);
        connection->request_stop();
        return;
      }
      case MessageType::Invalid:
      case MessageType::HelloAck:
      case MessageType::AttachPublisherAck:
      case MessageType::HeartbeatAck:
      case MessageType::OperationAck:
      case MessageType::ReconcileAck:
      case MessageType::LookupAck:
      case MessageType::SnapshotAck:
      case MessageType::StatsAck:
      case MessageType::Error:
      default: {
        send_error(connection, request_id, OutcomeCode::ProtocolViolation,
                   "the coordinator received a message type only a client may send");
        return;
      }
    }
  }

  void run_session(const std::shared_ptr<Session>& session) {
    session->last_activity.store(now_ticks(), std::memory_order_relaxed);
    const auto timeout = options.transport.heartbeat_timeout;
    try {
      while (!stop.load(std::memory_order_acquire) && !session->connection->stopped()) {
        std::string error;
        const FrameDecodeResult result = session->connection->receive(options.transport.poll_interval, error);
        if (result.status == FrameDecodeStatus::Complete) {
          session->last_activity.store(now_ticks(), std::memory_order_relaxed);
          handle_frame(session, result.frame);
          continue;
        }
        if (!error.empty()) {
          // The connection reported a transport failure (the peer closed) or a
          // stop request. Either way this session is finished.
          break;
        }
        const std::int64_t idle_ns = now_ticks() - session->last_activity.load(std::memory_order_relaxed);
        if (std::chrono::nanoseconds(idle_ns) > timeout) {
          break;
        }
      }
    } catch (...) {
      // A session thread must never let an exception escape.
    }
    if (session->has_authority.load(std::memory_order_acquire)) {
      std::size_t demoted = 0;
      const Outcome outcome = registry.fence_publisher(session->publisher, FenceReason::SessionLost,
                                                      demoted);
      if (outcome.committed()) {
        ++fenced_publishers;
      }
      session->has_authority.store(false, std::memory_order_release);
      persist_if_needed(outcome);
    }
    session->connection->close();
    session->finished.store(true, std::memory_order_release);
  }

  void run_acceptor() {
    try {
      while (!stop.load(std::memory_order_acquire)) {
        std::string error;
        std::optional<Socket> socket = listener->accept(options.transport.poll_interval, stop, error);
        if (!socket.has_value()) {
          continue;
        }
        std::shared_ptr<Session> session = std::make_shared<Session>();
        session->connection = std::make_shared<Connection>(std::move(*socket), options.transport);
        bool accepted = false;
        {
          std::lock_guard<std::mutex> guard(sessions_mutex);
          if (sessions.size() < options.max_sessions) {
            sessions.push_back(session);
            accepted = true;
          }
        }
        if (!accepted) {
          session->connection->close();
          continue;
        }
        session->thread = std::thread([this, session]() { run_session(session); });
      }
    } catch (...) {
    }
  }

  void run_reaper() {
    try {
      while (!stop.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(options.transport.poll_interval);
        std::vector<std::shared_ptr<Session>> finished;
        {
          std::lock_guard<std::mutex> guard(sessions_mutex);
          for (auto entry = sessions.begin(); entry != sessions.end();) {
            if ((*entry)->finished.load(std::memory_order_acquire)) {
              finished.push_back(*entry);
              entry = sessions.erase(entry);
            } else {
              ++entry;
            }
          }
        }
        for (const std::shared_ptr<Session>& session : finished) {
          if (session->thread.joinable()) {
            session->thread.join();
          }
        }
      }
    } catch (...) {
    }
  }

  void stop_internal() {
    if (stop.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
    if (listener) {
      listener->close();
    }
    {
      std::lock_guard<std::mutex> guard(sessions_mutex);
      for (const std::shared_ptr<Session>& session : sessions) {
        session->connection->request_stop();
      }
    }
    if (acceptor.joinable()) {
      acceptor.join();
    }
    if (reaper.joinable()) {
      reaper.join();
    }
    std::vector<std::shared_ptr<Session>> remaining;
    {
      std::lock_guard<std::mutex> guard(sessions_mutex);
      remaining.swap(sessions);
    }
    for (const std::shared_ptr<Session>& session : remaining) {
      if (session->thread.joinable()) {
        session->thread.join();
      }
      if (session->has_authority.exchange(false, std::memory_order_acq_rel)) {
        std::size_t demoted = 0;
        registry.fence_publisher(session->publisher, FenceReason::SessionLost, demoted);
        ++fenced_publishers;
      }
    }
    remaining.clear();
    if (!options.state_path.empty()) {
      const Outcome saved = registry.save(options.state_path);
      if (!saved.committed()) {
        ++persist_failures;
        std::fprintf(stderr, "fabric-registry-coordinator: the final durable state was not written: %s: %s\n",
                     std::string(to_string(saved.code)).c_str(), saved.message.c_str());
        std::fflush(stderr);
      }
    }
  }

  std::size_t active_session_count() const {
    std::lock_guard<std::mutex> guard(sessions_mutex);
    return sessions.size();
  }
};

Coordinator::Coordinator() : impl_(std::make_unique<Impl>(CoordinatorOptions{})) {}

std::unique_ptr<Coordinator> Coordinator::start(const CoordinatorOptions& options, std::string& error) {
  const ValidationResult validation = options.validate();
  if (!validation) {
    error = validation.message;
    return nullptr;
  }
  std::unique_ptr<Coordinator> coordinator(new Coordinator());
  try {
    coordinator->impl_ = std::make_unique<Impl>(options);
  } catch (const std::exception& exception) {
    error = std::string("the registry could not be constructed: ") + exception.what();
    return nullptr;
  }
  Impl& impl = *coordinator->impl_;
  if (!options.state_path.empty()) {
    std::error_code exists_error;
    const bool present = std::filesystem::exists(options.state_path, exists_error) && !exists_error;
    if (present) {
      const Outcome loaded = impl.registry.load(options.state_path, impl.recovery);
      if (!loaded.committed()) {
        error = std::string("durable state could not be recovered: ") + std::string(to_string(loaded.code)) + ": " +
                loaded.message;
        return nullptr;
      }
    } else {
      impl.recovery.detail = "no durable state file existed; the registry started empty";
    }
  } else {
    impl.recovery.detail = "no durable state path was configured; the registry started empty";
  }
  std::optional<TcpListener> listener = TcpListener::bind(options.listen, error);
  if (!listener.has_value()) {
    return nullptr;
  }
  impl.listener = std::make_unique<TcpListener>(std::move(*listener));
  impl.acceptor = std::thread([&impl]() { impl.run_acceptor(); });
  impl.reaper = std::thread([&impl]() { impl.run_reaper(); });
  error.clear();
  return coordinator;
}

Coordinator::~Coordinator() {
  if (impl_) {
    impl_->stop_internal();
  }
}

void Coordinator::stop() noexcept {
  if (impl_) {
    impl_->stop_internal();
  }
}

std::uint16_t Coordinator::port() const noexcept {
  return impl_->listener ? impl_->listener->port() : 0;
}

Endpoint Coordinator::endpoint() const { return impl_->listener ? impl_->listener->endpoint() : Endpoint{}; }

RegistryStats Coordinator::stats() const { return impl_->registry.stats(); }

std::size_t Coordinator::active_sessions() const noexcept { return impl_->active_session_count(); }

CoordinatorEpoch Coordinator::epoch() const noexcept { return impl_->registry.epoch(); }

Outcome Coordinator::save_now() {
  if (impl_->options.state_path.empty()) {
    return Outcome(OutcomeCode::TransportFailure, "the coordinator has no durable state path configured");
  }
  return impl_->registry.save(impl_->options.state_path);
}

Outcome Coordinator::reap_expired_publishers() {
  Impl& impl = *impl_;
  const std::int64_t threshold =
      std::chrono::duration_cast<std::chrono::nanoseconds>(impl.options.transport.heartbeat_timeout).count();
  std::vector<PublisherId> expired;
  {
    std::lock_guard<std::mutex> guard(impl.sessions_mutex);
    for (const std::shared_ptr<Impl::Session>& session : impl.sessions) {
      if (session->finished.load(std::memory_order_acquire)) {
        continue;
      }
      if (!session->has_authority.load(std::memory_order_acquire)) {
        continue;
      }
      if (now_ticks() - session->last_activity.load(std::memory_order_relaxed) > threshold) {
        expired.push_back(session->publisher);
      }
    }
  }
  if (expired.empty()) {
    return Outcome(OutcomeCode::NotFound, "no publisher has exceeded the heartbeat timeout");
  }
  Outcome outcome(OutcomeCode::Committed, "expired publishers were fenced");
  for (const PublisherId& publisher : expired) {
    std::size_t demoted = 0;
    const Outcome fenced = impl.registry.fence_publisher(publisher, FenceReason::HeartbeatExpired, demoted);
    if (fenced.committed()) {
      ++impl.fenced_publishers;
      outcome.steps.push_back(ExplanationStep{"reap", "publisher", publisher.to_string(),
                                              "the publisher exceeded the heartbeat timeout and was fenced"});
    }
    impl.persist_if_needed(fenced);
  }
  return outcome;
}

std::uint64_t Coordinator::fenced_publisher_count() const noexcept {
  return impl_->fenced_publishers.load(std::memory_order_relaxed);
}

std::uint64_t Coordinator::persist_failure_count() const noexcept {
  return impl_->persist_failures.load(std::memory_order_relaxed);
}

const RecoveryReport& Coordinator::recovery_report() const noexcept { return impl_->recovery; }

} // namespace fabric_registry
