// Fabric Registry — the publisher (worker) client.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// One PublisherClient owns one connection and one worker incarnation. Requests
// are serialised: a client sends one request and waits for its response, so the
// response stream can never be mis-associated. Frames carrying a different
// request id are skipped by Connection::round_trip up to a documented bound.

#include "fabric_registry/publisher.hpp"

#include <chrono>
#include <mutex>
#include <span>
#include <utility>

#include "fabric_registry/codec.hpp"
#include "fabric_registry/version.hpp"

namespace fabric_registry {

struct PublisherClient::Impl {
  PublisherClientOptions options;
  std::unique_ptr<Connection> connection;
  AuthorityClaim claim;
  std::uint64_t next_request{1};
  std::mutex mutex;
  bool open{false};

  explicit Impl(const PublisherClientOptions& options_in) : options(options_in) {}

  std::uint64_t take_request_id() { return next_request++; }

  bool exchange(MessageType type, std::uint64_t request_id, std::span<const std::uint8_t> payload, Frame& response,
                std::string& error) {
    if (!connection || !connection->valid()) {
      error = "the publisher is not connected";
      return false;
    }
    return connection->round_trip(type, request_id, payload, response, error);
  }

  RemoteOutcome perform(MessageType type, const std::vector<std::uint8_t>& payload) {
    RemoteOutcome result;
    const auto started = std::chrono::steady_clock::now();
    Frame response;
    std::string error;
    const std::uint64_t request_id = take_request_id();
    if (!exchange(type, request_id, payload, response, error)) {
      result.outcome = Outcome(OutcomeCode::TransportFailure, "the request could not be completed: " + error);
      return result;
    }
    result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    if (response.type == MessageType::Error) {
      ErrorPayload payload_out;
      if (!decode_error(response.payload, payload_out, error)) {
        result.outcome = Outcome(OutcomeCode::ProtocolViolation, "the server returned an undecodable error frame");
        return result;
      }
      result.outcome = Outcome(payload_out.code, payload_out.message);
      return result;
    }
    if (response.type != MessageType::OperationAck) {
      result.outcome = Outcome(OutcomeCode::ProtocolViolation, "the server returned an unexpected message type");
      return result;
    }
    if (!decode_outcome(response.payload, result.outcome, error)) {
      result.outcome = Outcome(OutcomeCode::ProtocolViolation, "the server returned an undecodable outcome: " + error);
    }
    return result;
  }
};

PublisherClient::PublisherClient() : impl_(std::make_unique<Impl>(PublisherClientOptions{})) {}

PublisherClient::~PublisherClient() {
  if (impl_) {
    close();
  }
}

std::unique_ptr<PublisherClient> PublisherClient::connect(const PublisherClientOptions& options, std::string& error) {
  const ValidationResult validation = options.transport.validate();
  if (!validation) {
    error = validation.message;
    return nullptr;
  }
  if (!is_bindable_host(options.coordinator.host)) {
    error = "the coordinator address is not a usable address";
    return nullptr;
  }
  if (options.name.size() > kIdentityValueHardLimit) {
    error = "the publisher name exceeds the hard string bound";
    return nullptr;
  }
  std::unique_ptr<PublisherClient> client(new PublisherClient());
  client->impl_ = std::make_unique<Impl>(options);

  std::optional<Socket> socket = connect_to(options.coordinator, options.transport.connect_timeout, error);
  if (!socket.has_value()) {
    return nullptr;
  }
  client->impl_->connection = std::make_unique<Connection>(std::move(*socket), options.transport);

  HelloRequest hello;
  hello.protocol_version = protocol_version();
  hello.client_name = options.name;
  Frame response;
  const std::uint64_t hello_request = client->impl_->take_request_id();
  if (!client->impl_->exchange(MessageType::Hello, hello_request, encode_hello_request(hello), response, error)) {
    client->impl_->connection->close();
    return nullptr;
  }
  if (response.type != MessageType::HelloAck) {
    error = "the coordinator did not answer the hello handshake";
    client->impl_->connection->close();
    return nullptr;
  }
  HelloResponse hello_response;
  if (!decode_hello_response(response.payload, hello_response, error)) {
    client->impl_->connection->close();
    return nullptr;
  }
  if (!hello_response.accepted) {
    error = hello_response.reason.empty() ? "the coordinator rejected the handshake" : hello_response.reason;
    client->impl_->connection->close();
    return nullptr;
  }

  PublisherAttachRequest attach;
  attach.publisher = options.publisher;
  attach.name = options.name;
  attach.protocol_version = protocol_version();
  Frame attach_response;
  const std::uint64_t attach_request = client->impl_->take_request_id();
  if (!client->impl_->exchange(MessageType::AttachPublisher, attach_request, encode_attach_request(attach),
                               attach_response, error)) {
    client->impl_->connection->close();
    return nullptr;
  }
  if (attach_response.type != MessageType::AttachPublisherAck) {
    error = "the coordinator did not answer the attach request";
    client->impl_->connection->close();
    return nullptr;
  }
  PublisherAttachResult attach_result;
  if (!decode_attach_response(attach_response.payload, attach_result, error)) {
    client->impl_->connection->close();
    return nullptr;
  }
  if (!attach_result.outcome.committed()) {
    error = std::string("the coordinator refused the attach: ") + std::string(to_string(attach_result.outcome.code)) +
            ": " + attach_result.outcome.message;
    client->impl_->connection->close();
    return nullptr;
  }
  client->impl_->claim.publisher = attach_result.publisher;
  client->impl_->claim.worker_boot = attach_result.worker_boot;
  client->impl_->claim.epoch = attach_result.epoch;
  client->impl_->open = true;
  error.clear();
  return client;
}

const AuthorityClaim& PublisherClient::authority() const noexcept { return impl_->claim; }

CoordinatorEpoch PublisherClient::coordinator_epoch() const noexcept { return impl_->claim.epoch; }

bool PublisherClient::heartbeat(std::string& error) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Frame response;
  const std::uint64_t request_id = impl_->take_request_id();
  if (!impl_->exchange(MessageType::Heartbeat, request_id, std::span<const std::uint8_t>{}, response, error)) {
    return false;
  }
  if (response.type != MessageType::HeartbeatAck) {
    error = "the coordinator did not acknowledge the heartbeat";
    return false;
  }
  ByteReader reader(response.payload);
  std::uint64_t epoch = 0;
  if (!reader.u64(epoch) || !reader.at_end()) {
    error = "the heartbeat acknowledgement is malformed";
    return false;
  }
  impl_->claim.epoch = CoordinatorEpoch(epoch);
  return true;
}

RemoteOutcome PublisherClient::register_entity(RegisterEntityRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_register_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::RegisterEntity, payload);
}

RemoteOutcome PublisherClient::update_evidence(UpdateEvidenceRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_update_evidence_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::UpdateEvidence, payload);
}

RemoteOutcome PublisherClient::attach_alias(AliasMutationRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_alias_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::AttachAlias, payload);
}

RemoteOutcome PublisherClient::detach_alias(AliasMutationRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_alias_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::DetachAlias, payload);
}

RemoteOutcome PublisherClient::supersede_entity(SupersedeEntityRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_supersede_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::SupersedeEntity, payload);
}

RemoteOutcome PublisherClient::retire_entity(RetireEntityRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_retire_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::RetireEntity, payload);
}

RemoteOutcome PublisherClient::tombstone_entity(TombstoneEntityRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_tombstone_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::TombstoneEntity, payload);
}

RemoteOutcome PublisherClient::revalidate_entity(RevalidateEntityRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_revalidate_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::RevalidateEntity, payload);
}

RemoteOutcome PublisherClient::resolve_conflict(ResolveConflictRequest request) {
  request.authority = impl_->claim;
  const std::vector<std::uint8_t> payload = encode_resolve_conflict_request(request);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->perform(MessageType::ResolveConflict, payload);
}

bool PublisherClient::reconcile_observation(ReconcileObservationRequest request, ReconcileResult& out,
                                            std::string& error) {
  request.authority = impl_->claim;
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Frame response;
  const std::uint64_t request_id = impl_->take_request_id();
  if (!impl_->exchange(MessageType::ReconcileObservation, request_id, encode_reconcile_request(request), response,
                       error)) {
    return false;
  }
  if (response.type == MessageType::Error) {
    ErrorPayload payload;
    if (!decode_error(response.payload, payload, error)) {
      return false;
    }
    out.outcome = Outcome(payload.code, payload.message);
    return true;
  }
  if (response.type != MessageType::ReconcileAck) {
    error = "the coordinator returned an unexpected message type for a reconciliation";
    return false;
  }
  ByteReader reader(response.payload);
  std::vector<std::uint8_t> outcome_bytes;
  std::vector<std::uint8_t> detail_bytes;
  if (!reader.blob(outcome_bytes, 1u << 20) || !reader.blob(detail_bytes, 1u << 20) || !reader.at_end()) {
    error = "the reconciliation response is malformed";
    return false;
  }
  if (!decode_outcome(outcome_bytes, out.outcome, error)) {
    return false;
  }
  return decode_reconcile_detail(detail_bytes, out.detail, error);
}

bool PublisherClient::lookup(const CanonicalId& target, Outcome& outcome, std::shared_ptr<const EntityRecord>& record,
                             std::string& error) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  LookupRequest request;
  request.target = target;
  Frame response;
  const std::uint64_t request_id = impl_->take_request_id();
  if (!impl_->exchange(MessageType::LookupEntity, request_id, encode_lookup_request(request), response, error)) {
    return false;
  }
  if (response.type == MessageType::Error) {
    ErrorPayload payload;
    if (!decode_error(response.payload, payload, error)) {
      return false;
    }
    outcome = Outcome(payload.code, payload.message);
    return true;
  }
  if (response.type != MessageType::LookupAck) {
    error = "the coordinator returned an unexpected message type for a lookup";
    return false;
  }
  return decode_lookup_response(response.payload, outcome, record, error);
}

bool PublisherClient::snapshot_summary(SnapshotSummary& out, std::string& error) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Frame response;
  const std::uint64_t request_id = impl_->take_request_id();
  if (!impl_->exchange(MessageType::SnapshotRequest, request_id, std::span<const std::uint8_t>{}, response, error)) {
    return false;
  }
  if (response.type != MessageType::SnapshotAck) {
    error = "the coordinator did not return a snapshot summary";
    return false;
  }
  return decode_snapshot_summary(response.payload, out, error);
}

bool PublisherClient::statistics(StatsPayload& out, std::string& error) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Frame response;
  const std::uint64_t request_id = impl_->take_request_id();
  if (!impl_->exchange(MessageType::StatsRequest, request_id, std::span<const std::uint8_t>{}, response, error)) {
    return false;
  }
  if (response.type != MessageType::StatsAck) {
    error = "the coordinator did not return statistics";
    return false;
  }
  return decode_stats(response.payload, out, error);
}

Outcome PublisherClient::detach() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!impl_->open || !impl_->connection) {
    return Outcome(OutcomeCode::Idempotent, "the publisher is already detached");
  }
  Frame response;
  std::string error;
  const std::uint64_t request_id = impl_->take_request_id();
  Outcome outcome(OutcomeCode::Committed, "the publisher detached");
  if (impl_->exchange(MessageType::DetachPublisher, request_id,
                      encode_detach_request(impl_->claim, FenceReason::ExplicitDetach), response, error)) {
    if (response.type == MessageType::OperationAck) {
      decode_outcome(response.payload, outcome, error);
    } else if (response.type == MessageType::Error) {
      ErrorPayload payload;
      if (decode_error(response.payload, payload, error)) {
        outcome = Outcome(payload.code, payload.message);
      }
    }
  } else {
    outcome = Outcome(OutcomeCode::TransportFailure, "the detach request could not be delivered: " + error);
  }
  impl_->open = false;
  impl_->connection->close();
  return outcome;
}

void PublisherClient::close() noexcept {
  if (!impl_) {
    return;
  }
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (impl_->connection) {
    impl_->connection->request_stop();
    impl_->connection->close();
  }
  impl_->open = false;
}

bool PublisherClient::connected() const noexcept {
  return impl_->connection != nullptr && impl_->connection->valid();
}

} // namespace fabric_registry
