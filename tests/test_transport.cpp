// Fabric Registry — framed transport and coordinator lifecycle proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The transport is the component whose correctness depends on the operating
// system's socket lifecycle. Every case below drives real loopback sockets or a
// real Coordinator: endpoint text, configuration validation, listener binding, a
// two-way frame exchange over all 27 message types, out-of-order response
// skipping, the stop path that must wake a blocked reader, peer-close
// reporting, socket churn and repeated coordinator start/stop cycles. Nothing
// is asserted through a renderer: the enumerators, the error text and the exact
// payload bytes are the contract.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/registry_test_support.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::Connection;
using fabric_registry::Coordinator;
using fabric_registry::CoordinatorOptions;
using fabric_registry::Endpoint;
using fabric_registry::Frame;
using fabric_registry::FrameDecodeResult;
using fabric_registry::FrameDecodeStatus;
using fabric_registry::MessageType;
using fabric_registry::Outcome;
using fabric_registry::OutcomeCode;
using fabric_registry::PublisherClient;
using fabric_registry::PublisherClientOptions;
using fabric_registry::RegisterEntityRequest;
using fabric_registry::Registry;
using fabric_registry::Socket;
using fabric_registry::TcpListener;
using fabric_registry::TransportConfig;

/// Bounded waits. Every socket operation below is given a wait it must finish
/// inside, so a regression fails the case instead of hanging the run.
constexpr std::chrono::milliseconds kConnectTimeout{5000};
constexpr std::chrono::milliseconds kAcceptWait{5000};
constexpr std::chrono::milliseconds kReceiveWait{5000};

/// The default configuration with a short poll interval, so a stop request is
/// observed promptly without changing any other bound.
TransportConfig fast_config() {
  TransportConfig config;
  config.poll_interval = std::chrono::milliseconds(10);
  config.connect_timeout = kConnectTimeout;
  return config;
}

/// A connected loopback pair: `server` accepted the connection that `client`
/// opened through connect_to(). Both ends share one transport configuration.
struct LoopbackPair {
  std::optional<TcpListener> listener;
  std::optional<Connection> server;
  std::optional<Connection> client;
};

/// Binds an ephemeral loopback listener, connects to it and accepts. The pair
/// is complete only when both ends exist; `error` describes the first failure.
LoopbackPair open_loopback_pair(const TransportConfig& config, std::string& error) {
  LoopbackPair pair;
  pair.listener = TcpListener::bind(Endpoint{"127.0.0.1", std::uint16_t{0}}, error);
  if (!pair.listener.has_value()) {
    return pair;
  }
  std::optional<Socket> pending =
      connect_to(Endpoint{"127.0.0.1", pair.listener->port()}, config.connect_timeout, error);
  if (!pending.has_value()) {
    return pair;
  }
  std::atomic<bool> stop{false};
  std::optional<Socket> accepted = pair.listener->accept(kAcceptWait, stop, error);
  if (!accepted.has_value()) {
    return pair;
  }
  pair.client.emplace(std::move(*pending), config);
  pair.server.emplace(std::move(*accepted), config);
  return pair;
}

/// A registration request whose authority is stamped by the publisher client.
/// The same shape is used for the in-process coordinator registrations.
RegisterEntityRequest client_request(const std::string& label, const std::string& serial,
                                     const std::string& derivation_namespace) {
  RegisterEntityRequest request;
  request.attempt = frtest::attempt_from(label);
  request.entity_class = fabric_registry::EntityClass::Switch;
  request.derivation_namespace = derivation_namespace;
  request.friendly_name = label;
  request.facts = {frtest::serial_fact(serial)};
  request.provenance = frtest::real_provenance();
  request.evidence_class = fabric_registry::EvidenceClass::DurableAuthority;
  request.admission = fabric_registry::AdmissionMode::RequireCurrent;
  return request;
}

std::vector<std::uint8_t> load_bytes(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    return {};
  }
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size), 0);
  stream.seekg(0, std::ios::beg);
  if (!bytes.empty()) {
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
      return {};
    }
  }
  return bytes;
}

void store_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!bytes.empty()) {
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  }
}

std::string type_name(MessageType type) { return std::string(fabric_registry::to_string(type)); }

std::string status_name(FrameDecodeStatus status) {
  return std::string(fabric_registry::to_string(status));
}

/// A deterministic payload that differs per message type and length.
std::vector<std::uint8_t> patterned_payload(std::uint16_t raw, std::size_t length, std::size_t salt) {
  std::vector<std::uint8_t> payload(length, 0);
  for (std::size_t index = 0; index < payload.size(); ++index) {
    payload[index] = static_cast<std::uint8_t>((static_cast<std::size_t>(raw) * salt + index) & 0xFFu);
  }
  return payload;
}

}  // namespace

// ---------------------------------------------------------------------------
// Endpoint text
// ---------------------------------------------------------------------------

FR_TEST_CASE(transport, endpoint_parse_round_trips_and_rejects_malformed_text) {
  const std::optional<Endpoint> ipv4 = Endpoint::parse("127.0.0.1:8080");
  FR_CHECK_MSG(ipv4.has_value(), "'127.0.0.1:8080' did not parse");
  FR_CHECK_EQ(ipv4->host, std::string("127.0.0.1"));
  FR_CHECK_EQ(ipv4->port, std::uint16_t{8080});
  FR_CHECK_EQ(ipv4->to_string(), std::string("127.0.0.1:8080"));
  FR_CHECK_EQ(Endpoint::parse(ipv4->to_string()), ipv4);

  const std::optional<Endpoint> ipv6 = Endpoint::parse("[::1]:443");
  FR_CHECK_MSG(ipv6.has_value(), "'[::1]:443' did not parse");
  FR_CHECK_EQ(ipv6->host, std::string("::1"));
  FR_CHECK_EQ(ipv6->port, std::uint16_t{443});
  FR_CHECK_EQ(ipv6->to_string(), std::string("[::1]:443"));
  FR_CHECK_EQ(Endpoint::parse(ipv6->to_string()), ipv6);

  // The highest legal port is accepted; one above it is not.
  const std::optional<Endpoint> highest = Endpoint::parse("127.0.0.1:65535");
  FR_CHECK_MSG(highest.has_value(), "'127.0.0.1:65535' did not parse");
  FR_CHECK_EQ(highest->port, std::uint16_t{65535});

  constexpr std::string_view kMalformed[] = {":80",           "127.0.0.1:",     "127.0.0.1:65536",
                                             "127.0.0.1:80:90", "[::1]443",      "", "::1:80",
                                             "127.0.0.1:abc"};
  for (const std::string_view text : kMalformed) {
    FR_CHECK_MSG(!Endpoint::parse(text).has_value(),
                 "malformed endpoint text was accepted: \"" + std::string(text) + "\"");
  }
}

FR_TEST_CASE(transport, endpoint_to_string_brackets_ipv6_hosts_only) {
  const Endpoint ipv6_loopback{"::1", std::uint16_t{443}};
  FR_CHECK_EQ(ipv6_loopback.to_string(), std::string("[::1]:443"));
  const Endpoint ipv6_wildcard{"::", std::uint16_t{0}};
  FR_CHECK_EQ(ipv6_wildcard.to_string(), std::string("[::]:0"));
  const Endpoint ipv4_loopback{"127.0.0.1", std::uint16_t{8080}};
  FR_CHECK_EQ(ipv4_loopback.to_string(), std::string("127.0.0.1:8080"));
  const Endpoint ipv4_wildcard{"0.0.0.0", std::uint16_t{9000}};
  FR_CHECK_EQ(ipv4_wildcard.to_string(), std::string("0.0.0.0:9000"));

  const Endpoint ipv4_ephemeral{"127.0.0.1", std::uint16_t{1}};
  const std::string rendered = ipv4_ephemeral.to_string();
  FR_CHECK_MSG(rendered.find('[') == std::string::npos, "an IPv4 host was bracketed: " + rendered);
}

FR_TEST_CASE(transport, is_bindable_host_accepts_loopback_and_wildcard_hosts_only) {
  constexpr std::string_view kBindable[] = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::", ""};
  for (const std::string_view host : kBindable) {
    FR_CHECK_MSG(fabric_registry::is_bindable_host(host),
                 "a bindable host was rejected: \"" + std::string(host) + "\"");
  }
  constexpr std::string_view kRejected[] = {"example.com", "not a host"};
  for (const std::string_view host : kRejected) {
    FR_CHECK_MSG(!fabric_registry::is_bindable_host(host),
                 "a non-bindable host was accepted: \"" + std::string(host) + "\"");
  }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

FR_TEST_CASE(transport, transport_config_validation_names_every_rejected_field) {
  FR_CHECK_MSG(TransportConfig{}.validate().ok, "the default transport configuration was rejected");

  // Returns an empty string when the configuration is rejected and the message
  // names the field; otherwise it returns the problem to report.
  const auto rejected_field = [](const TransportConfig& config, const char* field) {
    const fabric_registry::ValidationResult result = config.validate();
    if (result.ok) {
      return std::string("a configuration that must be rejected was accepted: ") + field;
    }
    if (result.message.find(field) == std::string::npos) {
      return std::string("the rejection message does not name ") + field + ": " + result.message;
    }
    return std::string();
  };

  {
    TransportConfig config;
    config.poll_interval = std::chrono::milliseconds(0);
    const std::string problem = rejected_field(config, "poll_interval");
    FR_CHECK_MSG(problem.empty(), problem);
  }
  {
    TransportConfig config;
    config.connect_timeout = std::chrono::milliseconds(0);
    const std::string problem = rejected_field(config, "connect_timeout");
    FR_CHECK_MSG(problem.empty(), problem);
  }
  {
    TransportConfig config;
    config.heartbeat_interval = std::chrono::milliseconds(0);
    const std::string problem = rejected_field(config, "heartbeat_interval");
    FR_CHECK_MSG(problem.empty(), problem);
  }
  {
    TransportConfig config;
    config.heartbeat_timeout = std::chrono::milliseconds(0);
    const std::string problem = rejected_field(config, "heartbeat_timeout");
    FR_CHECK_MSG(problem.empty(), problem);
  }
  {
    TransportConfig config;
    config.max_payload_bytes = 63;
    const std::string problem = rejected_field(config, "max_payload_bytes");
    FR_CHECK_MSG(problem.empty(), problem);
  }
  {
    TransportConfig config;
    config.max_payload_bytes = fabric_registry::hard_limits::kMaxFramePayloadBytes + 1;
    const std::string problem = rejected_field(config, "max_payload_bytes");
    FR_CHECK_MSG(problem.empty(), problem);
  }

  // The two ends of the accepted payload range stay accepted.
  {
    TransportConfig config;
    config.max_payload_bytes = 64;
    FR_CHECK_MSG(config.validate().ok, "the smallest legal payload bound was rejected");
    config.max_payload_bytes = fabric_registry::hard_limits::kMaxFramePayloadBytes;
    FR_CHECK_MSG(config.validate().ok, "the largest legal payload bound was rejected");
  }
}

// ---------------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------------

FR_TEST_CASE(transport, listener_bind_reports_a_real_port_and_rejects_a_non_bindable_host) {
  std::string error;
  std::optional<TcpListener> first = TcpListener::bind(Endpoint{"127.0.0.1", std::uint16_t{0}}, error);
  FR_CHECK_MSG(first.has_value(), "the first listener did not bind: " + error);
  FR_CHECK_MSG(first->valid(), "a bound listener does not report itself valid");
  FR_CHECK_MSG(first->port() != 0, "binding port 0 did not report a real ephemeral port");
  FR_CHECK_EQ(first->endpoint().port, first->port());
  FR_CHECK_EQ(first->endpoint().host, std::string("127.0.0.1"));

  std::optional<TcpListener> second = TcpListener::bind(Endpoint{"127.0.0.1", std::uint16_t{0}}, error);
  FR_CHECK_MSG(second.has_value(), "the second listener did not bind: " + error);
  FR_CHECK_MSG(second->port() != 0, "the second listener reported port zero");
  FR_CHECK_MSG(first->port() != second->port(),
               "two listeners bound at once reported the same port " + std::to_string(first->port()));

  for (const std::string_view host : {std::string_view("example.com"), std::string_view("not a host")}) {
    std::string host_error;
    const std::optional<TcpListener> refused =
        TcpListener::bind(Endpoint{std::string(host), std::uint16_t{0}}, host_error);
    FR_CHECK_MSG(!refused.has_value(),
                 "a listener bound to the non-bindable host \"" + std::string(host) + "\"");
    FR_CHECK_MSG(!host_error.empty(),
                 "a refused bind reported no error for \"" + std::string(host) + "\"");
    FR_CHECK_MSG(host_error.find("host") != std::string::npos,
                 "the refusal does not name the host: " + host_error);
  }

  first->close();
  second->close();
  FR_CHECK_MSG(!first->valid() && !second->valid(), "a closed listener still reports itself valid");
}

// ---------------------------------------------------------------------------
// Frames over a real loopback connection
// ---------------------------------------------------------------------------

FR_TEST_CASE(transport, every_message_type_round_trips_over_loopback_in_both_directions) {
  const TransportConfig config = fast_config();
  std::string error;
  LoopbackPair pair = open_loopback_pair(config, error);
  FR_CHECK_MSG(pair.server.has_value() && pair.client.has_value(),
               "the loopback pair was not established: " + error);
  Connection& client = *pair.client;
  Connection& server = *pair.server;

  for (std::uint16_t raw = 1; raw <= fabric_registry::kMessageTypeCount; ++raw) {
    const MessageType type = static_cast<MessageType>(raw);
    const std::uint64_t request_id = 1000u + raw;
    const std::vector<std::uint8_t> payload = patterned_payload(raw, static_cast<std::size_t>(raw) * 5u + 1u, 7u);
    FR_CHECK_MSG(client.send(type, request_id, payload, error),
                 "the client could not send " + type_name(type) + ": " + error);

    const FrameDecodeResult received = server.receive(kReceiveWait, error);
    FR_CHECK_MSG(received.status == FrameDecodeStatus::Complete,
                 "the server did not receive " + type_name(type) + ": " + status_name(received.status) + ": " + error);
    FR_CHECK_EQ(received.frame.type, type);
    FR_CHECK_EQ(received.frame.request_id, request_id);
    FR_CHECK_EQ(received.frame.flags, std::uint32_t{0});
    FR_CHECK_MSG(received.frame.payload == payload, "the payload of " + type_name(type) + " changed in transit");
  }

  for (std::uint16_t raw = 1; raw <= fabric_registry::kMessageTypeCount; ++raw) {
    const MessageType type = static_cast<MessageType>(raw);
    const std::uint64_t request_id = 5000u + raw;
    const std::vector<std::uint8_t> payload = patterned_payload(raw, static_cast<std::size_t>(raw) * 3u + 2u, 11u);
    FR_CHECK_MSG(server.send(type, request_id, payload, error),
                 "the server could not send " + type_name(type) + ": " + error);

    const FrameDecodeResult received = client.receive(kReceiveWait, error);
    FR_CHECK_MSG(received.status == FrameDecodeStatus::Complete,
                 "the client did not receive " + type_name(type) + ": " + status_name(received.status) + ": " + error);
    FR_CHECK_EQ(received.frame.type, type);
    FR_CHECK_EQ(received.frame.request_id, request_id);
    FR_CHECK_EQ(received.frame.flags, std::uint32_t{0});
    FR_CHECK_MSG(received.frame.payload == payload, "the payload of " + type_name(type) + " changed in transit");
  }
}

FR_TEST_CASE(transport, round_trip_skips_a_frame_with_a_different_request_id) {
  const TransportConfig config = fast_config();
  std::string error;
  LoopbackPair pair = open_loopback_pair(config, error);
  FR_CHECK_MSG(pair.server.has_value() && pair.client.has_value(),
               "the loopback pair was not established: " + error);
  Connection& client = *pair.client;
  Connection& server = *pair.server;

  // Two frames are already waiting when the round trip starts: one belonging to
  // another request, then the answer to the request the round trip will send.
  const std::vector<std::uint8_t> out_of_order{1, 2, 3, 4};
  FR_CHECK_MSG(server.send(MessageType::Heartbeat, 4242, out_of_order, error),
               "the server could not send the out-of-order frame: " + error);
  const std::vector<std::uint8_t> answer{9, 8, 7, 6, 5};
  FR_CHECK_MSG(server.send(MessageType::HeartbeatAck, 7, answer, error),
               "the server could not send the matching answer: " + error);

  const std::vector<std::uint8_t> request_payload{42, 43};
  Frame response;
  FR_CHECK_MSG(client.round_trip(MessageType::Hello, 7, request_payload, response, error),
               "the round trip failed: " + error);
  FR_CHECK_EQ(response.type, MessageType::HeartbeatAck);
  FR_CHECK_EQ(response.request_id, std::uint64_t{7});
  FR_CHECK_MSG(response.payload == answer, "the round trip returned the wrong payload");

  // The skipped frame was consumed exactly once and the request the round trip
  // sent is intact on the peer.
  const FrameDecodeResult received = server.receive(kReceiveWait, error);
  FR_CHECK_MSG(received.status == FrameDecodeStatus::Complete,
               "the request frame did not arrive: " + status_name(received.status) + ": " + error);
  FR_CHECK_EQ(received.frame.type, MessageType::Hello);
  FR_CHECK_EQ(received.frame.request_id, std::uint64_t{7});
  FR_CHECK_MSG(received.frame.payload == request_payload, "the request payload changed in transit");
}

// ---------------------------------------------------------------------------
// Stop and failure paths
// ---------------------------------------------------------------------------

FR_TEST_CASE(transport, request_stop_wakes_a_blocked_receive_with_stopped) {
  const TransportConfig config = fast_config();
  std::string error;
  LoopbackPair pair = open_loopback_pair(config, error);
  FR_CHECK_MSG(pair.server.has_value() && pair.client.has_value(),
               "the loopback pair was not established: " + error);
  Connection& server = *pair.server;

  // A wait far longer than the test's patience: only the stop request can end
  // this receive. The reader is joined unconditionally, so a regression hangs
  // here instead of passing under a watchdog.
  const std::chrono::milliseconds wait{60000};
  std::atomic<bool> entered{false};
  FrameDecodeStatus status = FrameDecodeStatus::Complete;
  std::string thread_error;
  std::chrono::milliseconds elapsed{0};
  std::thread reader([&server, wait, &entered, &status, &thread_error, &elapsed]() {
    entered.store(true, std::memory_order_release);
    const auto start = std::chrono::steady_clock::now();
    const FrameDecodeResult result = server.receive(wait, thread_error);
    elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    status = result.status;
  });

  while (!entered.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  server.request_stop();
  reader.join();

  FR_CHECK_MSG(server.stopped(), "request_stop did not record the stop on the connection");
  FR_CHECK_EQ(status, FrameDecodeStatus::NeedMoreData);
  FR_CHECK_EQ(thread_error, std::string("stopped"));
  FR_CHECK_MSG(elapsed < std::chrono::seconds(5),
               "the stopped receive did not return promptly: " + std::to_string(elapsed.count()) + " ms");
}

FR_TEST_CASE(transport, a_peer_close_is_reported_as_malformed_naming_the_peer_close) {
  const TransportConfig config = fast_config();
  std::string error;
  LoopbackPair pair = open_loopback_pair(config, error);
  FR_CHECK_MSG(pair.server.has_value() && pair.client.has_value(),
               "the loopback pair was not established: " + error);
  Connection& client = *pair.client;
  Connection& server = *pair.server;

  client.close();
  FR_CHECK_MSG(!client.valid(), "a closed connection still reports itself valid");

  const FrameDecodeResult result = server.receive(kReceiveWait, error);
  FR_CHECK_EQ(result.status, FrameDecodeStatus::Malformed);
  FR_CHECK_MSG(!error.empty(), "a peer close produced no diagnostic");
  FR_CHECK_MSG(error.find("peer") != std::string::npos, "the diagnostic does not name the peer: " + error);
  FR_CHECK_MSG(error.find("closed") != std::string::npos, "the diagnostic does not name the close: " + error);
  FR_CHECK_MSG(error == result.detail, "the returned error and the decode detail disagree: " + result.detail);
}

// ---------------------------------------------------------------------------
// Endurance
// ---------------------------------------------------------------------------

FR_TEST_CASE(transport, two_hundred_create_connect_stop_close_cycles_complete) {
  const TransportConfig config = fast_config();
  int completed = 0;
  for (int cycle = 0; cycle < 200; ++cycle) {
    const std::string label = "cycle-" + std::to_string(cycle);
    std::string error;
    std::optional<TcpListener> listener = TcpListener::bind(Endpoint{"127.0.0.1", std::uint16_t{0}}, error);
    FR_CHECK_MSG(listener.has_value(), label + ": the listener did not bind: " + error);
    std::optional<Socket> pending =
        connect_to(Endpoint{"127.0.0.1", listener->port()}, config.connect_timeout, error);
    FR_CHECK_MSG(pending.has_value(), label + ": the connect failed: " + error);
    std::atomic<bool> stop{false};
    std::optional<Socket> accepted = listener->accept(kAcceptWait, stop, error);
    FR_CHECK_MSG(accepted.has_value(), label + ": the accept failed: " + error);

    Connection client(std::move(*pending), config);
    Connection server(std::move(*accepted), config);
    client.request_stop();
    server.request_stop();
    FR_CHECK_MSG(client.stopped() && server.stopped(), label + ": a stop request was not recorded");
    client.close();
    server.close();
    listener->close();
    FR_CHECK_MSG(!client.valid() && !server.valid() && !listener->valid(),
                 label + ": a socket survived its close");
    ++completed;
  }
  FR_CHECK_EQ(completed, 200);
}

FR_TEST_CASE(transport, twenty_five_coordinator_start_stop_iterations_serve_a_registration) {
  for (int iteration = 0; iteration < 25; ++iteration) {
    const std::string label = "transport-iteration-" + std::to_string(iteration);
    const std::filesystem::path state = frtest::temporary_state_path(label);
    frtest::remove_state(state);

    CoordinatorOptions options;
    options.listen = Endpoint{"127.0.0.1", std::uint16_t{0}};
    options.state_path = state;
    options.registry = frtest::test_options(static_cast<std::uint64_t>(200 + iteration));
    options.transport.poll_interval = std::chrono::milliseconds(5);

    std::string error;
    std::unique_ptr<Coordinator> coordinator = Coordinator::start(options, error);
    FR_CHECK_MSG(coordinator != nullptr, label + ": the coordinator did not start: " + error);

    PublisherClientOptions client_options;
    client_options.coordinator = coordinator->endpoint();
    client_options.name = label;
    client_options.transport.poll_interval = std::chrono::milliseconds(5);
    std::unique_ptr<PublisherClient> client = PublisherClient::connect(client_options, error);
    FR_CHECK_MSG(client != nullptr, label + ": the publisher did not attach: " + error);
    FR_CHECK_MSG(client->authority().is_complete(), label + ": the attached publisher holds no complete claim");

    const fabric_registry::RemoteOutcome remote =
        client->register_entity(client_request(label, "TRANSPORT-SERIAL-" + std::to_string(iteration),
                                               "test/transport"));
    FR_CHECK_MSG(remote.outcome.committed(), label + ": the registration was not committed: " +
                                                  std::string(fabric_registry::to_string(remote.outcome.code)));
    FR_CHECK_MSG(client->detach().succeeded(), label + ": the publisher did not detach cleanly");

    coordinator->stop();
    FR_CHECK_MSG(coordinator->active_sessions() == 0, label + ": a session survived the stop");
    FR_CHECK_MSG(coordinator->persist_failure_count() == 0, label + ": a durable state write failed");
    frtest::remove_state(state);
  }
}

FR_TEST_CASE(transport, twenty_five_bind_and_stop_cycles_without_a_client_always_start) {
  int started = 0;
  for (int iteration = 0; iteration < 25; ++iteration) {
    const std::string label = "bind-only-" + std::to_string(iteration);
    CoordinatorOptions options;
    options.listen = Endpoint{"127.0.0.1", std::uint16_t{0}};
    options.registry = frtest::test_options(static_cast<std::uint64_t>(300 + iteration));
    options.transport.poll_interval = std::chrono::milliseconds(5);

    std::string error;
    std::unique_ptr<Coordinator> coordinator = Coordinator::start(options, error);
    FR_CHECK_MSG(coordinator != nullptr, label + ": the coordinator did not start: " + error);
    FR_CHECK_MSG(coordinator->port() != 0, label + ": the bound port was not reported");
    FR_CHECK_EQ(coordinator->active_sessions(), std::size_t{0});
    coordinator->stop();
    FR_CHECK_MSG(coordinator->active_sessions() == 0, label + ": a session survived the stop");
    ++started;
  }
  FR_CHECK_EQ(started, 25);
}

FR_TEST_CASE(transport, a_coordinator_refuses_a_corrupt_state_file_and_starts_empty_without_one) {
  const std::filesystem::path corrupt = frtest::temporary_state_path("transport-corrupt");
  frtest::remove_state(corrupt);
  {
    std::unique_ptr<Registry> registry = frtest::make_registry(320);
    const Outcome stored = registry->register_entity(
        frtest::device_request(*registry, "transport-corrupt-source", "TRANSPORT-CORRUPT-SERIAL"));
    FR_CHECK_MSG(stored.committed(), "the seed registration was not committed");
    FR_CHECK_EQ(registry->save(corrupt).code, OutcomeCode::Committed);
  }

  std::vector<std::uint8_t> image = load_bytes(corrupt);
  FR_CHECK_MSG(image.size() > fabric_registry::persistence::kHeaderBytes + 8,
               "the written state image is too small to corrupt");
  image[fabric_registry::persistence::kHeaderBytes + 8] =
      static_cast<std::uint8_t>(image[fabric_registry::persistence::kHeaderBytes + 8] ^ 0x5Au);
  store_bytes(corrupt, image);

  CoordinatorOptions options;
  options.listen = Endpoint{"127.0.0.1", std::uint16_t{0}};
  options.state_path = corrupt;
  std::string error;
  std::unique_ptr<Coordinator> refused = Coordinator::start(options, error);
  FR_CHECK_MSG(refused == nullptr, "the coordinator started on a corrupt state file");
  FR_CHECK_MSG(!error.empty(), "the refusal carried no diagnostic");
  FR_CHECK_MSG(error.find("integrity-failure") != std::string::npos,
               "the refusal did not name the integrity failure: " + error);

  // Control: a state path with no file is not corruption. The registry starts
  // empty and says so.
  const std::filesystem::path absent = corrupt.parent_path() / "transport-absent-state.bin";
  frtest::remove_state(absent);
  CoordinatorOptions fresh_options = options;
  fresh_options.state_path = absent;
  std::unique_ptr<Coordinator> fresh = Coordinator::start(fresh_options, error);
  FR_CHECK_MSG(fresh != nullptr, "the coordinator refused to start without a state file: " + error);
  FR_CHECK_EQ(fresh->stats().entities, std::size_t{0});
  FR_CHECK_MSG(fresh->recovery_report().detail.find("empty") != std::string::npos,
               "a coordinator with no state file did not report an empty start: " +
                   fresh->recovery_report().detail);
  fresh->stop();
  FR_CHECK_EQ(fresh->active_sessions(), std::size_t{0});

  frtest::remove_state(absent);
  frtest::remove_state(corrupt);
}
