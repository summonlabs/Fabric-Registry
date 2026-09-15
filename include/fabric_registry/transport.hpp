// Fabric Registry — framed TCP transport.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Shutdown design
// ---------------
// A blocking recv() is never relied upon to wake up when another thread wants to
// stop the connection. Every read goes through a bounded wait on the socket
// (select with the configured poll interval), so a reader always returns within
// one poll interval and re-checks the stop flag. request_stop() additionally
// shuts the socket down so an in-flight wait completes immediately. Either
// mechanism alone would be enough on a well-behaved platform; together they make
// the stop path bounded on every platform, including Windows, where a
// blocked recv() is not reliably woken by shutdown() alone.
//
// Ownership
// ---------
// Socket owns one native handle and closes it exactly once. Connection owns one
// Socket plus its inbound reassembly buffer and is movable but not copyable.
// Nothing in this module starts a thread or invokes a callback.

#ifndef FABRIC_REGISTRY_TRANSPORT_HPP
#define FABRIC_REGISTRY_TRANSPORT_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/export.hpp"
#include "fabric_registry/frame.hpp"
#include "fabric_registry/limits.hpp"

namespace fabric_registry {

/// A TCP endpoint. Only literal IPv4/IPv6 addresses and "localhost" are
/// accepted; the transport never performs a name lookup that could block on an
/// unreachable resolver.
struct FABRIC_REGISTRY_API Endpoint {
  std::string host{"127.0.0.1"};
  std::uint16_t port{0};

  std::string to_string() const;
  /// Parses "host:port" or "[v6]:port". Returns nullopt for malformed text,
  /// for a port above 65535 and for an empty host.
  static std::optional<Endpoint> parse(std::string_view text) noexcept;

  friend bool operator==(const Endpoint&, const Endpoint&) = default;
};

struct TransportConfig {
  /// Maximum frame payload accepted or produced on this connection.
  std::size_t max_payload_bytes{1024 * 1024};
  /// Bounded wait used by every socket read. A reader returns at least this
  /// often so it can observe a stop request.
  std::chrono::milliseconds poll_interval{20};
  /// Bound on establishing a connection.
  std::chrono::milliseconds connect_timeout{5000};
  /// Interval between heartbeat frames emitted by a publisher.
  std::chrono::milliseconds heartbeat_interval{500};
  /// A publisher is considered lost when no frame arrives from it within this
  /// interval.
  std::chrono::milliseconds heartbeat_timeout{5000};

  ValidationResult validate() const;
};

/// RAII owner of one native socket handle.
class FABRIC_REGISTRY_API Socket {
public:
  Socket() noexcept = default;
  ~Socket();
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  bool valid() const noexcept;
  /// Shuts the socket down and closes the handle. Idempotent and safe to call
  /// from any thread.
  void close() noexcept;
  /// Requests a graceful shutdown of both directions without closing.
  void shutdown_both() noexcept;

  std::intptr_t native_handle() const noexcept { return handle_; }

  /// Moves a raw handle into a Socket. Intended for the platform helpers in
  /// this module.
  static Socket adopt(std::intptr_t handle) noexcept;

private:
  static constexpr std::intptr_t kInvalid = -1;
  std::intptr_t handle_{kInvalid};
};

/// Listens on a local endpoint.
class FABRIC_REGISTRY_API TcpListener {
public:
  TcpListener() noexcept = default;
  ~TcpListener();
  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  /// Binds and starts listening. Port 0 selects an ephemeral port, which is
  /// readable afterwards with port(). Only loopback and wildcard hosts are
  /// accepted.
  static std::optional<TcpListener> bind(const Endpoint& endpoint, std::string& error);

  /// Waits at most `wait` for a connection. Returns nullopt on timeout, on a
  /// stop request, or on a transient accept failure that is described in
  /// `error` (which is cleared on a clean timeout).
  std::optional<Socket> accept(std::chrono::milliseconds wait, const std::atomic<bool>& stop, std::string& error) noexcept;

  void close() noexcept;
  bool valid() const noexcept;
  std::uint16_t port() const noexcept { return endpoint_.port; }
  const Endpoint& endpoint() const noexcept { return endpoint_; }

private:
  Socket socket_;
  Endpoint endpoint_;
};

/// Connects to `endpoint`. Returns nullopt and fills `error` on failure.
std::optional<Socket> connect_to(const Endpoint& endpoint, std::chrono::milliseconds timeout, std::string& error);

/// One framed connection.
class FABRIC_REGISTRY_API Connection {
public:
  Connection() noexcept = default;
  Connection(Socket socket, TransportConfig config) noexcept;
  ~Connection();
  Connection(Connection&& other) noexcept;
  Connection& operator=(Connection&& other) noexcept;
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;

  bool valid() const noexcept { return socket_.valid(); }
  void close() noexcept;
  /// Asks the connection to stop and makes any blocked wait return.
  void request_stop() noexcept;
  bool stopped() const noexcept { return stop_.load(std::memory_order_acquire); }

  /// Sends one frame. Returns false and fills `error` on failure.
  bool send(MessageType type, std::uint64_t request_id, std::span<const std::uint8_t> payload, std::string& error);

  /// Receives one frame, waiting at most `wait`. On timeout the status is
  /// NeedMoreData and `error` is cleared. On a transport failure the status is
  /// Malformed and `error` describes it.
  FrameDecodeResult receive(std::chrono::milliseconds wait, std::string& error);

  /// Sends a request and returns the first response frame whose request id
  /// matches. Frames carrying other request ids are skipped up to a bound; a
  /// protocol violation fails the round trip.
  bool round_trip(MessageType type,
                  std::uint64_t request_id,
                  std::span<const std::uint8_t> payload,
                  Frame& response,
                  std::string& error);

  const TransportConfig& config() const noexcept { return config_; }

private:
  Socket socket_;
  TransportConfig config_{};
  std::vector<std::uint8_t> inbound_;
  /// Receive scratch buffer. It belongs to the connection rather than to the
  /// stack so a session thread never needs a large stack.
  std::vector<std::uint8_t> scratch_;
  std::atomic<bool> stop_{false};
};

/// True when the host string denotes the loopback interface or a wildcard bind
/// address.
FABRIC_REGISTRY_API bool is_bindable_host(std::string_view host) noexcept;

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_TRANSPORT_HPP
