// Fabric Registry — framed TCP transport.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every native handle is owned by exactly one Socket object and is closed
// exactly once. Every wait on a socket is bounded by select(), so a reader
// re-checks the stop flag at least once per poll slice; request_stop()
// additionally shuts the socket down, which makes an in-flight wait complete
// immediately on every platform, including Windows.

#include "fabric_registry/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fabric_registry {
namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
using socket_length = int;
constexpr native_socket kInvalidSocket = INVALID_SOCKET;
#else
using native_socket = int;
using socket_length = socklen_t;
constexpr native_socket kInvalidSocket = -1;
#endif

/// Longest textual IP address plus its terminator. Nothing longer can be a
/// numeric address, so it is rejected without touching the resolver.
constexpr std::size_t kMaxNumericHostBytes = 64;

/// One read never asks for more than this, and one send never hands the kernel
/// more than this.
constexpr std::size_t kReceiveChunkBytes = 16 * 1024;
constexpr std::size_t kSendChunkBytes = 1024 * 1024;

/// A reader never sleeps longer than this before it re-checks the stop flag.
constexpr std::chrono::milliseconds kStopPollSlice{50};

/// Responses carrying another request id that round_trip tolerates.
constexpr int kMaxSkippedResponses = 64;

constexpr int kListenBacklog = 64;

#if defined(_WIN32)
constexpr int kSendFlags = 0;
#elif defined(MSG_NOSIGNAL)
// A peer that vanished must fail the send, not raise SIGPIPE.
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

/// Starts Winsock exactly once per process. There is deliberately no matching
/// WSACleanup: sockets may outlive any single call site.
void ensure_network_ready() {
#if defined(_WIN32)
  static std::once_flag start_once;
  std::call_once(start_once, []() {
    WSADATA data{};
    (void)::WSAStartup(MAKEWORD(2, 2), &data);
  });
#endif
}

native_socket to_native(std::intptr_t handle) noexcept {
  return static_cast<native_socket>(handle);
}

int socket_error() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

std::string os_error_text(int code) {
  std::string text = "os error ";
  text += std::to_string(code);
  return text;
}

/// "<step> failed: <os error>" — the failing step plus the platform code.
std::string step_error(std::string_view step, int code) {
  std::string message(step);
  message += " failed: ";
  message += os_error_text(code);
  return message;
}

bool is_interrupted(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEINTR;
#else
  return code == EINTR;
#endif
}

bool is_would_block(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEWOULDBLOCK;
#else
  return code == EWOULDBLOCK || code == EAGAIN;
#endif
}

bool is_connect_pending(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS || code == WSAEALREADY;
#else
  return code == EINPROGRESS || code == EALREADY || code == EINTR;
#endif
}

void shutdown_native(native_socket handle) noexcept {
#if defined(_WIN32)
  (void)::shutdown(handle, SD_BOTH);
#else
  (void)::shutdown(handle, SHUT_RDWR);
#endif
}

void close_native(native_socket handle) noexcept {
#if defined(_WIN32)
  (void)::closesocket(handle);
#else
  (void)::close(handle);
#endif
}

enum class wait_mode {
  /// The socket has bytes to read.
  readable,
  /// The socket can accept bytes.
  writable,
  /// A pending non-blocking connect finished. Winsock reports a failed
  /// connect in the exception set, not the write set, so both are watched.
  connect,
};

/// Bounded wait on one socket. Returns 1 when the socket is ready, 0 when the
/// wait elapsed or was interrupted, and -1 when the wait itself failed.
int wait_native(native_socket handle, wait_mode mode, std::chrono::milliseconds timeout) noexcept {
  fd_set read_set;
  fd_set write_set;
  fd_set except_set;
  fd_set* read_ptr = nullptr;
  fd_set* write_ptr = nullptr;
  fd_set* except_ptr = nullptr;
  if (mode == wait_mode::readable) {
    FD_ZERO(&read_set);
    FD_SET(handle, &read_set);
    read_ptr = &read_set;
  } else {
    FD_ZERO(&write_set);
    FD_SET(handle, &write_set);
    write_ptr = &write_set;
    if (mode == wait_mode::connect) {
      FD_ZERO(&except_set);
      FD_SET(handle, &except_set);
      except_ptr = &except_set;
    }
  }
  const std::int64_t total_ms = timeout.count() > 0 ? timeout.count() : 0;
  timeval interval{};
  interval.tv_sec = static_cast<long>(total_ms / 1000);
  interval.tv_usec = static_cast<long>((total_ms % 1000) * 1000);
#if defined(_WIN32)
  const int ready = ::select(0, read_ptr, write_ptr, except_ptr, &interval);
#else
  const int ready = ::select(static_cast<int>(handle) + 1, read_ptr, write_ptr, except_ptr, &interval);
#endif
  if (ready > 0) {
    return 1;
  }
  if (ready == 0) {
    return 0;
  }
  return is_interrupted(socket_error()) ? 0 : -1;
}

bool set_blocking_mode(native_socket handle, bool blocking) noexcept {
#if defined(_WIN32)
  u_long mode = blocking ? 0ul : 1ul;
  return ::ioctlsocket(handle, FIONBIO, &mode) == 0;
#else
  const int current = ::fcntl(handle, F_GETFL, 0);
  if (current < 0) {
    return false;
  }
  const int updated = blocking ? (current & ~O_NONBLOCK) : (current | O_NONBLOCK);
  return ::fcntl(handle, F_SETFL, updated) == 0;
#endif
}

bool set_boolean_option(native_socket handle, int level, int option, bool enabled) noexcept {
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  return ::setsockopt(handle, level, option, reinterpret_cast<const char*>(&value),
                      static_cast<int>(sizeof(value))) == 0;
#else
  return ::setsockopt(handle, level, option, &value, static_cast<socklen_t>(sizeof(value))) == 0;
#endif
}

bool read_socket_error(native_socket handle, int& value) noexcept {
  int pending = 0;
  socket_length length = static_cast<socket_length>(sizeof(pending));
#if defined(_WIN32)
  if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&pending), &length) != 0) {
    return false;
  }
#else
  if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, &pending, &length) != 0) {
    return false;
  }
#endif
  value = pending;
  return true;
}

std::uint16_t port_of(const sockaddr_storage& storage) noexcept {
  if (storage.ss_family == AF_INET) {
    const auto* address = reinterpret_cast<const sockaddr_in*>(&storage);
    return static_cast<std::uint16_t>(ntohs(address->sin_port));
  }
  if (storage.ss_family == AF_INET6) {
    const auto* address = reinterpret_cast<const sockaddr_in6*>(&storage);
    return static_cast<std::uint16_t>(ntohs(address->sin6_port));
  }
  return 0;
}

/// True when the text is a literal IPv4 or IPv6 address.
bool is_numeric_host(std::string_view host) noexcept {
  if (host.empty() || host.size() >= kMaxNumericHostBytes) {
    return false;
  }
  char text[kMaxNumericHostBytes] = {};
  std::memcpy(text, host.data(), host.size());
  text[host.size()] = '\0';
  in_addr address_v4{};
  if (::inet_pton(AF_INET, text, &address_v4) == 1) {
    return true;
  }
  in6_addr address_v6{};
  return ::inet_pton(AF_INET6, text, &address_v6) == 1;
}

struct AddrInfoDeleter {
  void operator()(addrinfo* value) const noexcept {
    if (value != nullptr) {
      ::freeaddrinfo(value);
    }
  }
};

using AddrInfoList = std::unique_ptr<addrinfo, AddrInfoDeleter>;

/// Resolves one endpoint. Numeric hosts never reach a resolver.
bool resolve(const Endpoint& endpoint, bool passive, AddrInfoList& out, int& error_code) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = passive ? AI_PASSIVE : 0;
  if (is_numeric_host(endpoint.host)) {
    hints.ai_flags |= AI_NUMERICHOST;
  }
  const char* node = endpoint.host.empty() ? nullptr : endpoint.host.c_str();
  const std::string service = std::to_string(endpoint.port);
  addrinfo* raw = nullptr;
  const int result = ::getaddrinfo(node, service.c_str(), &hints, &raw);
  if (result != 0) {
    error_code = result;
    return false;
  }
  out.reset(raw);
  return true;
}

void erase_front(std::vector<std::uint8_t>& buffer, std::size_t count) {
  if (count == 0 || count > buffer.size()) {
    return;
  }
  buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(count));
}

FrameDecodeResult need_more_result() {
  FrameDecodeResult result;
  result.status = FrameDecodeStatus::NeedMoreData;
  return result;
}

FrameDecodeResult malformed_result(const std::string& detail) {
  FrameDecodeResult result;
  result.status = FrameDecodeStatus::Malformed;
  result.detail = detail;
  return result;
}

std::string range_message(std::string_view field, std::size_t value, std::size_t low, std::size_t high) {
  std::string message(field);
  message += " is out of range: ";
  message += std::to_string(value);
  message += " is not within [";
  message += std::to_string(low);
  message += ", ";
  message += std::to_string(high);
  message += "]";
  return message;
}

} // namespace

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

std::string Endpoint::to_string() const {
  std::string text;
  const bool needs_brackets = host.find(':') != std::string::npos;
  if (needs_brackets) {
    text += '[';
    text += host;
    text += ']';
  } else {
    text += host;
  }
  text += ':';
  text += std::to_string(port);
  return text;
}

std::optional<Endpoint> Endpoint::parse(std::string_view text) noexcept {
  if (text.empty()) {
    return std::nullopt;
  }
  std::string_view host;
  std::string_view port_text;
  if (text.front() == '[') {
    const std::size_t closing = text.find(']');
    if (closing == std::string_view::npos) {
      return std::nullopt;
    }
    host = text.substr(1, closing - 1);
    const std::string_view rest = text.substr(closing + 1);
    if (rest.empty() || rest.front() != ':') {
      return std::nullopt;
    }
    port_text = rest.substr(1);
  } else {
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos) {
      return std::nullopt;
    }
    host = text.substr(0, colon);
    port_text = text.substr(colon + 1);
  }
  if (host.empty() || port_text.empty()) {
    return std::nullopt;
  }
  std::uint32_t port = 0;
  for (char digit : port_text) {
    if (digit < '0' || digit > '9') {
      return std::nullopt;
    }
    port = port * 10u + static_cast<std::uint32_t>(digit - '0');
    if (port > 65535u) {
      return std::nullopt;
    }
  }
  Endpoint result;
  result.host.assign(host);
  result.port = static_cast<std::uint16_t>(port);
  return result;
}

bool is_bindable_host(std::string_view host) noexcept {
  if (host.empty() || host == "127.0.0.1" || host == "localhost" || host == "::1" ||
      host == "0.0.0.0" || host == "::") {
    return true;
  }
  return is_numeric_host(host);
}

// ---------------------------------------------------------------------------
// TransportConfig
// ---------------------------------------------------------------------------

ValidationResult TransportConfig::validate() const {
  if (max_payload_bytes < 64 || max_payload_bytes > hard_limits::kMaxFramePayloadBytes) {
    return ValidationResult::failure(
        range_message("max_payload_bytes", max_payload_bytes, 64, hard_limits::kMaxFramePayloadBytes));
  }
  if (poll_interval.count() <= 0) {
    return ValidationResult::failure("poll_interval must be greater than zero");
  }
  if (poll_interval > std::chrono::milliseconds(5000)) {
    return ValidationResult::failure("poll_interval must be at most 5000 ms");
  }
  if (connect_timeout.count() <= 0) {
    return ValidationResult::failure("connect_timeout must be greater than zero");
  }
  if (connect_timeout > std::chrono::milliseconds(120000)) {
    return ValidationResult::failure("connect_timeout must be at most 120000 ms");
  }
  if (heartbeat_interval.count() <= 0) {
    return ValidationResult::failure("heartbeat_interval must be greater than zero");
  }
  if (heartbeat_timeout.count() <= 0) {
    return ValidationResult::failure("heartbeat_timeout must be greater than zero");
  }
  return ValidationResult::success();
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

Socket::~Socket() {
  close();
}

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = kInvalid;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalid;
  }
  return *this;
}

bool Socket::valid() const noexcept {
  return handle_ != kInvalid;
}

void Socket::close() noexcept {
  const std::intptr_t handle = handle_;
  if (handle == kInvalid) {
    return;
  }
  // Invalidate first: a second close() never touches the same handle twice.
  handle_ = kInvalid;
  const native_socket native = to_native(handle);
  shutdown_native(native);
  close_native(native);
}

void Socket::shutdown_both() noexcept {
  if (handle_ == kInvalid) {
    return;
  }
  shutdown_native(to_native(handle_));
}

Socket Socket::adopt(std::intptr_t handle) noexcept {
  Socket result;
  result.handle_ = handle;
  return result;
}

// ---------------------------------------------------------------------------
// TcpListener
// ---------------------------------------------------------------------------

TcpListener::~TcpListener() = default;
TcpListener::TcpListener(TcpListener&& other) noexcept = default;
TcpListener& TcpListener::operator=(TcpListener&& other) noexcept = default;

std::optional<TcpListener> TcpListener::bind(const Endpoint& endpoint, std::string& error) {
  error.clear();
  if (!is_bindable_host(endpoint.host)) {
    error = "bind failed: host is not a numeric loopback or wildcard address";
    return std::nullopt;
  }
  ensure_network_ready();
  AddrInfoList addresses;
  int resolve_error = 0;
  if (!resolve(endpoint, true, addresses, resolve_error)) {
    error = step_error("getaddrinfo", resolve_error);
    return std::nullopt;
  }
  int last_error = 0;
  for (const addrinfo* candidate = addresses.get(); candidate != nullptr; candidate = candidate->ai_next) {
    const native_socket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) {
      last_error = socket_error();
      continue;
    }
    // Closed on every path out of this iteration.
    Socket owned = Socket::adopt(static_cast<std::intptr_t>(handle));
    (void)set_boolean_option(handle, SOL_SOCKET, SO_REUSEADDR, true);
    if (candidate->ai_family == AF_INET6) {
      // A wildcard IPv6 listener also serves IPv4 peers.
      (void)set_boolean_option(handle, IPPROTO_IPV6, IPV6_V6ONLY, false);
    }
    if (::bind(handle, candidate->ai_addr, static_cast<socket_length>(candidate->ai_addrlen)) != 0) {
      last_error = socket_error();
      continue;
    }
    if (::listen(handle, kListenBacklog) != 0) {
      last_error = socket_error();
      continue;
    }
    sockaddr_storage local{};
    socket_length local_length = static_cast<socket_length>(sizeof(local));
    if (::getsockname(handle, reinterpret_cast<sockaddr*>(&local), &local_length) != 0) {
      last_error = socket_error();
      continue;
    }
    TcpListener listener;
    listener.socket_ = std::move(owned);
    // Port 0 means "any port": the caller learns the real one from here.
    listener.endpoint_ = endpoint;
    listener.endpoint_.port = port_of(local);
    return listener;
  }
  error = last_error != 0 ? step_error("bind", last_error) : std::string("bind failed: no usable address");
  return std::nullopt;
}

std::optional<Socket> TcpListener::accept(std::chrono::milliseconds wait, const std::atomic<bool>& stop,
                                          std::string& error) noexcept {
  error.clear();
  if (!socket_.valid()) {
    error = "accept failed: the listener is not open";
    return std::nullopt;
  }
  if (stop.load(std::memory_order_acquire)) {
    error = "stopped";
    return std::nullopt;
  }
  const native_socket handle = to_native(socket_.native_handle());
  const int ready = wait_native(handle, wait_mode::readable, wait);
  if (ready < 0) {
    error = step_error("select", socket_error());
    return std::nullopt;
  }
  if (ready == 0) {
    error.clear();
    return std::nullopt;
  }
  if (stop.load(std::memory_order_acquire)) {
    error = "stopped";
    return std::nullopt;
  }
  sockaddr_storage remote{};
  socket_length remote_length = static_cast<socket_length>(sizeof(remote));
  const native_socket accepted = ::accept(handle, reinterpret_cast<sockaddr*>(&remote), &remote_length);
  if (accepted == kInvalidSocket) {
    error = step_error("accept", socket_error());
    return std::nullopt;
  }
  return Socket::adopt(static_cast<std::intptr_t>(accepted));
}

void TcpListener::close() noexcept {
  socket_.close();
}

bool TcpListener::valid() const noexcept {
  return socket_.valid();
}

// ---------------------------------------------------------------------------
// connect_to
// ---------------------------------------------------------------------------

std::optional<Socket> connect_to(const Endpoint& endpoint, std::chrono::milliseconds timeout,
                                 std::string& error) {
  error.clear();
  if (endpoint.host.empty()) {
    error = "connect failed: the host is empty";
    return std::nullopt;
  }
  if (endpoint.host != "localhost" && !is_numeric_host(endpoint.host)) {
    error = "connect failed: the host is not a numeric address or localhost";
    return std::nullopt;
  }
  ensure_network_ready();
  AddrInfoList addresses;
  int resolve_error = 0;
  if (!resolve(endpoint, false, addresses, resolve_error)) {
    error = step_error("getaddrinfo", resolve_error);
    return std::nullopt;
  }
  const auto start = std::chrono::steady_clock::now();
  int last_error = 0;
  for (const addrinfo* candidate = addresses.get(); candidate != nullptr; candidate = candidate->ai_next) {
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    const auto remaining = timeout - elapsed;
    if (remaining <= std::chrono::milliseconds::zero()) {
      break;
    }
    const native_socket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidSocket) {
      last_error = socket_error();
      continue;
    }
    Socket owned = Socket::adopt(static_cast<std::intptr_t>(handle));
    if (!set_blocking_mode(handle, false)) {
      last_error = socket_error();
      continue;
    }
    if (::connect(handle, candidate->ai_addr, static_cast<socket_length>(candidate->ai_addrlen)) != 0) {
      const int code = socket_error();
      if (!is_connect_pending(code)) {
        last_error = code;
        continue;
      }
      const int ready = wait_native(handle, wait_mode::connect, remaining);
      if (ready < 0) {
        last_error = socket_error();
        continue;
      }
      if (ready == 0) {
        break;
      }
      int pending = 0;
      if (!read_socket_error(handle, pending)) {
        last_error = socket_error();
        continue;
      }
      if (pending != 0) {
        last_error = pending;
        continue;
      }
    }
    if (!set_blocking_mode(handle, true)) {
      last_error = socket_error();
      continue;
    }
    return owned;
  }
  if (last_error != 0) {
    error = step_error("connect", last_error);
  } else {
    error = "connect failed: timed out after ";
    error += std::to_string(timeout.count());
    error += " ms";
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

Connection::Connection(Socket socket, TransportConfig config) noexcept
    : socket_(std::move(socket)), config_(config), inbound_(), stop_(false) {}

Connection::~Connection() = default;

Connection::Connection(Connection&& other) noexcept
    : socket_(std::move(other.socket_)),
      config_(other.config_),
      inbound_(std::move(other.inbound_)),
      stop_(other.stop_.load(std::memory_order_acquire)) {}

Connection& Connection::operator=(Connection&& other) noexcept {
  if (this != &other) {
    socket_ = std::move(other.socket_);
    config_ = other.config_;
    inbound_ = std::move(other.inbound_);
    stop_.store(other.stop_.load(std::memory_order_acquire), std::memory_order_release);
  }
  return *this;
}

void Connection::close() noexcept {
  socket_.close();
}

void Connection::request_stop() noexcept {
  stop_.store(true, std::memory_order_release);
  socket_.shutdown_both();
}

bool Connection::send(MessageType type, std::uint64_t request_id, std::span<const std::uint8_t> payload,
                      std::string& error) {
  error.clear();
  if (stop_.load(std::memory_order_acquire)) {
    error = "stopped";
    return false;
  }
  if (!socket_.valid()) {
    error = "send failed: the connection is not open";
    return false;
  }
  FrameLimits limits{};
  limits.max_payload_bytes = config_.max_payload_bytes;
  std::string encode_error;
  const std::vector<std::uint8_t> frame = encode_frame(type, request_id, payload, limits, encode_error);
  if (frame.empty()) {
    error =
        encode_error.empty() ? std::string("encode failed: the frame could not be built") : encode_error;
    return false;
  }
  const native_socket handle = to_native(socket_.native_handle());
  std::size_t offset = 0;
  while (offset < frame.size()) {
    if (stop_.load(std::memory_order_acquire)) {
      error = "stopped";
      return false;
    }
    const std::size_t remaining = frame.size() - offset;
    const int chunk = static_cast<int>(std::min(remaining, kSendChunkBytes));
    const int written =
        ::send(handle, reinterpret_cast<const char*>(frame.data() + offset), chunk, kSendFlags);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written == 0) {
      error = "send failed: the peer is no longer reading";
      return false;
    }
    const int code = socket_error();
    if (is_interrupted(code)) {
      continue;
    }
    if (is_would_block(code)) {
      const int ready = wait_native(handle, wait_mode::writable, config_.poll_interval);
      if (ready < 0) {
        error = step_error("select", socket_error());
        return false;
      }
      continue;
    }
    if (stop_.load(std::memory_order_acquire)) {
      error = "stopped";
      return false;
    }
    error = step_error("send", code);
    return false;
  }
  return true;
}

FrameDecodeResult Connection::receive(std::chrono::milliseconds wait, std::string& error) {
  try {
    error.clear();
    if (!socket_.valid()) {
      error = "receive failed: the connection is not open";
      return malformed_result(error);
    }
    const native_socket handle = to_native(socket_.native_handle());
    const auto start = std::chrono::steady_clock::now();
    FrameLimits limits{};
    limits.max_payload_bytes = config_.max_payload_bytes;
    // A scratch buffer that lives for the lifetime of the connection instead of
    // on the stack: 16 KiB of stack per reader is a real risk on the small
    // default stacks a session thread may be given.
    scratch_.resize(kReceiveChunkBytes);
    for (;;) {
      FrameDecodeResult result = decode_frame(inbound_, limits);
      if (result.status == FrameDecodeStatus::Complete) {
        erase_front(inbound_, result.consumed);
        error.clear();
        return result;
      }
      if (result.status == FrameDecodeStatus::NeedMoreData) {
        if (inbound_.size() > kFrameOverheadBytes + config_.max_payload_bytes) {
          error = "frame exceeds the configured payload bound";
          return malformed_result(error);
        }
      } else {
        erase_front(inbound_, result.consumed);
        error = result.detail.empty() ? std::string(to_string(result.status)) : result.detail;
        return result;
      }
      if (stop_.load(std::memory_order_acquire)) {
        error = "stopped";
        return need_more_result();
      }
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
      if (elapsed >= wait) {
        error.clear();
        return need_more_result();
      }
      const auto slice = std::min(wait - elapsed, kStopPollSlice);
      const int ready = wait_native(handle, wait_mode::readable, slice);
      if (ready < 0) {
        error = step_error("select", socket_error());
        return malformed_result(error);
      }
      if (ready == 0) {
        continue;
      }
      const int received = ::recv(handle, reinterpret_cast<char*>(scratch_.data()),
                                  static_cast<int>(scratch_.size()), 0);
      if (received == 0) {
        if (stop_.load(std::memory_order_acquire)) {
          error = "stopped";
          return need_more_result();
        }
        error = "peer closed the connection";
        return malformed_result(error);
      }
      if (received < 0) {
        const int code = socket_error();
        if (is_interrupted(code) || is_would_block(code)) {
          continue;
        }
        if (stop_.load(std::memory_order_acquire)) {
          error = "stopped";
          return need_more_result();
        }
        error = step_error("recv", code);
        return malformed_result(error);
      }
      const std::size_t count = static_cast<std::size_t>(received);
      inbound_.insert(inbound_.end(), scratch_.data(), scratch_.data() + count);
    }
  } catch (...) {
    error = "internal failure";
    FrameDecodeResult failure;
    failure.status = FrameDecodeStatus::Malformed;
    failure.detail = error;
    return failure;
  }
}

bool Connection::round_trip(MessageType type, std::uint64_t request_id,
                            std::span<const std::uint8_t> payload, Frame& response, std::string& error) {
  if (!send(type, request_id, payload, error)) {
    return false;
  }
  int skipped = 0;
  for (;;) {
    if (stopped()) {
      error = "stopped";
      return false;
    }
    FrameDecodeResult result = receive(config_.poll_interval, error);
    if (result.status == FrameDecodeStatus::Complete) {
      if (result.frame.request_id == request_id) {
        response = std::move(result.frame);
        error.clear();
        return true;
      }
      if (skipped >= kMaxSkippedResponses) {
        error = "too many out-of-order responses";
        return false;
      }
      ++skipped;
      continue;
    }
    if (result.status == FrameDecodeStatus::NeedMoreData) {
      if (stopped()) {
        error = "stopped";
        return false;
      }
      continue;
    }
    return false;
  }
}

} // namespace fabric_registry
