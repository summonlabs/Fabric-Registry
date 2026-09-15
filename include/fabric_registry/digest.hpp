// Fabric Registry — SHA-256 and canonical digest construction.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// SHA-256 is implemented in-tree because the library takes no external
// dependency. It is validated against the FIPS 180-4 / NIST example vectors and
// against explicit padding-boundary lengths (55, 56, 63, 64, 119, 120 bytes) in
// tests/test_digest.cpp. Digests are only ever computed over the canonical
// encoding defined by CanonicalHasher, never over a C++ object's memory
// representation.

#ifndef FABRIC_REGISTRY_DIGEST_HPP
#define FABRIC_REGISTRY_DIGEST_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "fabric_registry/export.hpp"
#include "fabric_registry/ids.hpp"

namespace fabric_registry {

/// Streaming SHA-256 (FIPS 180-4).
class FABRIC_REGISTRY_API Sha256 {
public:
  static constexpr std::size_t block_size = 64;
  static constexpr std::size_t digest_size = kDigestBytes;

  Sha256() noexcept;

  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept;
  void update(std::span<const std::uint8_t> bytes) noexcept;

  /// Finishes the digest. The object must not be updated afterwards without a
  /// reset.
  DigestBytes finish() noexcept;
  void reset() noexcept;

  static DigestBytes hash(const void* data, std::size_t size) noexcept;
  static DigestBytes hash(std::string_view text) noexcept;

private:
  void compress(const std::uint8_t* block) noexcept;

  std::uint32_t state_[8];
  std::uint64_t total_bytes_;
  std::uint8_t buffer_[block_size];
  std::size_t buffered_;
};

/// Lowercase hex rendering of a digest.
FABRIC_REGISTRY_API std::string to_hex(const DigestBytes& digest);

/// Builds a domain-separated canonical digest.
///
/// Every field is written with an unambiguous encoding: integers are
/// little-endian fixed width, byte strings and texts are length-prefixed with a
/// 64-bit length. Two different field sequences can therefore never produce the
/// same byte stream. Callers must open a domain first; the domain string is
/// what keeps, for example, a state digest from ever colliding with a request
/// digest.
class FABRIC_REGISTRY_API CanonicalHasher {
public:
  CanonicalHasher() = default;

  void begin(std::string_view domain);
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void bytes(std::span<const std::uint8_t> value);
  void text(std::string_view value);
  /// Length-prefixed sequence header. Must be followed by exactly the declared
  /// number of encoded elements.
  void sequence(std::uint64_t count);

  DigestBytes finish();

private:
  Sha256 hasher_;
  bool begun_{false};
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_DIGEST_HPP
