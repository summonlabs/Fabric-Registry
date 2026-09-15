// Fabric Registry — SHA-256 and canonical digest construction.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/digest.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace fabric_registry {

namespace {

// FIPS 180-4, section 4.2.2: the first 32 bits of the fractional parts of the
// cube roots of the first 64 primes.
constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

// FIPS 180-4, section 5.3.3: the initial hash value.
constexpr std::uint32_t kInitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

// Written by CanonicalHasher::begin before the domain, so that a domain name
// can never be replayed across encoding revisions.
constexpr std::string_view kCanonicalMarker = "fabric-registry/1";

constexpr std::uint32_t rotate_right(std::uint32_t value, std::uint32_t amount) noexcept {
  return (value >> amount) | (value << (32u - amount));
}

std::uint32_t load_big_endian32(const std::uint8_t* data) noexcept {
  return (static_cast<std::uint32_t>(data[0]) << 24) | (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) | static_cast<std::uint32_t>(data[3]);
}

void store_big_endian32(std::uint32_t value, std::uint8_t* out) noexcept {
  out[0] = static_cast<std::uint8_t>(value >> 24);
  out[1] = static_cast<std::uint8_t>(value >> 16);
  out[2] = static_cast<std::uint8_t>(value >> 8);
  out[3] = static_cast<std::uint8_t>(value);
}

void store_big_endian64(std::uint64_t value, std::uint8_t* out) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>(value >> ((7u - static_cast<unsigned int>(i)) * 8u));
  }
}

// Writes the low bytes of a value little-endian. This is the fixed width
// integer encoding of CanonicalHasher.
void append_little_endian(Sha256& hasher, std::uint64_t value, std::size_t width) {
  std::uint8_t encoded[8] = {};
  for (std::size_t i = 0; i < width; ++i) {
    encoded[i] = static_cast<std::uint8_t>(value & 0xffu);
    value >>= 8;
  }
  hasher.update(encoded, width);
}

} // namespace

Sha256::Sha256() noexcept {
  reset();
}

void Sha256::reset() noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    state_[i] = kInitialState[i];
  }
  total_bytes_ = 0;
  buffered_ = 0;
  std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::update(const void* data, std::size_t size) noexcept {
  if (size == 0) {
    return;
  }
  const std::uint8_t* input = static_cast<const std::uint8_t*>(data);
  total_bytes_ += static_cast<std::uint64_t>(size);

  if (buffered_ != 0) {
    const std::size_t room = block_size - buffered_;
    if (size < room) {
      std::memcpy(buffer_ + buffered_, input, size);
      buffered_ += size;
      return;
    }
    std::memcpy(buffer_ + buffered_, input, room);
    compress(buffer_);
    input += room;
    size -= room;
    buffered_ = 0;
  }

  while (size >= block_size) {
    compress(input);
    input += block_size;
    size -= block_size;
  }

  if (size != 0) {
    std::memcpy(buffer_, input, size);
    buffered_ = size;
  }
}

void Sha256::update(std::string_view text) noexcept {
  update(text.data(), text.size());
}

void Sha256::update(std::span<const std::uint8_t> bytes) noexcept {
  update(bytes.data(), bytes.size());
}

DigestBytes Sha256::finish() noexcept {
  constexpr std::size_t kLengthFieldBytes = 8;
  constexpr std::size_t kPaddingBoundary = block_size - kLengthFieldBytes;

  const std::uint64_t bit_length = total_bytes_ * 8u;

  std::uint8_t padding[block_size] = {};
  padding[0] = 0x80u;
  const std::size_t padding_size =
      (buffered_ < kPaddingBoundary ? kPaddingBoundary : kPaddingBoundary + block_size) - buffered_;
  update(padding, padding_size);

  std::uint8_t length_field[kLengthFieldBytes] = {};
  store_big_endian64(bit_length, length_field);
  update(length_field, sizeof(length_field));

  DigestBytes digest{};
  for (std::size_t i = 0; i < 8; ++i) {
    store_big_endian32(state_[i], digest.data() + i * 4);
  }
  return digest;
}

DigestBytes Sha256::hash(const void* data, std::size_t size) noexcept {
  Sha256 hasher;
  hasher.update(data, size);
  return hasher.finish();
}

DigestBytes Sha256::hash(std::string_view text) noexcept {
  return hash(text.data(), text.size());
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::uint32_t schedule[64] = {};
  for (std::size_t i = 0; i < 16; ++i) {
    schedule[i] = load_big_endian32(block + i * 4);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t previous15 = schedule[i - 15];
    const std::uint32_t previous2 = schedule[i - 2];
    const std::uint32_t sigma0 = rotate_right(previous15, 7u) ^ rotate_right(previous15, 18u) ^ (previous15 >> 3);
    const std::uint32_t sigma1 = rotate_right(previous2, 17u) ^ rotate_right(previous2, 19u) ^ (previous2 >> 10);
    schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t sum1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + sum1 + choose + kRoundConstants[i] + schedule[i];
    const std::uint32_t sum0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = sum0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

std::string to_hex(const DigestBytes& digest) {
  std::string out(digest.size() * 2u, '0');
  render_hex(digest.data(), digest.size(), out.data());
  return out;
}

void CanonicalHasher::begin(std::string_view domain) {
  hasher_.reset();
  hasher_.update(kCanonicalMarker);
  const std::uint8_t separator = 0x00;
  hasher_.update(&separator, 1u);
  u32(static_cast<std::uint32_t>(domain.size()));
  hasher_.update(domain.data(), domain.size());
  begun_ = true;
}

void CanonicalHasher::u8(std::uint8_t value) {
  append_little_endian(hasher_, value, sizeof(value));
}

void CanonicalHasher::u16(std::uint16_t value) {
  append_little_endian(hasher_, value, sizeof(value));
}

void CanonicalHasher::u32(std::uint32_t value) {
  append_little_endian(hasher_, value, sizeof(value));
}

void CanonicalHasher::u64(std::uint64_t value) {
  append_little_endian(hasher_, value, sizeof(value));
}

void CanonicalHasher::bytes(std::span<const std::uint8_t> value) {
  u64(static_cast<std::uint64_t>(value.size()));
  hasher_.update(value);
}

void CanonicalHasher::text(std::string_view value) {
  u64(static_cast<std::uint64_t>(value.size()));
  hasher_.update(value);
}

void CanonicalHasher::sequence(std::uint64_t count) {
  const std::uint8_t marker = 0x53;
  hasher_.update(&marker, 1u);
  u64(count);
}

DigestBytes CanonicalHasher::finish() {
  return hasher_.finish();
}

} // namespace fabric_registry
