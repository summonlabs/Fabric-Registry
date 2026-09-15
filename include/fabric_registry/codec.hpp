// Fabric Registry — bounds-checked binary codec primitives.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every length in a decoded stream is validated against the number of bytes
// actually remaining and against a caller-supplied maximum before any buffer is
// sized. The reader never reads past its end and never allocates a container
// proportional to an unvalidated declared length.

#ifndef FABRIC_REGISTRY_CODEC_HPP
#define FABRIC_REGISTRY_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/export.hpp"

namespace fabric_registry {

/// Append-only little-endian writer.
class FABRIC_REGISTRY_API ByteWriter {
public:
  explicit ByteWriter(std::size_t reserve = 0);

  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void raw(std::span<const std::uint8_t> value);
  void raw(const void* data, std::size_t size);
  /// 32-bit length prefix followed by the bytes.
  void text(std::string_view value);
  /// 32-bit length prefix followed by the bytes.
  void blob(std::span<const std::uint8_t> value);
  /// Overwrites a previously reserved 32-bit length slot.
  void patch_u32(std::size_t offset, std::uint32_t value);

  const std::vector<std::uint8_t>& bytes() const noexcept { return buffer_; }
  std::vector<std::uint8_t>& bytes() noexcept { return buffer_; }
  std::size_t size() const noexcept { return buffer_.size(); }
  void clear() noexcept { buffer_.clear(); }

private:
  std::vector<std::uint8_t> buffer_;
};

/// Sequential bounds-checked little-endian reader.
class FABRIC_REGISTRY_API ByteReader {
public:
  ByteReader(const std::uint8_t* data, std::size_t size) noexcept;
  explicit ByteReader(std::span<const std::uint8_t> data) noexcept;

  bool u8(std::uint8_t& out) noexcept;
  bool u16(std::uint16_t& out) noexcept;
  bool u32(std::uint32_t& out) noexcept;
  bool u64(std::uint64_t& out) noexcept;
  bool raw(std::uint8_t* out, std::size_t size) noexcept;
  /// Reads a 32-bit length prefix, rejects lengths above `max_bytes` or beyond
  /// the remaining input, then reads the bytes.
  bool text(std::string& out, std::size_t max_bytes);
  bool blob(std::vector<std::uint8_t>& out, std::size_t max_bytes);
  bool skip(std::size_t size) noexcept;

  std::size_t position() const noexcept { return position_; }
  std::size_t size() const noexcept { return size_; }
  std::size_t remaining() const noexcept { return size_ - position_; }
  bool at_end() const noexcept { return position_ == size_; }
  const std::uint8_t* cursor() const noexcept { return data_ + position_; }

private:
  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t position_;
};

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_CODEC_HPP
