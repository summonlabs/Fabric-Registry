// Fabric Registry — bounds-checked binary codec primitives.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/codec.hpp"

#include <cstring>

namespace fabric_registry {

// ---------------------------------------------------------------------------
// ByteWriter
// ---------------------------------------------------------------------------

ByteWriter::ByteWriter(std::size_t reserve) {
  buffer_.reserve(reserve);
}

void ByteWriter::u8(std::uint8_t value) {
  buffer_.push_back(value);
}

void ByteWriter::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  buffer_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void ByteWriter::u32(std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void ByteWriter::u64(std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void ByteWriter::raw(const void* data, std::size_t size) {
  if (size == 0) {
    return;
  }
  const std::uint8_t* bytes = static_cast<const std::uint8_t*>(data);
  buffer_.insert(buffer_.end(), bytes, bytes + size);
}

void ByteWriter::raw(std::span<const std::uint8_t> value) {
  raw(value.data(), value.size());
}

void ByteWriter::text(std::string_view value) {
  const std::size_t size = value.size();
  if (size > 0xFFFFFFFFull) {
    // Unreachable for any input this library accepts; refusing to truncate is
    // the only safe behaviour.
    u32(0xFFFFFFFFu);
    return;
  }
  u32(static_cast<std::uint32_t>(size));
  raw(value.data(), size);
}

void ByteWriter::blob(std::span<const std::uint8_t> value) {
  const std::size_t size = value.size();
  if (size > 0xFFFFFFFFull) {
    u32(0xFFFFFFFFu);
    return;
  }
  u32(static_cast<std::uint32_t>(size));
  raw(value.data(), size);
}

void ByteWriter::patch_u32(std::size_t offset, std::uint32_t value) {
  if (offset + 4u > buffer_.size()) {
    return;
  }
  for (int shift = 0; shift < 32; shift += 8) {
    buffer_[offset + static_cast<std::size_t>(shift / 8)] =
        static_cast<std::uint8_t>((value >> shift) & 0xFFu);
  }
}

// ---------------------------------------------------------------------------
// ByteReader
// ---------------------------------------------------------------------------

ByteReader::ByteReader(const std::uint8_t* data, std::size_t size) noexcept
    : data_(data), size_(size), position_(0) {}

ByteReader::ByteReader(std::span<const std::uint8_t> data) noexcept
    : data_(data.data()), size_(data.size()), position_(0) {}

bool ByteReader::u8(std::uint8_t& out) noexcept {
  if (remaining() < 1u) {
    return false;
  }
  out = data_[position_];
  position_ += 1u;
  return true;
}

bool ByteReader::u16(std::uint16_t& out) noexcept {
  if (remaining() < 2u) {
    return false;
  }
  out = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[position_]) |
                                   static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[position_ + 1u]) << 8));
  position_ += 2u;
  return true;
}

bool ByteReader::u32(std::uint32_t& out) noexcept {
  if (remaining() < 4u) {
    return false;
  }
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4u; ++i) {
    value |= static_cast<std::uint32_t>(data_[position_ + i]) << (8u * static_cast<unsigned>(i));
  }
  out = value;
  position_ += 4u;
  return true;
}

bool ByteReader::u64(std::uint64_t& out) noexcept {
  if (remaining() < 8u) {
    return false;
  }
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8u; ++i) {
    value |= static_cast<std::uint64_t>(data_[position_ + i]) << (8u * static_cast<unsigned>(i));
  }
  out = value;
  position_ += 8u;
  return true;
}

bool ByteReader::raw(std::uint8_t* out, std::size_t size) noexcept {
  if (remaining() < size) {
    return false;
  }
  if (size != 0) {
    std::memcpy(out, data_ + position_, size);
  }
  position_ += size;
  return true;
}

bool ByteReader::text(std::string& out, std::size_t max_bytes) {
  std::uint32_t declared = 0;
  if (!u32(declared)) {
    return false;
  }
  const std::size_t length = declared;
  if (length > max_bytes) {
    return false;
  }
  if (remaining() < length) {
    return false;
  }
  out.assign(reinterpret_cast<const char*>(data_ + position_), length);
  position_ += length;
  return true;
}

bool ByteReader::blob(std::vector<std::uint8_t>& out, std::size_t max_bytes) {
  std::uint32_t declared = 0;
  if (!u32(declared)) {
    return false;
  }
  const std::size_t length = declared;
  if (length > max_bytes) {
    return false;
  }
  if (remaining() < length) {
    return false;
  }
  out.assign(data_ + position_, data_ + position_ + length);
  position_ += length;
  return true;
}

bool ByteReader::skip(std::size_t size) noexcept {
  if (remaining() < size) {
    return false;
  }
  position_ += size;
  return true;
}

} // namespace fabric_registry
