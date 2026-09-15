// Fabric Registry — strongly typed identifiers.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/ids.hpp"

#include <cctype>

#include "fabric_registry/identity.hpp"

namespace fabric_registry {
namespace {

/// Returns the numeric value of a lowercase hexadecimal digit, or -1.
constexpr int hex_value(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

/// Parses 1..4 hexadecimal digits into a 16-bit value. Rejects empty input.
bool parse_hex_u16(std::string_view text, std::uint16_t& out) noexcept {
  if (text.empty() || text.size() > 4) {
    return false;
  }
  std::uint32_t value = 0;
  for (char c : text) {
    const int digit = hex_value(c);
    if (digit < 0) {
      return false;
    }
    value = (value << 4) | static_cast<std::uint32_t>(digit);
  }
  out = static_cast<std::uint16_t>(value);
  return true;
}

std::string render_hex_u16(std::uint16_t value, std::size_t digits) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out(digits, '0');
  for (std::size_t i = 0; i < digits; ++i) {
    const std::size_t shift = (digits - 1 - i) * 4;
    out[i] = kDigits[(static_cast<std::uint32_t>(value) >> shift) & 0xFu];
  }
  return out;
}

} // namespace

void render_hex(const std::uint8_t* data, std::size_t size, char* out) noexcept {
  static constexpr char kDigits[] = "0123456789abcdef";
  for (std::size_t i = 0; i < size; ++i) {
    out[i * 2] = kDigits[(data[i] >> 4) & 0xFu];
    out[i * 2 + 1] = kDigits[data[i] & 0xFu];
  }
}

bool parse_hex(const char* text, std::size_t size, std::uint8_t* out) noexcept {
  if ((size % 2) != 0) {
    return false;
  }
  for (std::size_t i = 0; i < size / 2; ++i) {
    const int high = hex_value(text[i * 2]);
    const int low = hex_value(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

// ---------------------------------------------------------------------------
// CanonicalId
// ---------------------------------------------------------------------------

std::optional<CanonicalId> CanonicalId::parse(std::string_view text) noexcept {
  const std::size_t separator = text.find(':');
  if (separator == std::string_view::npos) {
    return std::nullopt;
  }
  const std::optional<EntityClass> entity_class = entity_class_from_string(text.substr(0, separator));
  if (!entity_class.has_value()) {
    return std::nullopt;
  }
  return parse(*entity_class, text.substr(separator + 1));
}

std::optional<CanonicalId> CanonicalId::parse(EntityClass entity_class, std::string_view text) noexcept {
  if (!is_valid_entity_class(entity_class)) {
    return std::nullopt;
  }
  if (text.size() != kOpaqueIdTextLength) {
    return std::nullopt;
  }
  IdBytes value{};
  if (!parse_hex(text.data(), text.size(), value.data())) {
    return std::nullopt;
  }
  CanonicalId result(entity_class, value);
  if (result.is_null()) {
    return std::nullopt;
  }
  return result;
}

std::string CanonicalId::to_string() const {
  std::string out;
  const std::string_view name = fabric_registry::to_string(entity_class_);
  out.reserve(name.size() + 1 + kOpaqueIdTextLength);
  out.append(name);
  out.push_back(':');
  const std::size_t offset = out.size();
  out.resize(offset + kOpaqueIdTextLength, '0');
  render_hex(bytes_.data(), bytes_.size(), out.data() + offset);
  return out;
}

// ---------------------------------------------------------------------------
// DeviceId
// ---------------------------------------------------------------------------

std::optional<DeviceId> DeviceId::from_canonical(const CanonicalId& id) noexcept {
  if (!is_device_class(id.entity_class()) || id.is_null()) {
    return std::nullopt;
  }
  DeviceId result;
  result.canonical_ = id;
  return result;
}

std::optional<DeviceId> DeviceId::parse(std::string_view text) noexcept {
  const std::optional<CanonicalId> parsed = CanonicalId::parse(text);
  if (!parsed.has_value()) {
    return std::nullopt;
  }
  return from_canonical(*parsed);
}

// ---------------------------------------------------------------------------
// Vendor / product identifiers
// ---------------------------------------------------------------------------

std::optional<VendorId> VendorId::parse(std::string_view text) noexcept {
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    text.remove_prefix(2);
  }
  std::uint16_t value = 0;
  if (!parse_hex_u16(text, value) || value == 0) {
    return std::nullopt;
  }
  return VendorId(value);
}

std::string VendorId::to_string() const {
  return std::string("0x") + render_hex_u16(value_, 4);
}

std::optional<ProductId> ProductId::parse(std::string_view text) noexcept {
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    text.remove_prefix(2);
  }
  std::uint16_t value = 0;
  if (!parse_hex_u16(text, value) || value == 0) {
    return std::nullopt;
  }
  return ProductId(value);
}

std::string ProductId::to_string() const {
  return std::string("0x") + render_hex_u16(value_, 4);
}

// ---------------------------------------------------------------------------
// SerialIdentity
// ---------------------------------------------------------------------------

std::optional<SerialIdentity> SerialIdentity::parse(std::string_view value, std::string_view scope) {
  if (value.size() > max_value_bytes || scope.size() > max_scope_bytes) {
    return std::nullopt;
  }
  std::size_t begin = 0;
  std::size_t end = value.size();
  while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' || value[begin] == '\n')) {
    ++begin;
  }
  while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t' || value[end - 1] == '\r' || value[end - 1] == '\n')) {
    --end;
  }
  const std::string_view trimmed = value.substr(begin, end - begin);
  const std::string_view trimmed_scope = trim_ascii(scope);
  if (trimmed.empty() || trimmed_scope.empty()) {
    return std::nullopt;
  }
  for (char c : trimmed) {
    const unsigned char raw = static_cast<unsigned char>(c);
    if (raw < 0x20 || raw == 0x7F) {
      return std::nullopt;
    }
  }
  for (char c : trimmed_scope) {
    const unsigned char raw = static_cast<unsigned char>(c);
    if (raw < 0x20 || raw == 0x7F) {
      return std::nullopt;
    }
  }
  SerialIdentity result;
  result.value_.assign(trimmed);
  result.scope_.assign(trimmed_scope);
  return result;
}

std::string SerialIdentity::to_string() const {
  if (value_.empty()) {
    return "serial:<null>";
  }
  return "serial[" + scope_ + "]:" + value_;
}

} // namespace fabric_registry
