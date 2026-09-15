// Fabric Registry — identity facts, aliases and provenance.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/identity.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "fabric_registry/digest.hpp"

namespace fabric_registry {
namespace {

// ---------------------------------------------------------------------------
// Small text helpers
// ---------------------------------------------------------------------------

bool is_ascii_control(unsigned char value) noexcept {
  return value < 0x20u || value == 0x7Fu;
}

/// Decodes one UTF-8 sequence starting at \`index\`. Returns the number of bytes
/// consumed and writes the code point, or returns 0 when the sequence is
/// invalid (overlong, surrogate, out of range or truncated).
std::size_t decode_utf8(std::string_view text, std::size_t index, std::uint32_t& code_point) noexcept {
  const unsigned char first = static_cast<unsigned char>(text[index]);
  if (first < 0x80u) {
    code_point = first;
    return 1;
  }
  std::size_t length = 0;
  std::uint32_t value = 0;
  std::uint32_t minimum = 0;
  if ((first & 0xE0u) == 0xC0u) {
    length = 2;
    value = first & 0x1Fu;
    minimum = 0x80u;
  } else if ((first & 0xF0u) == 0xE0u) {
    length = 3;
    value = first & 0x0Fu;
    minimum = 0x800u;
  } else if ((first & 0xF8u) == 0xF0u) {
    length = 4;
    value = first & 0x07u;
    minimum = 0x10000u;
  } else {
    return 0;
  }
  if (index + length > text.size()) {
    return 0;
  }
  for (std::size_t i = 1; i < length; ++i) {
    const unsigned char next = static_cast<unsigned char>(text[index + i]);
    if ((next & 0xC0u) != 0x80u) {
      return 0;
    }
    value = (value << 6) | (next & 0x3Fu);
  }
  if (value < minimum) {
    return 0;
  }
  if (value > 0x10FFFFu) {
    return 0;
  }
  if (value >= 0xD800u && value <= 0xDFFFu) {
    return 0;
  }
  code_point = value;
  return length;
}

bool contains_only(std::string_view text, std::string_view allowed) noexcept {
  for (char c : text) {
    if (allowed.find(c) == std::string_view::npos) {
      return false;
    }
  }
  return true;
}

char to_lower_ascii(char value) noexcept {
  if (value >= 'A' && value <= 'Z') {
    return static_cast<char>(value - 'A' + 'a');
  }
  return value;
}

std::string lowercase_copy(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = to_lower_ascii(c);
  }
  return out;
}

int hex_digit_value(char value) noexcept {
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

/// Removes every character listed in \`separators\`; rejects anything that is not
/// a hexadecimal digit.
bool strip_separators(std::string_view text, std::string_view separators, std::string& out) {
  out.clear();
  out.reserve(text.size());
  for (char c : text) {
    if (separators.find(c) != std::string_view::npos) {
      continue;
    }
    if (hex_digit_value(c) < 0) {
      return false;
    }
    out.push_back(to_lower_ascii(c));
  }
  return true;
}

// ---------------------------------------------------------------------------
// Per-kind canonicalisation
// ---------------------------------------------------------------------------

bool normalize_guid(std::string_view value, std::string& out) {
  std::string digits;
  if (!strip_separators(value, "-{}() ", digits)) {
    return false;
  }
  if (digits.size() != 32) {
    return false;
  }
  out.clear();
  out.reserve(36);
  for (std::size_t i = 0; i < digits.size(); ++i) {
    if (i == 8 || i == 12 || i == 16 || i == 20) {
      out.push_back('-');
    }
    out.push_back(digits[i]);
  }
  return true;
}

bool normalize_mac(std::string_view value, std::string& out, bool& locally_administered) {
  std::string digits;
  if (!strip_separators(value, ":-.", digits)) {
    return false;
  }
  if (digits.size() != 12) {
    return false;
  }
  const int first_octet = (hex_digit_value(digits[0]) << 4) | hex_digit_value(digits[1]);
  locally_administered = (first_octet & 0x02) != 0;
  out.clear();
  out.reserve(12);
  out.assign(digits);
  return true;
}

bool normalize_pci_address(std::string_view value, std::string& out) {
  const std::string lowered = lowercase_copy(trim_ascii(value));
  const std::size_t dot = lowered.find('.');
  if (dot == std::string::npos) {
    return false;
  }
  const std::string_view function = std::string_view(lowered).substr(dot + 1);
  const std::string_view before_dot = std::string_view(lowered).substr(0, dot);
  if (function.empty() || function.size() > 1 || hex_digit_value(function[0]) < 0) {
    return false;
  }
  std::array<std::string_view, 3> parts{};
  std::size_t part_count = 0;
  std::size_t start = 0;
  while (true) {
    const std::size_t colon = before_dot.find(':', start);
    const std::string_view piece = colon == std::string_view::npos ? before_dot.substr(start)
                                                                   : before_dot.substr(start, colon - start);
    if (part_count == parts.size()) {
      return false;
    }
    parts[part_count++] = piece;
    if (colon == std::string_view::npos) {
      break;
    }
    start = colon + 1;
  }
  std::string_view domain = "0000";
  std::string_view bus;
  std::string_view device;
  if (part_count == 3) {
    domain = parts[0];
    bus = parts[1];
    device = parts[2];
  } else if (part_count == 2) {
    bus = parts[0];
    device = parts[1];
  } else {
    return false;
  }
  if (domain.empty() || domain.size() > 4 || bus.empty() || bus.size() > 2 || device.empty() || device.size() > 2) {
    return false;
  }
  const auto all_hex = [](std::string_view text) {
    for (char c : text) {
      if (hex_digit_value(c) < 0) {
        return false;
      }
    }
    return true;
  };
  if (!all_hex(domain) || !all_hex(bus) || !all_hex(device)) {
    return false;
  }
  out.clear();
  out.reserve(12);
  out.append(4 - domain.size(), '0');
  out.append(domain);
  out.push_back(':');
  out.append(2 - bus.size(), '0');
  out.append(bus);
  out.push_back(':');
  out.append(2 - device.size(), '0');
  out.append(device);
  out.push_back('.');
  out.append(function);
  return true;
}

bool normalize_host_name(std::string_view value, std::string& out) {
  std::string_view trimmed = trim_ascii(value);
  if (!trimmed.empty() && trimmed.back() == '.') {
    trimmed.remove_suffix(1);
  }
  if (trimmed.empty() || trimmed.size() > 253) {
    return false;
  }
  if (trimmed.front() == '.' || trimmed.find("..") != std::string_view::npos) {
    return false;
  }
  const std::string lowered = lowercase_copy(trimmed);
  if (!contains_only(lowered, "abcdefghijklmnopqrstuvwxyz0123456789.-_")) {
    return false;
  }
  std::size_t start = 0;
  while (start <= lowered.size()) {
    const std::size_t dot = lowered.find('.', start);
    const std::string_view label =
        dot == std::string::npos ? std::string_view(lowered).substr(start) : std::string_view(lowered).substr(start, dot - start);
    if (label.empty() || label.size() > 63) {
      return false;
    }
    if (label.front() == '-' || label.back() == '-') {
      return false;
    }
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  out.assign(lowered);
  return true;
}

bool normalize_numeric_identifier(std::string_view value, std::string& out) {
  std::string_view text = trim_ascii(value);
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    text.remove_prefix(2);
  }
  if (text.empty() || text.size() > 4) {
    return false;
  }
  std::uint32_t parsed = 0;
  for (char c : text) {
    const int digit = hex_digit_value(c);
    if (digit < 0) {
      return false;
    }
    parsed = (parsed << 4) | static_cast<std::uint32_t>(digit);
  }
  if (parsed == 0) {
    return false;
  }
  static constexpr char kDigits[] = "0123456789abcdef";
  out.assign("0x");
  for (int shift = 12; shift >= 0; shift -= 4) {
    out.push_back(kDigits[(parsed >> shift) & 0xFu]);
  }
  return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------

bool is_ascii_whitespace(char value) noexcept {
  return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\v' || value == '\f';
}

std::string_view trim_ascii(std::string_view text) noexcept {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && is_ascii_whitespace(text[begin])) {
    ++begin;
  }
  while (end > begin && is_ascii_whitespace(text[end - 1])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

bool is_valid_identity_text(std::string_view text) noexcept {
  std::size_t index = 0;
  while (index < text.size()) {
    const unsigned char raw = static_cast<unsigned char>(text[index]);
    if (raw == 0u) {
      return false;
    }
    if (raw < 0x80u) {
      if (is_ascii_control(raw)) {
        return false;
      }
      ++index;
      continue;
    }
    std::uint32_t code_point = 0;
    const std::size_t consumed = decode_utf8(text, index, code_point);
    if (consumed == 0) {
      return false;
    }
    index += consumed;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Fact kinds
// ---------------------------------------------------------------------------

namespace {

struct FactKindName {
  IdentityFactKind kind;
  std::string_view name;
  FactStrength strength;
  bool requires_scope;
};

constexpr FactKindName kFactKinds[] = {
    {IdentityFactKind::SerialNumber, "serial-number", FactStrength::Strong, true},
    {IdentityFactKind::DeviceUuid, "device-uuid", FactStrength::Strong, false},
    {IdentityFactKind::SwitchGuid, "switch-guid", FactStrength::Strong, false},
    {IdentityFactKind::PortGuid, "port-guid", FactStrength::Strong, false},
    {IdentityFactKind::FabricGuid, "fabric-guid", FactStrength::Strong, false},
    {IdentityFactKind::ChassisId, "chassis-id", FactStrength::Strong, false},
    {IdentityFactKind::SlotId, "slot-id", FactStrength::Moderate, false},
    {IdentityFactKind::BoardId, "board-id", FactStrength::Moderate, false},
    {IdentityFactKind::PciAddress, "pci-address", FactStrength::Strong, false},
    {IdentityFactKind::PermanentMac, "permanent-mac", FactStrength::Strong, false},
    {IdentityFactKind::MacAddress, "mac-address", FactStrength::Moderate, false},
    {IdentityFactKind::DeviceInstanceId, "device-instance-id", FactStrength::Strong, true},
    {IdentityFactKind::VendorId, "vendor-id", FactStrength::Weak, false},
    {IdentityFactKind::ProductId, "product-id", FactStrength::Weak, false},
    {IdentityFactKind::SubsystemId, "subsystem-id", FactStrength::Weak, false},
    {IdentityFactKind::DeviceModel, "device-model", FactStrength::Weak, false},
    {IdentityFactKind::FirmwareFamily, "firmware-family", FactStrength::Weak, false},
    {IdentityFactKind::HostName, "host-name", FactStrength::Weak, false},
    {IdentityFactKind::FriendlyName, "friendly-name", FactStrength::Weak, false},
    {IdentityFactKind::InventoryAssetId, "inventory-asset-id", FactStrength::Moderate, false},
    {IdentityFactKind::CloudResourceId, "cloud-resource-id", FactStrength::Moderate, false},
    {IdentityFactKind::OperatorLabel, "operator-label", FactStrength::Weak, false},
    {IdentityFactKind::RackSlotLabel, "rack-slot-label", FactStrength::Weak, false},
    {IdentityFactKind::PortHardwareName, "port-hardware-name", FactStrength::Moderate, false},
};

const FactKindName* find_fact_kind(IdentityFactKind kind) noexcept {
  for (const FactKindName& entry : kFactKinds) {
    if (entry.kind == kind) {
      return &entry;
    }
  }
  return nullptr;
}

FactStrength strength_of(IdentityFactKind kind) noexcept {
  const FactKindName* entry = find_fact_kind(kind);
  return entry == nullptr ? FactStrength::Weak : entry->strength;
}

bool requires_scope_of(IdentityFactKind kind) noexcept {
  const FactKindName* entry = find_fact_kind(kind);
  return entry == nullptr ? false : entry->requires_scope;
}

} // namespace

std::string_view to_string(FactStrength value) noexcept {
  switch (value) {
    case FactStrength::Weak:
      return "weak";
    case FactStrength::Moderate:
      return "moderate";
    case FactStrength::Strong:
      return "strong";
  }
  return "unknown";
}

std::string_view to_string(IdentityFactKind value) noexcept {
  const FactKindName* entry = find_fact_kind(value);
  return entry == nullptr ? std::string_view("unspecified") : entry->name;
}

std::optional<IdentityFactKind> identity_fact_kind_from_string(std::string_view text) noexcept {
  for (const FactKindName& entry : kFactKinds) {
    if (entry.name == text) {
      return entry.kind;
    }
  }
  return std::nullopt;
}

FactStrength fact_strength(IdentityFactKind kind) noexcept {
  return strength_of(kind);
}

bool fact_requires_scope(IdentityFactKind kind) noexcept {
  return requires_scope_of(kind);
}

std::string_view to_string(IdentityIssue value) noexcept {
  switch (value) {
    case IdentityIssue::None:
      return "none";
    case IdentityIssue::UnknownFactKind:
      return "unknown-fact-kind";
    case IdentityIssue::InvalidEntityClass:
      return "invalid-entity-class";
    case IdentityIssue::EmptyValue:
      return "empty-value";
    case IdentityIssue::ValueTooLong:
      return "value-too-long";
    case IdentityIssue::ScopeTooLong:
      return "scope-too-long";
    case IdentityIssue::ScopeRequired:
      return "scope-required";
    case IdentityIssue::InvalidText:
      return "invalid-text";
    case IdentityIssue::InvalidHexLength:
      return "invalid-hex-length";
    case IdentityIssue::InvalidMacAddress:
      return "invalid-mac-address";
    case IdentityIssue::LocallyAdministeredMac:
      return "locally-administered-mac";
    case IdentityIssue::InvalidGuid:
      return "invalid-guid";
    case IdentityIssue::InvalidPciAddress:
      return "invalid-pci-address";
    case IdentityIssue::InvalidNumericId:
      return "invalid-numeric-id";
    case IdentityIssue::InvalidHostName:
      return "invalid-host-name";
    case IdentityIssue::InvalidSerial:
      return "invalid-serial";
    case IdentityIssue::TooManyFacts:
      return "too-many-facts";
    case IdentityIssue::DuplicateFact:
      return "duplicate-fact";
    case IdentityIssue::ContradictoryFact:
      return "contradictory-fact";
    case IdentityIssue::NoStrongFact:
      return "no-strong-fact";
    case IdentityIssue::EmptyDerivationNamespace:
      return "empty-derivation-namespace";
    case IdentityIssue::NamespaceTooLong:
      return "namespace-too-long";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Fact canonicalisation
// ---------------------------------------------------------------------------

FactResult canonicalize_fact(IdentityFactKind kind,
                             std::string_view scope,
                             std::string_view value,
                             std::size_t max_string_bytes) {
  FactResult result;
  if (find_fact_kind(kind) == nullptr) {
    result.issue = IdentityIssue::UnknownFactKind;
    return result;
  }
  const std::string_view trimmed_scope = trim_ascii(scope);
  if (trimmed_scope.size() > max_string_bytes) {
    result.issue = IdentityIssue::ScopeTooLong;
    return result;
  }
  if (!is_valid_identity_text(trimmed_scope)) {
    result.issue = IdentityIssue::InvalidText;
    return result;
  }
  if (requires_scope_of(kind) && trimmed_scope.empty()) {
    result.issue = IdentityIssue::ScopeRequired;
    return result;
  }
  if (value.size() > max_string_bytes) {
    result.issue = IdentityIssue::ValueTooLong;
    return result;
  }

  const std::string_view trimmed = trim_ascii(value);
  if (trimmed.empty()) {
    result.issue = IdentityIssue::EmptyValue;
    return result;
  }
  if (!is_valid_identity_text(trimmed)) {
    result.issue = IdentityIssue::InvalidText;
    return result;
  }

  std::string canonical;
  switch (kind) {
    case IdentityFactKind::SerialNumber: {
      canonical.assign(trimmed);
      break;
    }
    case IdentityFactKind::DeviceUuid:
    case IdentityFactKind::SwitchGuid:
    case IdentityFactKind::PortGuid:
    case IdentityFactKind::FabricGuid: {
      if (!normalize_guid(trimmed, canonical)) {
        result.issue = IdentityIssue::InvalidGuid;
        return result;
      }
      break;
    }
    case IdentityFactKind::PciAddress: {
      if (!normalize_pci_address(trimmed, canonical)) {
        result.issue = IdentityIssue::InvalidPciAddress;
        return result;
      }
      break;
    }
    case IdentityFactKind::PermanentMac:
    case IdentityFactKind::MacAddress: {
      bool locally_administered = false;
      if (!normalize_mac(trimmed, canonical, locally_administered)) {
        result.issue = IdentityIssue::InvalidMacAddress;
        return result;
      }
      if (kind == IdentityFactKind::PermanentMac && locally_administered) {
        result.issue = IdentityIssue::LocallyAdministeredMac;
        return result;
      }
      break;
    }
    case IdentityFactKind::VendorId:
    case IdentityFactKind::ProductId:
    case IdentityFactKind::SubsystemId: {
      if (!normalize_numeric_identifier(trimmed, canonical)) {
        result.issue = IdentityIssue::InvalidNumericId;
        return result;
      }
      break;
    }
    case IdentityFactKind::HostName: {
      if (!normalize_host_name(trimmed, canonical)) {
        result.issue = IdentityIssue::InvalidHostName;
        return result;
      }
      break;
    }
    case IdentityFactKind::DeviceInstanceId: {
      canonical = lowercase_copy(trimmed);
      break;
    }
    default: {
      canonical.assign(trimmed);
      break;
    }
  }

  if (canonical.size() > max_string_bytes) {
    result.issue = IdentityIssue::ValueTooLong;
    return result;
  }

  IdentityFact fact;
  fact.kind = kind;
  fact.scope.assign(trimmed_scope);
  fact.value = std::move(canonical);
  result.fact = std::move(fact);
  return result;
}

IdentityIssue normalize_fact_set(std::span<const IdentityFact> facts,
                                 std::size_t max_facts,
                                 std::size_t max_string_bytes,
                                 std::vector<IdentityFact>& out) {
  out.clear();
  if (facts.size() > max_facts) {
    return IdentityIssue::TooManyFacts;
  }
  out.reserve(facts.size());
  for (const IdentityFact& fact : facts) {
    FactResult canonical = canonicalize_fact(fact.kind, fact.scope, fact.value, max_string_bytes);
    if (!canonical) {
      // A rejected fact set leaves no partial result behind.
      out.clear();
      return canonical.issue;
    }
    out.push_back(std::move(*canonical.fact));
  }
  std::sort(out.begin(), out.end());
  for (std::size_t i = 1; i < out.size(); ++i) {
    const IdentityFact& previous = out[i - 1];
    const IdentityFact& current = out[i];
    if (previous.kind != current.kind || previous.scope != current.scope) {
      continue;
    }
    const IdentityIssue issue =
        previous.value == current.value ? IdentityIssue::DuplicateFact : IdentityIssue::ContradictoryFact;
    out.clear();
    return issue;
  }
  return IdentityIssue::None;
}

bool has_strong_fact(std::span<const IdentityFact> facts) noexcept {
  for (const IdentityFact& fact : facts) {
    if (strength_of(fact.kind) == FactStrength::Strong) {
      return true;
    }
  }
  return false;
}

std::vector<IdentityFact> significant_facts(std::span<const IdentityFact> facts) {
  std::vector<IdentityFact> out;
  out.reserve(facts.size());
  for (const IdentityFact& fact : facts) {
    if (strength_of(fact.kind) != FactStrength::Weak) {
      out.push_back(fact);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

namespace {

std::vector<IdentityFact> strong_facts_sorted(std::span<const IdentityFact> facts) {
  std::vector<IdentityFact> out;
  out.reserve(facts.size());
  for (const IdentityFact& fact : facts) {
    if (strength_of(fact.kind) == FactStrength::Strong) {
      out.push_back(fact);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

void hash_facts(CanonicalHasher& hasher, const std::vector<IdentityFact>& facts) {
  hasher.sequence(static_cast<std::uint64_t>(facts.size()));
  for (const IdentityFact& fact : facts) {
    hasher.u8(static_cast<std::uint8_t>(fact.kind));
    hasher.text(fact.scope);
    hasher.text(fact.value);
  }
}

} // namespace

StableHardwareIdentity compute_stable_hardware_identity(std::span<const IdentityFact> facts) {
  const std::vector<IdentityFact> strong = strong_facts_sorted(facts);
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/stable-hardware-identity/1");
  hash_facts(hasher, strong);
  return StableHardwareIdentity::from_bytes(hasher.finish());
}

FingerprintDigest compute_identity_fingerprint(EntityClass entity_class,
                                               std::string_view derivation_namespace,
                                               std::span<const IdentityFact> facts) {
  const std::vector<IdentityFact> strong = strong_facts_sorted(facts);
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/identity-fingerprint/1");
  hasher.u8(static_cast<std::uint8_t>(entity_class));
  hasher.text(derivation_namespace);
  hash_facts(hasher, strong);
  return FingerprintDigest::from_bytes(hasher.finish());
}

CanonicalIdResult derive_canonical_id(EntityClass entity_class,
                                      std::string_view derivation_namespace,
                                      std::span<const IdentityFact> facts,
                                      std::size_t max_string_bytes) {
  CanonicalIdResult result;
  if (!is_valid_entity_class(entity_class)) {
    result.issue = IdentityIssue::InvalidEntityClass;
    return result;
  }
  if (derivation_namespace.empty()) {
    result.issue = IdentityIssue::EmptyDerivationNamespace;
    return result;
  }
  if (derivation_namespace.size() > max_string_bytes) {
    result.issue = IdentityIssue::NamespaceTooLong;
    return result;
  }
  if (!has_strong_fact(facts)) {
    result.issue = IdentityIssue::NoStrongFact;
    return result;
  }
  const FingerprintDigest fingerprint = compute_identity_fingerprint(entity_class, derivation_namespace, facts);
  IdBytes bytes{};
  for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
    bytes[i] = fingerprint.bytes()[i];
  }
  result.id = CanonicalId(entity_class, bytes);
  if (result.id->is_null()) {
    // A 128-bit digest of all zeros is astronomically improbable but is not a
    // legal identity; refuse rather than mint an id that means "absent".
    result.id.reset();
    result.issue = IdentityIssue::NoStrongFact;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

namespace {

struct AliasNamespaceInfo {
  AliasNamespace value;
  std::string_view name;
  AliasScope scope;
};

constexpr AliasNamespaceInfo kAliasNamespaces[] = {
    {AliasNamespace::HostName, "host-name", AliasScope::Fabric},
    {AliasNamespace::SwitchHostName, "switch-host-name", AliasScope::Fabric},
    {AliasNamespace::VendorGuid, "vendor-guid", AliasScope::Global},
    {AliasNamespace::MacAddress, "mac-address", AliasScope::Global},
    {AliasNamespace::InventoryAssetId, "inventory-asset-id", AliasScope::Site},
    {AliasNamespace::OperatorLabel, "operator-label", AliasScope::Informational},
    {AliasNamespace::RackSlotLabel, "rack-slot-label", AliasScope::Site},
    {AliasNamespace::CloudResourceId, "cloud-resource-id", AliasScope::Global},
    {AliasNamespace::ExternalCmdbId, "external-cmdb-id", AliasScope::Global},
    {AliasNamespace::PortName, "port-name", AliasScope::ParentDevice},
    {AliasNamespace::DnsName, "dns-name", AliasScope::Global},
    {AliasNamespace::SerialNumber, "serial-number", AliasScope::Global},
    {AliasNamespace::DeviceInstanceId, "device-instance-id", AliasScope::Site},
};

const AliasNamespaceInfo* find_alias_namespace(AliasNamespace value) noexcept {
  for (const AliasNamespaceInfo& entry : kAliasNamespaces) {
    if (entry.value == value) {
      return &entry;
    }
  }
  return nullptr;
}

} // namespace

std::string_view to_string(AliasNamespace value) noexcept {
  const AliasNamespaceInfo* entry = find_alias_namespace(value);
  return entry == nullptr ? std::string_view("unspecified") : entry->name;
}

std::optional<AliasNamespace> alias_namespace_from_string(std::string_view text) noexcept {
  for (const AliasNamespaceInfo& entry : kAliasNamespaces) {
    if (entry.name == text) {
      return entry.value;
    }
  }
  return std::nullopt;
}

AliasScope alias_scope(AliasNamespace value) noexcept {
  const AliasNamespaceInfo* entry = find_alias_namespace(value);
  return entry == nullptr ? AliasScope::Informational : entry->scope;
}

bool alias_is_unique(AliasNamespace value) noexcept {
  return alias_scope(value) != AliasScope::Informational;
}

std::string_view to_string(AliasScope value) noexcept {
  switch (value) {
    case AliasScope::Global:
      return "global";
    case AliasScope::Fabric:
      return "fabric";
    case AliasScope::Site:
      return "site";
    case AliasScope::EntityClass:
      return "entity-class";
    case AliasScope::ParentDevice:
      return "parent-device";
    case AliasScope::Informational:
      return "informational";
  }
  return "unknown";
}

std::string_view to_string(AliasIssue value) noexcept {
  switch (value) {
    case AliasIssue::None:
      return "none";
    case AliasIssue::UnknownNamespace:
      return "unknown-namespace";
    case AliasIssue::EmptyValue:
      return "empty-value";
    case AliasIssue::ValueTooLong:
      return "value-too-long";
    case AliasIssue::InvalidText:
      return "invalid-text";
    case AliasIssue::InvalidMacAddress:
      return "invalid-mac-address";
    case AliasIssue::InvalidGuid:
      return "invalid-guid";
    case AliasIssue::InvalidHostName:
      return "invalid-host-name";
    case AliasIssue::InvalidSerial:
      return "invalid-serial";
    case AliasIssue::MissingFabricScope:
      return "missing-fabric-scope";
    case AliasIssue::MissingSiteScope:
      return "missing-site-scope";
    case AliasIssue::MissingEntityClassScope:
      return "missing-entity-class-scope";
    case AliasIssue::MissingParentDeviceScope:
      return "missing-parent-device-scope";
  }
  return "unknown";
}

AliasNameResult canonicalize_alias(AliasNamespace alias_namespace,
                                   std::string_view value,
                                   std::size_t max_string_bytes) {
  AliasNameResult result;
  if (find_alias_namespace(alias_namespace) == nullptr) {
    result.issue = AliasIssue::UnknownNamespace;
    return result;
  }
  if (value.size() > max_string_bytes) {
    result.issue = AliasIssue::ValueTooLong;
    return result;
  }
  const std::string_view trimmed = trim_ascii(value);
  if (trimmed.empty()) {
    result.issue = AliasIssue::EmptyValue;
    return result;
  }
  if (!is_valid_identity_text(trimmed)) {
    result.issue = AliasIssue::InvalidText;
    return result;
  }

  AliasName name;
  name.alias_namespace = alias_namespace;
  switch (alias_namespace) {
    case AliasNamespace::HostName:
    case AliasNamespace::SwitchHostName:
    case AliasNamespace::DnsName: {
      if (!normalize_host_name(trimmed, name.value)) {
        result.issue = AliasIssue::InvalidHostName;
        return result;
      }
      break;
    }
    case AliasNamespace::VendorGuid: {
      if (!normalize_guid(trimmed, name.value)) {
        result.issue = AliasIssue::InvalidGuid;
        return result;
      }
      break;
    }
    case AliasNamespace::MacAddress: {
      bool locally_administered = false;
      if (!normalize_mac(trimmed, name.value, locally_administered)) {
        result.issue = AliasIssue::InvalidMacAddress;
        return result;
      }
      break;
    }
    case AliasNamespace::SerialNumber: {
      if (trimmed.size() > SerialIdentity::max_value_bytes) {
        result.issue = AliasIssue::ValueTooLong;
        return result;
      }
      name.value.assign(trimmed);
      break;
    }
    case AliasNamespace::DeviceInstanceId: {
      name.value = lowercase_copy(trimmed);
      break;
    }
    default: {
      name.value.assign(trimmed);
      break;
    }
  }
  if (name.value.size() > max_string_bytes) {
    result.issue = AliasIssue::ValueTooLong;
    return result;
  }
  result.name = std::move(name);
  return result;
}

std::string AliasKey::to_string() const {
  std::string out(fabric_registry::to_string(alias_namespace));
  out.push_back(':');
  out.append(scope);
  out.push_back('=');
  out.append(value);
  return out;
}

std::optional<AliasKey> AliasKey::parse(std::string_view text) {
  const std::size_t separator = text.find(':');
  if (separator == std::string_view::npos) {
    return std::nullopt;
  }
  const std::optional<AliasNamespace> alias_namespace =
      alias_namespace_from_string(text.substr(0, separator));
  if (!alias_namespace.has_value()) {
    return std::nullopt;
  }
  const std::string_view rest = text.substr(separator + 1);
  const std::size_t equals = rest.find('=');
  if (equals == std::string_view::npos) {
    return std::nullopt;
  }
  const std::string_view scope = rest.substr(0, equals);
  const std::string_view value = rest.substr(equals + 1);
  if (value.empty() || value.size() > kIdentityValueHardLimit) {
    return std::nullopt;
  }
  const AliasScope expected = alias_scope(*alias_namespace);
  const bool scope_ok = [&]() {
    switch (expected) {
      case AliasScope::Global:
        return scope.empty();
      case AliasScope::Fabric:
        return scope.rfind("fabric:", 0) == 0 && scope.size() == 7u + kOpaqueIdTextLength;
      case AliasScope::Site:
        return scope.rfind("site:", 0) == 0 && scope.size() == 5u + kOpaqueIdTextLength;
      case AliasScope::EntityClass:
        return scope.rfind("class:", 0) == 0 &&
               entity_class_from_string(scope.substr(6)).has_value();
      case AliasScope::ParentDevice:
        return scope.rfind("parent:", 0) == 0 &&
               CanonicalId::parse(scope.substr(7)).has_value();
      case AliasScope::Informational:
        return scope == "info";
    }
    return false;
  }();
  if (!scope_ok) {
    return std::nullopt;
  }
  AliasKey key;
  key.alias_namespace = *alias_namespace;
  key.scope.assign(scope);
  key.value.assign(value);
  return key;
}

AliasKeyResult make_alias_key(const AliasName& name, const AliasScopeInput& scope) {
  AliasKeyResult result;
  if (find_alias_namespace(name.alias_namespace) == nullptr) {
    result.issue = AliasIssue::UnknownNamespace;
    return result;
  }
  if (name.value.empty()) {
    result.issue = AliasIssue::EmptyValue;
    return result;
  }
  AliasKey key;
  key.alias_namespace = name.alias_namespace;
  key.value = name.value;
  switch (alias_scope(name.alias_namespace)) {
    case AliasScope::Global: {
      key.scope.clear();
      break;
    }
    case AliasScope::Fabric: {
      if (!scope.fabric.has_value() || scope.fabric->is_null()) {
        result.issue = AliasIssue::MissingFabricScope;
        return result;
      }
      key.scope = "fabric:" + scope.fabric->to_string();
      break;
    }
    case AliasScope::Site: {
      if (!scope.site.has_value() || scope.site->is_null()) {
        result.issue = AliasIssue::MissingSiteScope;
        return result;
      }
      key.scope = "site:" + scope.site->to_string();
      break;
    }
    case AliasScope::EntityClass: {
      if (!is_valid_entity_class(scope.entity_class)) {
        result.issue = AliasIssue::MissingEntityClassScope;
        return result;
      }
      key.scope = std::string("class:") + std::string(fabric_registry::to_string(scope.entity_class));
      break;
    }
    case AliasScope::ParentDevice: {
      if (!scope.parent_device.has_value() || scope.parent_device->is_null()) {
        result.issue = AliasIssue::MissingParentDeviceScope;
        return result;
      }
      key.scope = "parent:" + scope.parent_device->to_string();
      break;
    }
    case AliasScope::Informational: {
      key.scope = "info";
      break;
    }
  }
  result.key = std::move(key);
  return result;
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

std::string_view to_string(ProvenanceClass value) noexcept {
  switch (value) {
    case ProvenanceClass::Unknown:
      return "unknown";
    case ProvenanceClass::Real:
      return "real";
    case ProvenanceClass::Synthetic:
      return "synthetic";
    case ProvenanceClass::Unsupported:
      return "unsupported";
  }
  return "unknown";
}

std::optional<ProvenanceClass> provenance_class_from_string(std::string_view text) noexcept {
  if (text == "unknown") {
    return ProvenanceClass::Unknown;
  }
  if (text == "real") {
    return ProvenanceClass::Real;
  }
  if (text == "synthetic") {
    return ProvenanceClass::Synthetic;
  }
  if (text == "unsupported") {
    return ProvenanceClass::Unsupported;
  }
  return std::nullopt;
}

std::string_view to_string(ObservationSource value) noexcept {
  switch (value) {
    case ObservationSource::Unspecified:
      return "unspecified";
    case ObservationSource::OperatorDeclaration:
      return "operator-declaration";
    case ObservationSource::LocalHostEnumeration:
      return "local-host-enumeration";
    case ObservationSource::DeviceAgent:
      return "device-agent";
    case ObservationSource::ControllerPush:
      return "controller-push";
    case ObservationSource::ImportedInventory:
      return "imported-inventory";
    case ObservationSource::ExternalCmdb:
      return "external-cmdb";
    case ObservationSource::SyntheticFixture:
      return "synthetic-fixture";
    case ObservationSource::PeerRegistry:
      return "peer-registry";
  }
  return "unspecified";
}

std::optional<ObservationSource> observation_source_from_string(std::string_view text) noexcept {
  for (std::uint8_t raw = 0; raw <= kObservationSourceCount; ++raw) {
    const ObservationSource value = static_cast<ObservationSource>(raw);
    if (to_string(value) == text) {
      return value;
    }
  }
  return std::nullopt;
}

ValidationResult validate_provenance(const Provenance& provenance, std::size_t max_string_bytes) {
  if (provenance.validity_class == ProvenanceClass::Unknown) {
    return ValidationResult::failure("provenance.validity_class must be real, synthetic or unsupported");
  }
  if (provenance.source == ObservationSource::Unspecified) {
    return ValidationResult::failure("provenance.source must name a concrete observation source");
  }
  if (provenance.mechanism.size() > max_string_bytes) {
    return ValidationResult::failure("provenance.mechanism exceeds the configured string bound");
  }
  if (provenance.source_identity.size() > max_string_bytes) {
    return ValidationResult::failure("provenance.source_identity exceeds the configured string bound");
  }
  if (!is_valid_identity_text(provenance.mechanism)) {
    return ValidationResult::failure("provenance.mechanism is not valid identity text");
  }
  if (!is_valid_identity_text(provenance.source_identity)) {
    return ValidationResult::failure("provenance.source_identity is not valid identity text");
  }
  if (provenance.validity_class == ProvenanceClass::Unsupported) {
    return ValidationResult::failure("provenance.validity_class unsupported cannot back a registered record");
  }
  return ValidationResult::success();
}

std::string_view to_string(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::Unspecified:
      return "unspecified";
    case EvidenceClass::ProcessBound:
      return "process-bound";
    case EvidenceClass::DurableAuthority:
      return "durable-authority";
  }
  return "unspecified";
}

std::string_view to_string(MatchClass value) noexcept {
  switch (value) {
    case MatchClass::NoMatch:
      return "no-match";
    case MatchClass::ExactCanonical:
      return "exact-canonical";
    case MatchClass::ProvenAlias:
      return "proven-alias";
    case MatchClass::StableHardware:
      return "stable-hardware";
    case MatchClass::ProbableInsufficient:
      return "probable-insufficient";
    case MatchClass::Conflicting:
      return "conflicting";
    case MatchClass::Ambiguous:
      return "ambiguous";
  }
  return "unknown";
}

} // namespace fabric_registry
