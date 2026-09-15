// Fabric Registry — strongly typed identifiers.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every identity domain in Fabric Registry has its own C++ type. Two ids from
// different domains are not convertible, not comparable and not interchangeable
// as map keys. Opaque ids are 128-bit values rendered as 32 lowercase hex
// characters; counters are 64-bit monotonic values rendered as decimal.
//
// The all-zero value of every id type is the null (absent) id. Null ids are
// rejected wherever an operation requires a real identity.

#ifndef FABRIC_REGISTRY_IDS_HPP
#define FABRIC_REGISTRY_IDS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <compare>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

#include "fabric_registry/entity_class.hpp"
#include "fabric_registry/export.hpp"

namespace fabric_registry {

/// Width of every opaque identifier in Fabric Registry.
inline constexpr std::size_t kOpaqueIdBytes = 16;

/// Width of the 32-character lowercase hex rendering of an opaque id.
inline constexpr std::size_t kOpaqueIdTextLength = kOpaqueIdBytes * 2;

/// Width of a SHA-256 digest in bytes.
inline constexpr std::size_t kDigestBytes = 32;

/// Hard ceiling applied to any single identity value (serial, MAC, GUID,
/// friendly name input, ...) before the configurable limits are consulted.
/// Nothing in the library allocates an identity string larger than this.
inline constexpr std::size_t kIdentityValueHardLimit = 1024;

using IdBytes = std::array<std::uint8_t, kOpaqueIdBytes>;
using DigestBytes = std::array<std::uint8_t, kDigestBytes>;

/// Renders bytes as lowercase hex into a caller-owned buffer.
FABRIC_REGISTRY_API void render_hex(const std::uint8_t* data, std::size_t size, char* out) noexcept;

/// Parses exactly `size * 2` hexadecimal characters into `out`. Accepts upper
/// and lower case on input; returns false for any other length or character.
FABRIC_REGISTRY_API bool parse_hex(const char* text, std::size_t size, std::uint8_t* out) noexcept;

// ---------------------------------------------------------------------------
// Opaque identifiers
// ---------------------------------------------------------------------------

/// Tag traits. `is_entity_id` is true only for tags that denote a class of
/// registry entity, which is what makes them usable with CanonicalId.
template <class Tag>
struct IdTagTraits {
  static constexpr bool is_entity_id = false;
  static constexpr EntityClass entity_class = EntityClass::Unknown;
  static constexpr std::string_view domain_name = "opaque";
};

/// A 128-bit opaque identifier belonging to the identity domain named by Tag.
template <class Tag>
class OpaqueId {
public:
  using tag_type = Tag;
  static constexpr std::size_t byte_size = kOpaqueIdBytes;
  static constexpr std::string_view domain_name = IdTagTraits<Tag>::domain_name;

  constexpr OpaqueId() noexcept = default;

  static constexpr OpaqueId from_bytes(const IdBytes& value) noexcept {
    OpaqueId result;
    result.bytes_ = value;
    return result;
  }

  /// Interprets the first 16 bytes of a 32-byte digest as an identifier. Used
  /// for deterministic identity derivation; never used to mint process
  /// incarnations.
  static constexpr OpaqueId from_digest(const DigestBytes& digest) noexcept {
    OpaqueId result;
    for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
      result.bytes_[i] = digest[i];
    }
    return result;
  }

  /// Parses exactly 32 hexadecimal characters. Returns nullopt for any other
  /// length, for non-hexadecimal characters and for overflow-free but malformed
  /// text; it never guesses or truncates.
  static std::optional<OpaqueId> parse(std::string_view text) noexcept {
    if (text.size() != kOpaqueIdTextLength) {
      return std::nullopt;
    }
    IdBytes value{};
    if (!parse_hex(text.data(), text.size(), value.data())) {
      return std::nullopt;
    }
    return OpaqueId::from_bytes(value);
  }

  constexpr bool is_null() const noexcept {
    for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
      if (bytes_[i] != 0) {
        return false;
      }
    }
    return true;
  }

  constexpr const IdBytes& bytes() const noexcept { return bytes_; }
  constexpr const std::uint8_t* data() const noexcept { return bytes_.data(); }

  std::string to_string() const {
    std::string out(kOpaqueIdTextLength, '0');
    render_hex(bytes_.data(), bytes_.size(), out.data());
    return out;
  }

  friend constexpr bool operator==(const OpaqueId&, const OpaqueId&) noexcept = default;
  friend constexpr auto operator<=>(const OpaqueId&, const OpaqueId&) noexcept = default;

private:
  IdBytes bytes_{};
};

// Identity domain tags. The tags are incomplete types on purpose: they exist
// only to give each OpaqueId instantiation a distinct C++ type.
#define FABRIC_REGISTRY_DECLARE_TAG(tag_name, domain, entity)      \
  struct tag_name##Tag;                                            \
  template <>                                                      \
  struct IdTagTraits<tag_name##Tag> {                              \
    static constexpr bool is_entity_id = true;                     \
    static constexpr EntityClass entity_class = EntityClass::entity; \
    static constexpr std::string_view domain_name = domain;        \
  };                                                               \
  using tag_name##Id = OpaqueId<tag_name##Tag>

FABRIC_REGISTRY_DECLARE_TAG(Fabric, "fabric", Fabric);
FABRIC_REGISTRY_DECLARE_TAG(Site, "site", Site);
FABRIC_REGISTRY_DECLARE_TAG(SubFabric, "sub-fabric", SubFabric);
FABRIC_REGISTRY_DECLARE_TAG(ControlDomain, "control-domain", ControlDomain);
FABRIC_REGISTRY_DECLARE_TAG(Switch, "switch", Switch);
FABRIC_REGISTRY_DECLARE_TAG(Router, "router", Router);
FABRIC_REGISTRY_DECLARE_TAG(Nic, "nic", Nic);
FABRIC_REGISTRY_DECLARE_TAG(SmartNic, "smartnic", SmartNic);
FABRIC_REGISTRY_DECLARE_TAG(Dpu, "dpu", Dpu);
FABRIC_REGISTRY_DECLARE_TAG(Host, "host", Host);
FABRIC_REGISTRY_DECLARE_TAG(Port, "port", Port);
FABRIC_REGISTRY_DECLARE_TAG(Link, "link", Link);
FABRIC_REGISTRY_DECLARE_TAG(Endpoint, "endpoint", Endpoint);
FABRIC_REGISTRY_DECLARE_TAG(ControlParticipant, "control-participant", ControlParticipant);
FABRIC_REGISTRY_DECLARE_TAG(VendorDevice, "vendor-device", VendorDevice);

#undef FABRIC_REGISTRY_DECLARE_TAG

// Identity domains that are not entity classes. These ids never take part in
// canonical entity addressing; they identify authority principals and attempts.
struct PublisherTag;
struct WorkerBootTag;
struct RegistrationTag;

template <>
struct IdTagTraits<PublisherTag> {
  static constexpr std::string_view domain_name = "publisher";
};
template <>
struct IdTagTraits<WorkerBootTag> {
  static constexpr std::string_view domain_name = "worker-boot";
};
template <>
struct IdTagTraits<RegistrationTag> {
  static constexpr std::string_view domain_name = "registration";
};

using PublisherId = OpaqueId<PublisherTag>;
using WorkerBootId = OpaqueId<WorkerBootTag>;
using RegistrationId = OpaqueId<RegistrationTag>;

// ---------------------------------------------------------------------------
// Monotonic counters
// ---------------------------------------------------------------------------

struct CoordinatorEpochTag;
struct RecordGenerationTag;
struct EvidenceGenerationTag;
struct RegistryGenerationTag;
struct SnapshotSequenceTag;

/// A 64-bit unsigned counter with checked increment. `next()` returns nullopt
/// instead of wrapping, so overflow is always surfaced as a failure rather than
/// silently restarting a generation space.
template <class Tag>
class Counter {
public:
  using tag_type = Tag;
  static constexpr std::uint64_t max_value() noexcept { return UINT64_MAX; }

  constexpr Counter() noexcept = default;
  constexpr explicit Counter(std::uint64_t value) noexcept : value_(value) {}

  static constexpr Counter first() noexcept { return Counter(1); }

  static std::optional<Counter> parse(std::string_view text) noexcept {
    if (text.empty() || text.size() > 20) {
      return std::nullopt;
    }
    std::uint64_t value = 0;
    for (char c : text) {
      if (c < '0' || c > '9') {
        return std::nullopt;
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
      if (value > (UINT64_MAX - digit) / 10u) {
        return std::nullopt;
      }
      value = value * 10u + digit;
    }
    return Counter(value);
  }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }

  std::optional<Counter> next() const noexcept {
    if (value_ == UINT64_MAX) {
      return std::nullopt;
    }
    return Counter(value_ + 1u);
  }

  std::string to_string() const {
    char buffer[24] = {};
    std::size_t index = sizeof(buffer);
    std::uint64_t value = value_;
    do {
      buffer[--index] = static_cast<char>('0' + static_cast<int>(value % 10u));
      value /= 10u;
    } while (value != 0);
    return std::string(buffer + index, sizeof(buffer) - index);
  }

  friend constexpr bool operator==(const Counter&, const Counter&) noexcept = default;
  friend constexpr auto operator<=>(const Counter&, const Counter&) noexcept = default;

private:
  std::uint64_t value_{0};
};

using CoordinatorEpoch = Counter<CoordinatorEpochTag>;
using RecordGeneration = Counter<RecordGenerationTag>;
using EvidenceGeneration = Counter<EvidenceGenerationTag>;
using RegistryGeneration = Counter<RegistryGenerationTag>;
using SnapshotSequence = Counter<SnapshotSequenceTag>;

// ---------------------------------------------------------------------------
// Digest values
// ---------------------------------------------------------------------------

/// A 32-byte digest belonging to the semantic domain named by Tag. Distinct
/// digest domains are distinct C++ types so that, for example, a request digest
/// can never be passed where a state digest is expected.
template <class Tag>
class DigestValue {
public:
  using tag_type = Tag;
  static constexpr std::size_t byte_size = kDigestBytes;

  constexpr DigestValue() noexcept = default;

  static constexpr DigestValue from_bytes(const DigestBytes& value) noexcept {
    DigestValue result;
    result.bytes_ = value;
    return result;
  }

  static std::optional<DigestValue> parse(std::string_view text) noexcept {
    if (text.size() != kDigestBytes * 2) {
      return std::nullopt;
    }
    DigestBytes value{};
    if (!parse_hex(text.data(), text.size(), value.data())) {
      return std::nullopt;
    }
    return DigestValue::from_bytes(value);
  }

  constexpr bool is_null() const noexcept {
    for (std::size_t i = 0; i < kDigestBytes; ++i) {
      if (bytes_[i] != 0) {
        return false;
      }
    }
    return true;
  }

  constexpr const DigestBytes& bytes() const noexcept { return bytes_; }
  constexpr const std::uint8_t* data() const noexcept { return bytes_.data(); }

  std::string to_string() const {
    std::string out(kDigestBytes * 2, '0');
    render_hex(bytes_.data(), bytes_.size(), out.data());
    return out;
  }

  friend constexpr bool operator==(const DigestValue&, const DigestValue&) noexcept = default;
  friend constexpr auto operator<=>(const DigestValue&, const DigestValue&) noexcept = default;

private:
  DigestBytes bytes_{};
};

struct StateDigestTag;
struct RequestDigestTag;
struct HardwareIdentityTag;
struct FingerprintTag;

/// Digest over the complete canonical registry state.
using StateDigest = DigestValue<StateDigestTag>;
/// Digest over the exact bytes of a mutation request, used for idempotency.
using RequestDigest = DigestValue<RequestDigestTag>;
/// Digest over the canonicalised strong hardware fact set of one entity.
using StableHardwareIdentity = DigestValue<HardwareIdentityTag>;
/// Digest over the canonical identity inputs used to derive a canonical id.
using FingerprintDigest = DigestValue<FingerprintTag>;

// ---------------------------------------------------------------------------
// Canonical (class-qualified) identity
// ---------------------------------------------------------------------------

/// The registry-wide identity of an entity: its entity class plus its 128-bit
/// opaque id. Qualifying by class is what keeps a port id and a switch id from
/// ever being confused, even if their bytes coincide.
class FABRIC_REGISTRY_API CanonicalId {
public:
  constexpr CanonicalId() noexcept = default;

  constexpr CanonicalId(EntityClass entity_class, const IdBytes& value) noexcept
      : entity_class_(entity_class), bytes_(value) {}

  /// Builds a canonical id from a class-specific id type. Only entity id types
  /// participate; PublisherId, WorkerBootId and RegistrationId do not compile.
  template <class TypedId,
            std::enable_if_t<IdTagTraits<typename TypedId::tag_type>::is_entity_id, int> = 0>
  static CanonicalId of(const TypedId& id) noexcept {
    return CanonicalId(IdTagTraits<typename TypedId::tag_type>::entity_class, id.bytes());
  }

  /// Recovers the class-specific id when, and only when, the class matches.
  template <class TypedId,
            std::enable_if_t<IdTagTraits<typename TypedId::tag_type>::is_entity_id, int> = 0>
  std::optional<TypedId> as() const noexcept {
    if (entity_class_ != IdTagTraits<typename TypedId::tag_type>::entity_class) {
      return std::nullopt;
    }
    return TypedId::from_bytes(bytes_);
  }

  static std::optional<CanonicalId> parse(std::string_view text) noexcept;
  static std::optional<CanonicalId> parse(EntityClass entity_class, std::string_view text) noexcept;

  constexpr EntityClass entity_class() const noexcept { return entity_class_; }
  constexpr const IdBytes& bytes() const noexcept { return bytes_; }

  /// True when the class is Unknown or the id bytes are all zero.
  constexpr bool is_null() const noexcept {
    if (entity_class_ == EntityClass::Unknown) {
      return true;
    }
    for (std::size_t i = 0; i < kOpaqueIdBytes; ++i) {
      if (bytes_[i] != 0) {
        return false;
      }
    }
    return true;
  }

  /// Renders as "<class>:<32 hex>", e.g. "switch:6f1c...".
  std::string to_string() const;

  friend constexpr bool operator==(const CanonicalId&, const CanonicalId&) noexcept = default;
  friend constexpr auto operator<=>(const CanonicalId&, const CanonicalId&) noexcept = default;

private:
  EntityClass entity_class_{EntityClass::Unknown};
  IdBytes bytes_{};
};

/// A class-qualified identity restricted to device-bearing entity classes.
class FABRIC_REGISTRY_API DeviceId {
public:
  constexpr DeviceId() noexcept = default;

  /// Returns nullopt when the canonical id is not a device class.
  static std::optional<DeviceId> from_canonical(const CanonicalId& id) noexcept;

  static std::optional<DeviceId> parse(std::string_view text) noexcept;

  constexpr const CanonicalId& canonical() const noexcept { return canonical_; }
  constexpr EntityClass entity_class() const noexcept { return canonical_.entity_class(); }
  constexpr bool is_null() const noexcept { return canonical_.is_null(); }

  std::string to_string() const { return canonical_.to_string(); }

  friend constexpr bool operator==(const DeviceId&, const DeviceId&) noexcept = default;
  friend constexpr auto operator<=>(const DeviceId&, const DeviceId&) noexcept = default;

private:
  CanonicalId canonical_{};
};

// ---------------------------------------------------------------------------
// Vendor / product / serial identity
// ---------------------------------------------------------------------------

/// A 16-bit vendor identifier in the PCI/PCIe identifier space, rendered as
/// "0x15b3". Null (0x0000) is not a legal vendor identifier.
class FABRIC_REGISTRY_API VendorId {
public:
  constexpr VendorId() noexcept = default;
  constexpr explicit VendorId(std::uint16_t value) noexcept : value_(value) {}

  static std::optional<VendorId> parse(std::string_view text) noexcept;

  constexpr std::uint16_t value() const noexcept { return value_; }
  constexpr bool is_null() const noexcept { return value_ == 0; }
  std::string to_string() const;

  friend constexpr bool operator==(const VendorId&, const VendorId&) noexcept = default;
  friend constexpr auto operator<=>(const VendorId&, const VendorId&) noexcept = default;

private:
  std::uint16_t value_{0};
};

/// A 16-bit product (device) identifier in the PCI/PCIe identifier space,
/// rendered as "0x1017".
class FABRIC_REGISTRY_API ProductId {
public:
  constexpr ProductId() noexcept = default;
  constexpr explicit ProductId(std::uint16_t value) noexcept : value_(value) {}

  static std::optional<ProductId> parse(std::string_view text) noexcept;

  constexpr std::uint16_t value() const noexcept { return value_; }
  constexpr bool is_null() const noexcept { return value_ == 0; }
  std::string to_string() const;

  friend constexpr bool operator==(const ProductId&, const ProductId&) noexcept = default;
  friend constexpr auto operator<=>(const ProductId&, const ProductId&) noexcept = default;

private:
  std::uint16_t value_{0};
};

/// A serial number together with the scope in which it is meaningful.
///
/// A serial number is only unique inside the namespace that issued it, which is
/// normally a (vendor, product) pair or an administrative domain. Fabric
/// Registry therefore never treats a bare serial string as a global identity:
/// the scope is part of the value and part of every index key built from it.
class FABRIC_REGISTRY_API SerialIdentity {
public:
  static constexpr std::size_t max_value_bytes = 256;
  static constexpr std::size_t max_scope_bytes = 256;

  /// Validates and normalises a serial identity. The value is trimmed of
  /// surrounding ASCII whitespace and must then be non-empty, at most
  /// max_value_bytes long, and free of control characters. The scope must be
  /// non-empty and at most max_scope_bytes long.
  static std::optional<SerialIdentity> parse(std::string_view value, std::string_view scope);

  const std::string& value() const noexcept { return value_; }
  const std::string& scope() const noexcept { return scope_; }
  bool is_null() const noexcept { return value_.empty(); }

  std::string to_string() const;

  friend bool operator==(const SerialIdentity&, const SerialIdentity&) noexcept = default;
  friend auto operator<=>(const SerialIdentity&, const SerialIdentity&) noexcept = default;

private:
  std::string value_;
  std::string scope_;
};

} // namespace fabric_registry

namespace std {

template <class Tag>
struct hash<fabric_registry::OpaqueId<Tag>> {
  std::size_t operator()(const fabric_registry::OpaqueId<Tag>& value) const noexcept {
    // FNV-1a over the 16 identifier bytes. The result feeds std::unordered_map,
    // which is not exposed to untrusted key selection in a way that would make
    // collision attacks meaningful; identities are validated 128-bit values.
    std::size_t accumulator = 1469598103934665603ull;
    for (std::uint8_t byte : value.bytes()) {
      accumulator ^= static_cast<std::size_t>(byte);
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

template <class Tag>
struct hash<fabric_registry::Counter<Tag>> {
  std::size_t operator()(const fabric_registry::Counter<Tag>& value) const noexcept {
    return std::hash<std::uint64_t>{}(value.value());
  }
};

template <class Tag>
struct hash<fabric_registry::DigestValue<Tag>> {
  std::size_t operator()(const fabric_registry::DigestValue<Tag>& value) const noexcept {
    std::size_t accumulator = 1469598103934665603ull;
    for (std::uint8_t byte : value.bytes()) {
      accumulator ^= static_cast<std::size_t>(byte);
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

template <>
struct hash<fabric_registry::CanonicalId> {
  std::size_t operator()(const fabric_registry::CanonicalId& value) const noexcept {
    std::size_t accumulator =
        std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(value.entity_class()));
    for (std::uint8_t byte : value.bytes()) {
      accumulator ^= static_cast<std::size_t>(byte);
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

} // namespace std

#endif // FABRIC_REGISTRY_IDS_HPP
