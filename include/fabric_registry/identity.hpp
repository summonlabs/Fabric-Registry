// Fabric Registry — identity facts, aliases and provenance.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A registry record is built from *facts*. A fact is a (kind, scope, value)
// triple whose value has been canonicalised by this module. Canonicalisation is
// total: for every input there is exactly one of "this is the canonical form"
// or "this input is invalid, and here is the specific reason". Nothing is
// guessed, silently truncated or coerced.

#ifndef FABRIC_REGISTRY_IDENTITY_HPP
#define FABRIC_REGISTRY_IDENTITY_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/export.hpp"
#include "fabric_registry/ids.hpp"
#include "fabric_registry/limits.hpp"

namespace fabric_registry {

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------

/// Strict UTF-8 validation: rejects overlong encodings, surrogate code points,
/// code points above U+10FFFF and truncated sequences. ASCII NUL is rejected
/// because every string in this library is also embedded in a binary codec that
/// uses length prefixes, and a NUL would make textual and binary forms
/// disagree.
FABRIC_REGISTRY_API bool is_valid_identity_text(std::string_view text) noexcept;

/// True for the ASCII whitespace characters trimmed by canonicalisation.
FABRIC_REGISTRY_API bool is_ascii_whitespace(char value) noexcept;

/// Removes leading and trailing ASCII whitespace.
FABRIC_REGISTRY_API std::string_view trim_ascii(std::string_view text) noexcept;

// ---------------------------------------------------------------------------
// Identity facts
// ---------------------------------------------------------------------------

/// The kinds of identity input Fabric Registry understands.
///
/// Enumerator values are part of the persisted format and the wire protocol and
/// must never be renumbered.
enum class IdentityFactKind : std::uint8_t {
  Unspecified = 0,
  /// Vendor-issued serial number. Only meaningful inside a scope.
  SerialNumber = 1,
  /// A device UUID reported by firmware or a device agent.
  DeviceUuid = 2,
  /// Fibre-channel or converged switch GUID.
  SwitchGuid = 3,
  /// Fibre-channel or converged port GUID.
  PortGuid = 4,
  /// Fabric-level GUID advertised by the fabric.
  FabricGuid = 5,
  /// Chassis identity of a modular system.
  ChassisId = 6,
  /// Slot or bay location inside a chassis. Location, not identity.
  SlotId = 7,
  /// Board or line-card identifier. Location within a chassis.
  BoardId = 8,
  /// PCI/PCIe address in BDF form, e.g. "0000:3b:00.0".
  PciAddress = 9,
  /// A universally administered (burned-in) MAC address.
  PermanentMac = 10,
  /// A MAC address in use that may be locally administered.
  MacAddress = 11,
  /// An operating-system device instance identifier. Scope-bound because it is
  /// only meaningful inside the system that assigned it.
  DeviceInstanceId = 12,
  /// PCI-style vendor identifier.
  VendorId = 13,
  /// PCI-style product (device) identifier.
  ProductId = 14,
  /// PCI-style subsystem identifier.
  SubsystemId = 15,
  /// Human-facing model string.
  DeviceModel = 16,
  /// Firmware family string.
  FirmwareFamily = 17,
  /// Host name. Not an identity on its own.
  HostName = 18,
  /// Human-facing friendly name. Not an identity on its own.
  FriendlyName = 19,
  /// Inventory or asset identifier assigned by an operator or CMDB.
  InventoryAssetId = 20,
  /// Cloud provider resource identifier.
  CloudResourceId = 21,
  /// Free-form operator label.
  OperatorLabel = 22,
  /// Physical rack/slot label as painted on the hardware.
  RackSlotLabel = 23,
  /// The hardware name or number printed on a port.
  PortHardwareName = 24,
};

/// Number of enumerators in IdentityFactKind that denote a real kind.
inline constexpr std::uint8_t kIdentityFactKindCount = 24;

/// How much weight a matching fact of this kind carries during reconciliation.
enum class FactStrength : std::uint8_t {
  /// Corroborating only. A weak match never establishes identity.
  Weak = 0,
  /// Supports a match but cannot prove one alone.
  Moderate = 1,
  /// Proves identity when it matches and no other strong fact disagrees.
  Strong = 2,
};

FABRIC_REGISTRY_API std::string_view to_string(FactStrength value) noexcept;
FABRIC_REGISTRY_API std::string_view to_string(IdentityFactKind value) noexcept;
FABRIC_REGISTRY_API std::optional<IdentityFactKind> identity_fact_kind_from_string(std::string_view text) noexcept;
FABRIC_REGISTRY_API FactStrength fact_strength(IdentityFactKind kind) noexcept;

/// True when a fact of this kind is only meaningful inside a non-empty scope
/// (a serial number without its issuing vendor/product scope, an operating
/// system device instance id without its system scope).
FABRIC_REGISTRY_API bool fact_requires_scope(IdentityFactKind kind) noexcept;

/// One validated identity input.
struct IdentityFact {
  IdentityFactKind kind{IdentityFactKind::Unspecified};
  /// Qualification namespace. Empty when the kind is globally meaningful.
  std::string scope;
  /// Canonicalised value.
  std::string value;

  friend bool operator==(const IdentityFact&, const IdentityFact&) = default;
  friend auto operator<=>(const IdentityFact&, const IdentityFact&) = default;
};

/// The specific reason a canonicalisation attempt failed.
enum class IdentityIssue : std::uint8_t {
  None = 0,
  UnknownFactKind,
  InvalidEntityClass,
  EmptyValue,
  ValueTooLong,
  ScopeTooLong,
  ScopeRequired,
  InvalidText,
  InvalidHexLength,
  InvalidMacAddress,
  LocallyAdministeredMac,
  InvalidGuid,
  InvalidPciAddress,
  InvalidNumericId,
  InvalidHostName,
  InvalidSerial,
  TooManyFacts,
  DuplicateFact,
  ContradictoryFact,
  NoStrongFact,
  EmptyDerivationNamespace,
  NamespaceTooLong,
};

FABRIC_REGISTRY_API std::string_view to_string(IdentityIssue value) noexcept;

/// Result of canonicalising a single fact.
struct FactResult {
  std::optional<IdentityFact> fact;
  IdentityIssue issue{IdentityIssue::None};

  explicit operator bool() const noexcept { return fact.has_value(); }
};

/// Canonicalises (kind, scope, value). Returns the canonical fact, or the
/// specific issue that makes the input unusable. Never partially succeeds.
FABRIC_REGISTRY_API FactResult canonicalize_fact(IdentityFactKind kind,
                                                 std::string_view scope,
                                                 std::string_view value,
                                                 std::size_t max_string_bytes);

/// Validates a whole fact set: every fact canonicalisable, no duplicates, no
/// two facts of the same (kind, scope) carrying different values, and at most
/// `max_facts` entries. On success `out` holds the facts sorted by
/// (kind, scope, value).
FABRIC_REGISTRY_API IdentityIssue normalize_fact_set(std::span<const IdentityFact> facts,
                                                     std::size_t max_facts,
                                                     std::size_t max_string_bytes,
                                                     std::vector<IdentityFact>& out);

/// Digest over the strong facts of a set, in canonical order. Two entities
/// whose strong facts agree have the same StableHardwareIdentity regardless of
/// class, namespace or ordering.
FABRIC_REGISTRY_API StableHardwareIdentity compute_stable_hardware_identity(std::span<const IdentityFact> facts);

/// Digest over (derivation namespace, entity class, strong facts). This is the
/// input to canonical id derivation; the namespace is part of the hashed
/// material so two administrative namespaces never produce the same id for
/// different entities.
FABRIC_REGISTRY_API FingerprintDigest compute_identity_fingerprint(EntityClass entity_class,
                                                                   std::string_view derivation_namespace,
                                                                   std::span<const IdentityFact> facts);

/// Result of deriving a canonical id.
struct CanonicalIdResult {
  std::optional<CanonicalId> id;
  IdentityIssue issue{IdentityIssue::None};

  explicit operator bool() const noexcept { return id.has_value(); }
};

/// Deterministically derives a canonical id from an administrative namespace,
/// an entity class and the strong facts of an entity.
///
/// Fails when the class is not a real entity class, when the namespace is empty
/// or too long, or when the fact set contains no strong fact: a derived
/// identity must rest on at least one strong fact.
FABRIC_REGISTRY_API CanonicalIdResult derive_canonical_id(EntityClass entity_class,
                                                          std::string_view derivation_namespace,
                                                          std::span<const IdentityFact> facts,
                                                          std::size_t max_string_bytes);

/// True when `facts` contains at least one strong fact.
FABRIC_REGISTRY_API bool has_strong_fact(std::span<const IdentityFact> facts) noexcept;

/// Returns the facts whose strength is at least Moderate, in canonical order.
FABRIC_REGISTRY_API std::vector<IdentityFact> significant_facts(std::span<const IdentityFact> facts);

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

/// Alias namespaces. Enumerator values are part of the persisted format.
enum class AliasNamespace : std::uint8_t {
  Unspecified = 0,
  HostName = 1,
  SwitchHostName = 2,
  VendorGuid = 3,
  MacAddress = 4,
  InventoryAssetId = 5,
  OperatorLabel = 6,
  RackSlotLabel = 7,
  CloudResourceId = 8,
  ExternalCmdbId = 9,
  PortName = 10,
  DnsName = 11,
  SerialNumber = 12,
  DeviceInstanceId = 13,
};

inline constexpr std::uint8_t kAliasNamespaceCount = 13;

/// The scope inside which an alias of a namespace is promised to be unique.
enum class AliasScope : std::uint8_t {
  /// Unique across the whole registry.
  Global = 0,
  /// Unique inside one fabric.
  Fabric = 1,
  /// Unique inside one site.
  Site = 2,
  /// Unique inside one entity class.
  EntityClass = 3,
  /// Unique among the children of one parent device.
  ParentDevice = 4,
  /// Not unique at all. Stored on the record, never indexed, never resolved.
  Informational = 5,
};

FABRIC_REGISTRY_API std::string_view to_string(AliasNamespace value) noexcept;
FABRIC_REGISTRY_API std::optional<AliasNamespace> alias_namespace_from_string(std::string_view text) noexcept;
FABRIC_REGISTRY_API AliasScope alias_scope(AliasNamespace value) noexcept;
FABRIC_REGISTRY_API std::string_view to_string(AliasScope value) noexcept;

/// A caller-supplied alias value before canonicalisation. The registry
/// canonicalises it and fails the request with a specific AliasIssue when it is
/// unusable.
struct AliasInput {
  AliasNamespace alias_namespace{AliasNamespace::Unspecified};
  std::string value;

  friend bool operator==(const AliasInput&, const AliasInput&) = default;
};

/// A canonicalised, still-unqualified alias value.
struct AliasName {
  AliasNamespace alias_namespace{AliasNamespace::Unspecified};
  std::string value;

  friend bool operator==(const AliasName&, const AliasName&) = default;
  friend auto operator<=>(const AliasName&, const AliasName&) = default;
};

enum class AliasIssue : std::uint8_t {
  None = 0,
  UnknownNamespace,
  EmptyValue,
  ValueTooLong,
  InvalidText,
  InvalidMacAddress,
  InvalidGuid,
  InvalidHostName,
  InvalidSerial,
  MissingFabricScope,
  MissingSiteScope,
  MissingEntityClassScope,
  MissingParentDeviceScope,
};

FABRIC_REGISTRY_API std::string_view to_string(AliasIssue value) noexcept;

struct AliasNameResult {
  std::optional<AliasName> name;
  AliasIssue issue{AliasIssue::None};

  explicit operator bool() const noexcept { return name.has_value(); }
};

/// Canonicalises an alias value for its namespace.
FABRIC_REGISTRY_API AliasNameResult canonicalize_alias(AliasNamespace alias_namespace,
                                                       std::string_view value,
                                                       std::size_t max_string_bytes);

/// State needed to qualify an alias into a key.
struct AliasScopeInput {
  std::optional<FabricId> fabric;
  std::optional<SiteId> site;
  EntityClass entity_class{EntityClass::Unknown};
  std::optional<CanonicalId> parent_device;
};

/// A fully qualified alias key.
///
/// Textual form is "<namespace>:<scope>=<value>" where <scope> is empty for a
/// global alias, "fabric:<hex>", "site:<hex>", "class:<name>",
/// "parent:<class>:<hex>" or "info". The value is everything after the first
/// '=' following the namespace separator, so values may contain '=' and ':'.
struct FABRIC_REGISTRY_API AliasKey {
  AliasNamespace alias_namespace{AliasNamespace::Unspecified};
  std::string scope;
  std::string value;

  std::string to_string() const;
  static std::optional<AliasKey> parse(std::string_view text);

  friend bool operator==(const AliasKey&, const AliasKey&) = default;
  friend auto operator<=>(const AliasKey&, const AliasKey&) = default;
};

struct AliasKeyResult {
  std::optional<AliasKey> key;
  AliasIssue issue{AliasIssue::None};

  explicit operator bool() const noexcept { return key.has_value(); }
};

/// Builds the key for an already canonicalised alias name. Fails when the alias
/// scope requires qualification that the scope input does not supply.
FABRIC_REGISTRY_API AliasKeyResult make_alias_key(const AliasName& name, const AliasScopeInput& scope);

/// True when aliases in this namespace take part in unique lookup.
FABRIC_REGISTRY_API bool alias_is_unique(AliasNamespace alias_namespace) noexcept;

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Validation provenance of an observation or capability. These labels are
/// never inferred and never upgraded: a record registered from synthetic input
/// is permanently marked synthetic.
enum class ProvenanceClass : std::uint8_t {
  Unknown = 0,
  /// Exercised against actual available host, network or hardware state.
  Real = 1,
  /// Exercised with generated records because the physical infrastructure is
  /// unavailable in this environment.
  Synthetic = 2,
  /// The capability cannot be truthfully validated or implemented here.
  Unsupported = 3,
};

FABRIC_REGISTRY_API std::string_view to_string(ProvenanceClass value) noexcept;
FABRIC_REGISTRY_API std::optional<ProvenanceClass> provenance_class_from_string(std::string_view text) noexcept;

/// Where a claim came from. Provenance is preserved verbatim; discovery sources
/// are never flattened into a single undifferentiated "observed" state.
enum class ObservationSource : std::uint8_t {
  Unspecified = 0,
  /// An operator or configuration file declared this identity.
  OperatorDeclaration = 1,
  /// Enumerated from the local operating system.
  LocalHostEnumeration = 2,
  /// Reported by a device agent running next to the device.
  DeviceAgent = 3,
  /// Pushed by a controller or orchestrator.
  ControllerPush = 4,
  /// Imported from an inventory file.
  ImportedInventory = 5,
  /// Read from an external CMDB.
  ExternalCmdb = 6,
  /// Generated deterministic fixture data.
  SyntheticFixture = 7,
  /// Received from a peer registry.
  PeerRegistry = 8,
};

inline constexpr std::uint8_t kObservationSourceCount = 8;

FABRIC_REGISTRY_API std::string_view to_string(ObservationSource value) noexcept;
FABRIC_REGISTRY_API std::optional<ObservationSource> observation_source_from_string(std::string_view text) noexcept;

/// The provenance attached to an observation.
struct Provenance {
  ObservationSource source{ObservationSource::Unspecified};
  ProvenanceClass validity_class{ProvenanceClass::Unknown};
  /// Free-form description of the mechanism, e.g. "GetAdaptersAddresses".
  std::string mechanism;
  /// Stable identifier of the source, e.g. the enumerating host identity.
  std::string source_identity;

  friend bool operator==(const Provenance&, const Provenance&) = default;
};

FABRIC_REGISTRY_API ValidationResult validate_provenance(const Provenance& provenance, std::size_t max_string_bytes);

// ---------------------------------------------------------------------------
// Evidence durability
// ---------------------------------------------------------------------------

/// How long an item of evidence remains authoritative.
enum class EvidenceClass : std::uint8_t {
  Unspecified = 0,
  /// Bound to a live publisher process. Dies with the process and must be
  /// re-established, not recovered, after a restart.
  ProcessBound = 1,
  /// An administrative act recorded durably. Survives coordinator restart.
  DurableAuthority = 2,
};

FABRIC_REGISTRY_API std::string_view to_string(EvidenceClass value) noexcept;

/// The outcome class of identity matching.
enum class MatchClass : std::uint8_t {
  /// Nothing in the registry refers to this observation.
  NoMatch = 0,
  /// The request named a canonical id that exists.
  ExactCanonical = 1,
  /// An alias in a unique namespace resolved to exactly one record.
  ProvenAlias = 2,
  /// Strong hardware facts matched exactly, with no contradicting fact.
  StableHardware = 3,
  /// Some facts matched but none of them is strong enough to prove identity.
  ProbableInsufficient = 4,
  /// At least one fact of the same (kind, scope) disagrees with an existing
  /// record, or a unique alias points at a different record.
  Conflicting = 5,
  /// More than one record matched at the same strength. Never resolved
  /// automatically.
  Ambiguous = 6,
};

FABRIC_REGISTRY_API std::string_view to_string(MatchClass value) noexcept;

} // namespace fabric_registry

namespace std {

template <>
struct hash<fabric_registry::IdentityFact> {
  std::size_t operator()(const fabric_registry::IdentityFact& fact) const noexcept {
    std::size_t accumulator = static_cast<std::size_t>(fact.kind) + 0x9E3779B97F4A7C15ull;
    for (char c : fact.scope) {
      accumulator ^= static_cast<std::size_t>(static_cast<unsigned char>(c));
      accumulator *= 1099511628211ull;
    }
    accumulator ^= 0xFFull;
    accumulator *= 1099511628211ull;
    for (char c : fact.value) {
      accumulator ^= static_cast<std::size_t>(static_cast<unsigned char>(c));
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

template <>
struct hash<fabric_registry::AliasKey> {
  std::size_t operator()(const fabric_registry::AliasKey& key) const noexcept {
    std::size_t accumulator = static_cast<std::size_t>(key.alias_namespace) + 0x9E3779B97F4A7C15ull;
    for (char c : key.scope) {
      accumulator ^= static_cast<std::size_t>(static_cast<unsigned char>(c));
      accumulator *= 1099511628211ull;
    }
    accumulator ^= 0xFFull;
    accumulator *= 1099511628211ull;
    for (char c : key.value) {
      accumulator ^= static_cast<std::size_t>(static_cast<unsigned char>(c));
      accumulator *= 1099511628211ull;
    }
    return accumulator;
  }
};

} // namespace std

#endif // FABRIC_REGISTRY_IDENTITY_HPP
