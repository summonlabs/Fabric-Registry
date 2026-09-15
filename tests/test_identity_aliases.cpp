// Fabric Registry — alias namespaces, qualified alias keys and provenance.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These checks pin the frozen alias and provenance contract of
// include/fabric_registry/identity.hpp to observable behaviour. Every one of
// the thirteen alias namespaces canonicalises exactly one way and rejects an
// unusable value with the specific issue that names the reason; alias_scope,
// alias_is_unique and make_alias_key agree with each other; a qualified key
// round trips through its textual form even when its value contains '=' and
// ':'; and provenance is validated, named and recorded verbatim, never
// upgraded.

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "registry_test_support.hpp"
#include "test_harness.hpp"

namespace {

using namespace fabric_registry;

/// Configured string bound used by the alias calls in this file.
constexpr std::size_t kAliasBound = 1024;
/// Enumerators of the provenance enums. Pinned so that a loop always visits
/// every one of them and a new enumerator cannot slip in unobserved.
constexpr std::uint8_t kProvenanceClassCount = 4;
constexpr std::uint8_t kObservationSourceEnumeratorCount = 9;
constexpr std::uint8_t kEvidenceClassCount = 3;
constexpr std::uint8_t kMatchClassCount = 7;
/// Enumeration bound used by the "list everything" assertions.
constexpr std::size_t kEnumerateAll = 1'000'000;

IdBytes bytes_with(std::uint8_t tag, std::uint8_t salt) {
  IdBytes bytes{};
  bytes[0] = tag;
  bytes[15] = salt;
  return bytes;
}

FabricId fabric_with(std::uint8_t salt) { return FabricId::from_bytes(bytes_with(0xF1u, salt)); }

SiteId site_with(std::uint8_t salt) { return SiteId::from_bytes(bytes_with(0x51u, salt)); }

/// A non-null parent device reference: a port canonical id.
CanonicalId parent_port_with(std::uint8_t salt) { return CanonicalId(EntityClass::Port, bytes_with(0xA1u, salt)); }

/// One alias namespace, the scope the contract promises for it, whether its
/// values take part in unique lookup, a valid input and the canonical value
/// that input must produce.
struct AliasSample {
  AliasNamespace alias_namespace;
  AliasScope scope;
  bool unique;
  std::string_view input;
  std::string_view canonical;
};

constexpr AliasSample kAliasSamples[] = {
    {AliasNamespace::HostName, AliasScope::Fabric, true, "  SW1.Core.Example.COM.  ", "sw1.core.example.com"},
    {AliasNamespace::SwitchHostName, AliasScope::Fabric, true, "SW1.Core.", "sw1.core"},
    {AliasNamespace::VendorGuid, AliasScope::Global, true, "{6F1C0B3A-1234-4ABC-9DEF-0A1B2C3D4E5F}",
     "6f1c0b3a-1234-4abc-9def-0a1b2c3d4e5f"},
    {AliasNamespace::MacAddress, AliasScope::Global, true, "02-00-00-00-00-01", "020000000001"},
    {AliasNamespace::InventoryAssetId, AliasScope::Site, true, "  Asset-0042  ", "Asset-0042"},
    {AliasNamespace::OperatorLabel, AliasScope::Informational, false, "  Rack 4 / U12  ", "Rack 4 / U12"},
    {AliasNamespace::RackSlotLabel, AliasScope::Site, true, " rack=4:u12 ", "rack=4:u12"},
    {AliasNamespace::CloudResourceId, AliasScope::Global, true, "  i-0AbC123  ", "i-0AbC123"},
    {AliasNamespace::ExternalCmdbId, AliasScope::Global, true, "  CMDB-77  ", "CMDB-77"},
    {AliasNamespace::PortName, AliasScope::ParentDevice, true, "  Ethernet1/1  ", "Ethernet1/1"},
    {AliasNamespace::DnsName, AliasScope::Global, true, "API.Example.COM.", "api.example.com"},
    {AliasNamespace::SerialNumber, AliasScope::Global, true, "  SN-AbC-1  ", "SN-AbC-1"},
    {AliasNamespace::DeviceInstanceId, AliasScope::Site, true, "  PCI\\VEN_15B3&DEV_1017  ", "pci\\ven_15b3&dev_1017"},
};

static_assert(std::size(kAliasSamples) == kAliasNamespaceCount,
              "every built-in alias namespace needs exactly one sample");

std::string namespace_label(AliasNamespace value) {
  std::string out("alias namespace ");
  out += std::string(to_string(value));
  return out;
}

/// The sample value of a namespace, or an empty string when it has none.
std::string canonical_sample(AliasNamespace value) {
  for (const AliasSample& entry : kAliasSamples) {
    if (entry.alias_namespace == value) {
      return std::string(entry.canonical);
    }
  }
  return std::string();
}

/// A scope input that satisfies every namespace at once.
AliasScopeInput complete_scope_input() {
  AliasScopeInput input;
  input.fabric = fabric_with(0x01u);
  input.site = site_with(0x02u);
  input.entity_class = EntityClass::Port;
  input.parent_device = parent_port_with(0x03u);
  return input;
}

/// The exact scope text a key of this scope must carry for this input.
std::string expected_scope_text(AliasScope scope, const AliasScopeInput& input) {
  switch (scope) {
    case AliasScope::Global:
      return std::string();
    case AliasScope::Fabric:
      return "fabric:" + input.fabric->to_string();
    case AliasScope::Site:
      return "site:" + input.site->to_string();
    case AliasScope::EntityClass:
      return "class:" + std::string(to_string(input.entity_class));
    case AliasScope::ParentDevice:
      return "parent:" + input.parent_device->to_string();
    case AliasScope::Informational:
      return "info";
  }
  return std::string();
}

/// True when the text is exactly `length` lowercase hexadecimal characters.
bool is_lowercase_hex(std::string_view text, std::size_t length) {
  if (text.size() != length) {
    return false;
  }
  for (const char value : text) {
    const bool digit = value >= '0' && value <= '9';
    const bool letter = value >= 'a' && value <= 'f';
    if (!digit && !letter) {
      return false;
    }
  }
  return true;
}

/// Canonicalises a value, discarding the issue. Callers that need the issue
/// call canonicalize_alias directly.
std::optional<AliasName> canonical_name(AliasNamespace alias_namespace, std::string_view value) {
  return canonicalize_alias(alias_namespace, value, kAliasBound).name;
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityaliases, canonicalizes_every_alias_namespace) {
  bool seen[kAliasNamespaceCount + 1] = {};
  for (const AliasSample& entry : kAliasSamples) {
    const std::string label = namespace_label(entry.alias_namespace);
    const AliasNameResult result = canonicalize_alias(entry.alias_namespace, entry.input, kAliasBound);
    FR_CHECK_MSG(result.name.has_value(),
                 label + " rejected its own sample with issue " + std::string(to_string(result.issue)));
    FR_CHECK_MSG(result.name->alias_namespace == entry.alias_namespace, label + " did not preserve its namespace");
    FR_CHECK_MSG(result.name->value == entry.canonical,
                 label + " produced '" + result.name->value + "' instead of '" + std::string(entry.canonical) + "'");
    const std::size_t raw = static_cast<std::size_t>(entry.alias_namespace);
    FR_CHECK_MSG(!seen[raw], label + " has more than one sample");
    seen[raw] = true;
  }
  for (std::uint8_t raw = 1; raw <= kAliasNamespaceCount; ++raw) {
    FR_CHECK_MSG(seen[raw], "the sample table does not cover alias namespace value " + std::to_string(raw));
  }
}

FR_TEST_CASE(identityaliases, mac_address_accepts_local_and_universal_forms) {
  const AliasNameResult local = canonicalize_alias(AliasNamespace::MacAddress, "02:00:00:00:00:01", kAliasBound);
  FR_CHECK_MSG(local.name.has_value(), "a locally administered address must be accepted");
  FR_CHECK_EQ(local.name->value, "020000000001");

  const AliasNameResult universal = canonicalize_alias(AliasNamespace::MacAddress, "AA:BB:CC:DD:EE:FF", kAliasBound);
  FR_CHECK_MSG(universal.name.has_value(), "a universally administered address must be accepted");
  FR_CHECK_EQ(universal.name->value, "aabbccddeeff");

  const AliasNameResult dotted = canonicalize_alias(AliasNamespace::MacAddress, "aabb.ccdd.eeff", kAliasBound);
  FR_CHECK_MSG(dotted.name.has_value(), "the dotted quad form must be accepted");
  FR_CHECK_EQ(dotted.name->value, "aabbccddeeff");
}

FR_TEST_CASE(identityaliases, rejects_unusable_alias_values) {
  {
    const AliasNameResult result = canonicalize_alias(AliasNamespace::Unspecified, "switch-a", kAliasBound);
    FR_CHECK(!result.name.has_value());
    FR_CHECK_EQ(result.issue, AliasIssue::UnknownNamespace);
  }

  for (const AliasSample& entry : kAliasSamples) {
    const std::string label = namespace_label(entry.alias_namespace);

    for (const std::string_view blank : {std::string_view(), std::string_view(" \t\r\n")}) {
      const AliasNameResult result = canonicalize_alias(entry.alias_namespace, blank, kAliasBound);
      FR_CHECK_MSG(!result.name.has_value(), label + " accepted a blank value");
      FR_CHECK_MSG(result.issue == AliasIssue::EmptyValue,
                   label + " must report EmptyValue for a blank value, got " + std::string(to_string(result.issue)));
    }

    const std::size_t bound = entry.canonical.size() - 1;
    const AliasNameResult too_long = canonicalize_alias(entry.alias_namespace, entry.input, bound);
    FR_CHECK_MSG(!too_long.name.has_value(), label + " accepted a value longer than max_bytes");
    FR_CHECK_MSG(too_long.issue == AliasIssue::ValueTooLong,
                 label + " must report ValueTooLong, got " + std::string(to_string(too_long.issue)));
  }

  for (const AliasNamespace alias_namespace :
       {AliasNamespace::HostName, AliasNamespace::SwitchHostName, AliasNamespace::DnsName}) {
    for (const std::string_view bad : {std::string_view("a..b"), std::string_view("-a"), std::string_view("a-")}) {
      const AliasNameResult result = canonicalize_alias(alias_namespace, bad, kAliasBound);
      FR_CHECK_MSG(!result.name.has_value(), namespace_label(alias_namespace) + " accepted '" + std::string(bad) + "'");
      FR_CHECK_MSG(result.issue == AliasIssue::InvalidHostName,
                   namespace_label(alias_namespace) + " must report InvalidHostName for '" + std::string(bad) +
                       "', got " + std::string(to_string(result.issue)));
    }
  }

  for (const std::string_view bad :
       {std::string_view("6f1c0b3a-1234-4abc-9def-0a1b2c3d4e5"), std::string_view("not-a-guid"),
        std::string_view("6f1c0b3a-1234-4abc-9def-0a1b2c3d4e5f0")}) {
    const AliasNameResult result = canonicalize_alias(AliasNamespace::VendorGuid, bad, kAliasBound);
    FR_CHECK_MSG(!result.name.has_value(), std::string("vendor-guid accepted '") + std::string(bad) + "'");
    FR_CHECK_MSG(result.issue == AliasIssue::InvalidGuid,
                 std::string("vendor-guid must report InvalidGuid for '") + std::string(bad) + "', got " +
                     std::string(to_string(result.issue)));
  }

  for (const std::string_view bad : {std::string_view("zz:00:00:00:00:00"), std::string_view("aa:bb:cc:dd:ee"),
                                     std::string_view("aa:bb:cc:dd:ee:ff:00")}) {
    const AliasNameResult result = canonicalize_alias(AliasNamespace::MacAddress, bad, kAliasBound);
    FR_CHECK_MSG(!result.name.has_value(), std::string("mac-address accepted '") + std::string(bad) + "'");
    FR_CHECK_MSG(result.issue == AliasIssue::InvalidMacAddress,
                 std::string("mac-address must report InvalidMacAddress for '") + std::string(bad) + "', got " +
                     std::string(to_string(result.issue)));
  }
}

// ---------------------------------------------------------------------------
// Scopes and qualification
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityaliases, scopes_and_uniqueness_match_the_contract) {
  std::size_t unique_count = 0;
  for (const AliasSample& entry : kAliasSamples) {
    const std::string label = namespace_label(entry.alias_namespace);
    FR_CHECK_MSG(alias_scope(entry.alias_namespace) == entry.scope,
                 label + " has scope " + std::string(to_string(alias_scope(entry.alias_namespace))) + " instead of " +
                     std::string(to_string(entry.scope)));
    FR_CHECK_MSG(alias_is_unique(entry.alias_namespace) == entry.unique, label + " disagrees about uniqueness");
    FR_CHECK_MSG(alias_is_unique(entry.alias_namespace) == (entry.scope != AliasScope::Informational),
                 label + " uniqueness must follow from its scope");
    if (entry.unique) {
      ++unique_count;
    }
  }
  FR_CHECK_EQ(unique_count, 12);

  FR_CHECK_EQ(to_string(AliasScope::Global), "global");
  FR_CHECK_EQ(to_string(AliasScope::Fabric), "fabric");
  FR_CHECK_EQ(to_string(AliasScope::Site), "site");
  FR_CHECK_EQ(to_string(AliasScope::EntityClass), "entity-class");
  FR_CHECK_EQ(to_string(AliasScope::ParentDevice), "parent-device");
  FR_CHECK_EQ(to_string(AliasScope::Informational), "informational");
}

FR_TEST_CASE(identityaliases, qualified_keys_require_their_scope) {
  const AliasScopeInput complete = complete_scope_input();

  for (const AliasSample& entry : kAliasSamples) {
    const std::string label = namespace_label(entry.alias_namespace);
    const std::optional<AliasName> name = canonical_name(entry.alias_namespace, entry.input);
    FR_CHECK_MSG(name.has_value(), label + " sample did not canonicalise");

    const AliasKeyResult key = make_alias_key(*name, complete);
    FR_CHECK_MSG(key.key.has_value(),
                 label + " did not build a key from a complete scope: " + std::string(to_string(key.issue)));
    FR_CHECK_MSG(key.key->scope == expected_scope_text(entry.scope, complete),
                 label + " produced scope '" + key.key->scope + "' instead of '" +
                     expected_scope_text(entry.scope, complete) + "'");
    FR_CHECK_MSG(key.key->value == entry.canonical, label + " lost its value on the way into the key");
    FR_CHECK_MSG(key.key->alias_namespace == entry.alias_namespace,
                 label + " lost its namespace on the way into the key");

    if (entry.scope == AliasScope::Fabric) {
      FR_CHECK_MSG(key.key->scope.rfind("fabric:", 0) == 0 &&
                       is_lowercase_hex(key.key->scope.substr(7), kOpaqueIdTextLength),
                   label + " must carry a 'fabric:<32 hex>' scope, got '" + key.key->scope + "'");
    } else if (entry.scope == AliasScope::Site) {
      FR_CHECK_MSG(key.key->scope.rfind("site:", 0) == 0 &&
                       is_lowercase_hex(key.key->scope.substr(5), kOpaqueIdTextLength),
                   label + " must carry a 'site:<32 hex>' scope, got '" + key.key->scope + "'");
    } else if (entry.scope == AliasScope::ParentDevice) {
      const std::size_t separator = key.key->scope.rfind(':');
      FR_CHECK_MSG(key.key->scope.rfind("parent:", 0) == 0 && separator != std::string::npos &&
                       is_lowercase_hex(key.key->scope.substr(separator + 1), kOpaqueIdTextLength),
                   label + " must carry a 'parent:<class>:<32 hex>' scope, got '" + key.key->scope + "'");
    }
  }

  for (const AliasNamespace alias_namespace : {AliasNamespace::HostName, AliasNamespace::SwitchHostName}) {
    const std::optional<AliasName> name = canonical_name(alias_namespace, canonical_sample(alias_namespace));
    FR_CHECK(name.has_value());
    AliasScopeInput without_fabric = complete;
    without_fabric.fabric.reset();
    FR_CHECK_EQ(make_alias_key(*name, without_fabric).issue, AliasIssue::MissingFabricScope);
    FR_CHECK(!make_alias_key(*name, without_fabric).key.has_value());
    AliasScopeInput null_fabric = complete;
    null_fabric.fabric = FabricId{};
    FR_CHECK_EQ(make_alias_key(*name, null_fabric).issue, AliasIssue::MissingFabricScope);
  }

  for (const AliasNamespace alias_namespace :
       {AliasNamespace::InventoryAssetId, AliasNamespace::RackSlotLabel, AliasNamespace::DeviceInstanceId}) {
    const std::optional<AliasName> name = canonical_name(alias_namespace, canonical_sample(alias_namespace));
    FR_CHECK(name.has_value());
    AliasScopeInput without_site = complete;
    without_site.site.reset();
    FR_CHECK_EQ(make_alias_key(*name, without_site).issue, AliasIssue::MissingSiteScope);
    FR_CHECK(!make_alias_key(*name, without_site).key.has_value());
    AliasScopeInput null_site = complete;
    null_site.site = SiteId{};
    FR_CHECK_EQ(make_alias_key(*name, null_site).issue, AliasIssue::MissingSiteScope);
  }

  {
    const std::optional<AliasName> name =
        canonical_name(AliasNamespace::PortName, canonical_sample(AliasNamespace::PortName));
    FR_CHECK(name.has_value());
    AliasScopeInput without_parent = complete;
    without_parent.parent_device.reset();
    FR_CHECK_EQ(make_alias_key(*name, without_parent).issue, AliasIssue::MissingParentDeviceScope);
    FR_CHECK(!make_alias_key(*name, without_parent).key.has_value());
    AliasScopeInput null_parent = complete;
    null_parent.parent_device = CanonicalId{};
    FR_CHECK_EQ(make_alias_key(*name, null_parent).issue, AliasIssue::MissingParentDeviceScope);

    const AliasKeyResult key = make_alias_key(*name, complete);
    FR_CHECK(key.key.has_value());
    FR_CHECK_EQ(key.key->scope, "parent:" + complete.parent_device->to_string());
  }

  {
    AliasName unspecified;
    unspecified.alias_namespace = AliasNamespace::Unspecified;
    unspecified.value = "switch-a";
    const AliasKeyResult result = make_alias_key(unspecified, complete);
    FR_CHECK(!result.key.has_value());
    FR_CHECK_EQ(result.issue, AliasIssue::UnknownNamespace);
  }

  {
    AliasName empty;
    empty.alias_namespace = AliasNamespace::HostName;
    const AliasKeyResult result = make_alias_key(empty, complete);
    FR_CHECK(!result.key.has_value());
    FR_CHECK_EQ(result.issue, AliasIssue::EmptyValue);
  }
}

FR_TEST_CASE(identityaliases, entity_class_scope_is_unreachable_for_builtin_namespaces) {
  const AliasScopeInput complete = complete_scope_input();
  AliasScopeInput fabric_only;
  fabric_only.fabric = complete.fabric;
  const AliasScopeInput inputs[] = {AliasScopeInput{}, fabric_only, complete};

  for (std::uint8_t raw = 1; raw <= kAliasNamespaceCount; ++raw) {
    const AliasNamespace alias_namespace = static_cast<AliasNamespace>(raw);
    const std::string label = namespace_label(alias_namespace);
    const std::optional<AliasName> name = canonical_name(alias_namespace, canonical_sample(alias_namespace));
    FR_CHECK_MSG(name.has_value(), label + " sample did not canonicalise");

    for (const AliasScopeInput& input : inputs) {
      const AliasKeyResult result = make_alias_key(*name, input);
      FR_CHECK_MSG(result.issue != AliasIssue::MissingEntityClassScope,
                   label + " can demand an entity-class scope, which no built-in namespace owns");
      if (!result.key.has_value()) {
        const bool named_other_reason = result.issue == AliasIssue::MissingFabricScope ||
                                        result.issue == AliasIssue::MissingSiteScope ||
                                        result.issue == AliasIssue::MissingParentDeviceScope;
        FR_CHECK_MSG(named_other_reason,
                     label + " failed with the unexpected issue " + std::string(to_string(result.issue)));
      }
    }

    const AliasKeyResult with_complete = make_alias_key(*name, complete);
    FR_CHECK_MSG(with_complete.key.has_value(),
                 label + " must succeed with a complete scope input, got " +
                     std::string(to_string(with_complete.issue)));
  }
}

FR_TEST_CASE(identityaliases, keys_round_trip_through_text) {
  const AliasScopeInput complete = complete_scope_input();
  const std::string fabric_text = complete.fabric->to_string();
  const std::string site_text = complete.site->to_string();
  const std::string parent_text = complete.parent_device->to_string();

  struct RoundTrip {
    AliasNamespace alias_namespace;
    std::string value;
    std::string text;
  };
  const RoundTrip cases[] = {
      {AliasNamespace::MacAddress, "aabbccddeeff", "mac-address:=aabbccddeeff"},
      {AliasNamespace::HostName, "sw1.core", "host-name:fabric:" + fabric_text + "=sw1.core"},
      {AliasNamespace::InventoryAssetId, "Asset-0042", "inventory-asset-id:site:" + site_text + "=Asset-0042"},
      {AliasNamespace::PortName, "Ethernet1/1", "port-name:parent:" + parent_text + "=Ethernet1/1"},
      {AliasNamespace::OperatorLabel, "Rack 4 / U12", "operator-label:info=Rack 4 / U12"},
      {AliasNamespace::RackSlotLabel, "rack=4:u12", "rack-slot-label:site:" + site_text + "=rack=4:u12"},
  };

  for (const RoundTrip& entry : cases) {
    const std::optional<AliasName> name = canonical_name(entry.alias_namespace, entry.value);
    FR_CHECK_MSG(name.has_value(), namespace_label(entry.alias_namespace) + " sample did not canonicalise");
    const AliasKeyResult built = make_alias_key(*name, complete);
    FR_CHECK_MSG(built.key.has_value(), namespace_label(entry.alias_namespace) + " did not build a key");
    FR_CHECK_EQ(built.key->to_string(), entry.text);

    const std::optional<AliasKey> parsed = AliasKey::parse(entry.text);
    FR_CHECK_MSG(parsed.has_value(), "parse rejected the canonical text '" + entry.text + "'");
    FR_CHECK_MSG(*parsed == *built.key, "the round trip changed '" + entry.text + "'");
    FR_CHECK_EQ(parsed->value, entry.value);
  }

  const std::optional<AliasKey> rack = AliasKey::parse("rack-slot-label:site:" + site_text + "=rack=4:u12");
  FR_CHECK(rack.has_value());
  FR_CHECK_EQ(rack->scope, "site:" + site_text);
  FR_CHECK_EQ(rack->value, "rack=4:u12");
  FR_CHECK_EQ(rack->alias_namespace, AliasNamespace::RackSlotLabel);
}

FR_TEST_CASE(identityaliases, key_parse_rejects_malformed_text) {
  const std::string hex32(32, 'a');
  const std::string malformed[] = {
      "notanalias",
      "hostname:abc",
      "host-name:=",
      "host-name:=x",
      "vendor-guid:fabric:" + hex32 + "=x",
      "operator-label:=x",
      "mac-address:info=aa:bb:cc:dd:ee:ff",
  };
  for (const std::string& text : malformed) {
    FR_CHECK_MSG(!AliasKey::parse(text).has_value(), "parse accepted the malformed text '" + text + "'");
  }

  const std::string well_formed = "host-name:fabric:" + hex32 + "=sw1.core";
  const std::optional<AliasKey> parsed = AliasKey::parse(well_formed);
  FR_CHECK_MSG(parsed.has_value(), "parse rejected the well formed text '" + well_formed + "'");
  FR_CHECK_EQ(parsed->alias_namespace, AliasNamespace::HostName);
  FR_CHECK_EQ(parsed->scope, "fabric:" + hex32);
  FR_CHECK_EQ(parsed->value, "sw1.core");
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityaliases, provenance_validation_names_the_broken_field) {
  Provenance provenance;
  ValidationResult result = validate_provenance(provenance, kAliasBound);
  FR_CHECK_MSG(!result.ok, "an unknown validity class must be rejected");
  FR_CHECK_MSG(result.message.find("validity_class") != std::string::npos,
               "the message must name validity_class, got '" + result.message + "'");

  provenance.validity_class = ProvenanceClass::Real;
  result = validate_provenance(provenance, kAliasBound);
  FR_CHECK_MSG(!result.ok, "an unspecified observation source must be rejected");
  FR_CHECK_MSG(result.message.find("source") != std::string::npos,
               "the message must name source, got '" + result.message + "'");

  Provenance unsupported;
  unsupported.source = ObservationSource::DeviceAgent;
  unsupported.validity_class = ProvenanceClass::Unsupported;
  result = validate_provenance(unsupported, kAliasBound);
  FR_CHECK_MSG(!result.ok, "an unsupported validity class must be rejected");
  FR_CHECK_MSG(result.message.find("cannot back a registered record") != std::string::npos,
               "the message must say it cannot back a registered record, got '" + result.message + "'");

  Provenance oversized;
  oversized.source = ObservationSource::DeviceAgent;
  oversized.validity_class = ProvenanceClass::Real;
  oversized.mechanism.assign(65, 'm');
  result = validate_provenance(oversized, 64);
  FR_CHECK_MSG(!result.ok, "a mechanism longer than max_bytes must be rejected");
  FR_CHECK_MSG(result.message.find("mechanism") != std::string::npos,
               "the message must name mechanism, got '" + result.message + "'");

  Provenance real;
  real.source = ObservationSource::OperatorDeclaration;
  real.validity_class = ProvenanceClass::Real;
  FR_CHECK(real.mechanism.empty());
  FR_CHECK(real.source_identity.empty());
  result = validate_provenance(real, kAliasBound);
  FR_CHECK_MSG(result.ok, "real provenance with a concrete source must be accepted, got '" + result.message + "'");

  Provenance synthetic;
  synthetic.source = ObservationSource::SyntheticFixture;
  synthetic.validity_class = ProvenanceClass::Synthetic;
  FR_CHECK(synthetic.mechanism.empty());
  FR_CHECK(synthetic.source_identity.empty());
  result = validate_provenance(synthetic, kAliasBound);
  FR_CHECK_MSG(result.ok, "synthetic provenance with a concrete source must be accepted, got '" + result.message + "'");
}

FR_TEST_CASE(identityaliases, provenance_class_and_observation_source_round_trip) {
  static_assert(kProvenanceClassCount == 4, "ProvenanceClass has four enumerators");
  for (std::uint8_t raw = 0; raw < kProvenanceClassCount; ++raw) {
    const ProvenanceClass value = static_cast<ProvenanceClass>(raw);
    const std::string name(to_string(value));
    FR_CHECK_MSG(!name.empty(), "ProvenanceClass " + std::to_string(raw) + " has no stable name");
    const std::optional<ProvenanceClass> parsed = provenance_class_from_string(name);
    FR_CHECK_MSG(parsed.has_value(), "the name '" + name + "' does not parse back");
    FR_CHECK_MSG(*parsed == value, "the name '" + name + "' parsed to a different class");
  }
  FR_CHECK(!provenance_class_from_string("REAL").has_value());
  FR_CHECK(!provenance_class_from_string("nonsense").has_value());

  static_assert(kObservationSourceCount + 1 == kObservationSourceEnumeratorCount,
                "ObservationSource has nine enumerators including Unspecified");
  for (std::uint8_t raw = 0; raw < kObservationSourceEnumeratorCount; ++raw) {
    const ObservationSource value = static_cast<ObservationSource>(raw);
    const std::string name(to_string(value));
    FR_CHECK_MSG(!name.empty(), "ObservationSource " + std::to_string(raw) + " has no stable name");
    const std::optional<ObservationSource> parsed = observation_source_from_string(name);
    FR_CHECK_MSG(parsed.has_value(), "the name '" + name + "' does not parse back");
    FR_CHECK_MSG(*parsed == value, "the name '" + name + "' parsed to a different source");
  }
  FR_CHECK(!observation_source_from_string("nonsense").has_value());
  FR_CHECK(!observation_source_from_string("Unspecified").has_value());
}

FR_TEST_CASE(identityaliases, evidence_and_match_class_names_are_defined) {
  static_assert(static_cast<std::uint8_t>(EvidenceClass::DurableAuthority) + 1 == kEvidenceClassCount,
                "every EvidenceClass enumerator must be visited");
  for (std::uint8_t raw = 0; raw < kEvidenceClassCount; ++raw) {
    const std::string name(to_string(static_cast<EvidenceClass>(raw)));
    FR_CHECK_MSG(!name.empty() && name != "unknown", "EvidenceClass " + std::to_string(raw) + " has no stable name");
  }

  static_assert(static_cast<std::uint8_t>(MatchClass::Ambiguous) + 1 == kMatchClassCount,
                "MatchClass has seven enumerators");
  for (std::uint8_t raw = 0; raw < kMatchClassCount; ++raw) {
    const std::string name(to_string(static_cast<MatchClass>(raw)));
    FR_CHECK_MSG(!name.empty() && name != "unknown", "MatchClass " + std::to_string(raw) + " has no stable name");
  }
  FR_CHECK_EQ(to_string(MatchClass::NoMatch), "no-match");
  FR_CHECK_EQ(to_string(MatchClass::Ambiguous), "ambiguous");
}

// ---------------------------------------------------------------------------
// Registry integration
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityaliases, unsupported_provenance_is_refused_and_synthetic_commits) {
  const std::unique_ptr<Registry> registry = frtest::make_registry(0x1D3A11ull);
  const RegistryStats before = registry->stats();
  const StateDigest digest_before = registry->state_digest();

  RegisterEntityRequest request =
      frtest::device_request(*registry, "identityaliases-provenance", "SN-ALIAS-PROV-0001");
  request.provenance.source = ObservationSource::DeviceAgent;
  request.provenance.validity_class = ProvenanceClass::Unsupported;
  request.provenance.mechanism = "unit-test";
  request.provenance.source_identity = "identityaliases";

  const CanonicalIdResult derived =
      derive_canonical_id(request.entity_class, request.derivation_namespace, request.facts, kAliasBound);
  FR_CHECK_MSG(derived.id.has_value(), "the integration case needs a derivable canonical identity");

  const Outcome refused = registry->register_entity(request);
  FR_CHECK_MSG(refused.code == OutcomeCode::InvalidEvidence,
               "an unsupported provenance must be refused with InvalidEvidence, got " +
                   std::string(to_string(refused.code)));

  const RegistryStats after_refusal = registry->stats();
  FR_CHECK_EQ(after_refusal.entities, before.entities);
  FR_CHECK_EQ(after_refusal.aliases, before.aliases);
  FR_CHECK_EQ(after_refusal.indexed_aliases, before.indexed_aliases);
  FR_CHECK_EQ(after_refusal.idempotency_records, before.idempotency_records);
  FR_CHECK_EQ(after_refusal.generation.value(), before.generation.value());
  FR_CHECK_EQ(after_refusal.epoch.value(), before.epoch.value());
  FR_CHECK(registry->state_digest() == digest_before);
  FR_CHECK(registry->all_ids(kEnumerateAll).empty());

  std::shared_ptr<const EntityRecord> absent;
  FR_CHECK_EQ(registry->lookup(*derived.id, absent).code, OutcomeCode::NotFound);
  FR_CHECK(absent == nullptr);

  RegisterEntityRequest synthetic = request;
  synthetic.provenance = frtest::synthetic_provenance("identityaliases");
  const Outcome committed = registry->register_entity(synthetic);
  FR_CHECK_MSG(committed.committed(),
               "the same registration with synthetic provenance must commit, got " +
                   std::string(to_string(committed.code)));

  std::shared_ptr<const EntityRecord> stored;
  FR_CHECK_EQ(registry->lookup(*derived.id, stored).code, OutcomeCode::Committed);
  FR_CHECK_MSG(stored != nullptr, "the committed record must be retrievable by its derived id");
  FR_CHECK_EQ(stored->lifecycle, Lifecycle::Current);
  FR_CHECK_EQ(stored->evidence.provenance.validity_class, ProvenanceClass::Synthetic);
  FR_CHECK_EQ(stored->evidence.provenance.source, ObservationSource::SyntheticFixture);
  FR_CHECK_EQ(registry->stats().entities, before.entities + 1);
}

} // namespace
