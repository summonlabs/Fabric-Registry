// Fabric Registry — identity fact canonicalisation, strength and derivation.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These checks pin the frozen identity contract of
// include/fabric_registry/identity.hpp to observable behaviour. Every real
// IdentityFactKind either canonicalises to exactly one documented form or is
// rejected with the documented IdentityIssue; no rejection is accepted without
// proving that no value was produced, and no canonical form is accepted without
// comparing it against the exact expected text.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/entity_class.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/ids.hpp"
#include "fabric_registry/limits.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::CanonicalIdResult;
using fabric_registry::EntityClass;
using fabric_registry::FactResult;
using fabric_registry::FactStrength;
using fabric_registry::FingerprintDigest;
using fabric_registry::IdentityFact;
using fabric_registry::IdentityFactKind;
using fabric_registry::IdentityIssue;
using fabric_registry::StableHardwareIdentity;
using fabric_registry::canonicalize_fact;
using fabric_registry::compute_identity_fingerprint;
using fabric_registry::compute_stable_hardware_identity;
using fabric_registry::derive_canonical_id;
using fabric_registry::fact_strength;
using fabric_registry::has_strong_fact;
using fabric_registry::normalize_fact_set;
using fabric_registry::significant_facts;

/// The tests bound identity strings with the library's own hard ceiling, so no
/// check depends on a constant invented here.
constexpr std::size_t kMaxBytes = fabric_registry::hard_limits::kMaxStringBytes;

static_assert(fabric_registry::kIdentityFactKindCount == 24,
              "the tables below must enumerate every real identity fact kind");

/// Every real fact kind, in enumerator order.
constexpr std::array<IdentityFactKind, fabric_registry::kIdentityFactKindCount> kAllKinds{
    IdentityFactKind::SerialNumber,
    IdentityFactKind::DeviceUuid,
    IdentityFactKind::SwitchGuid,
    IdentityFactKind::PortGuid,
    IdentityFactKind::FabricGuid,
    IdentityFactKind::ChassisId,
    IdentityFactKind::SlotId,
    IdentityFactKind::BoardId,
    IdentityFactKind::PciAddress,
    IdentityFactKind::PermanentMac,
    IdentityFactKind::MacAddress,
    IdentityFactKind::DeviceInstanceId,
    IdentityFactKind::VendorId,
    IdentityFactKind::ProductId,
    IdentityFactKind::SubsystemId,
    IdentityFactKind::DeviceModel,
    IdentityFactKind::FirmwareFamily,
    IdentityFactKind::HostName,
    IdentityFactKind::FriendlyName,
    IdentityFactKind::InventoryAssetId,
    IdentityFactKind::CloudResourceId,
    IdentityFactKind::OperatorLabel,
    IdentityFactKind::RackSlotLabel,
    IdentityFactKind::PortHardwareName};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonicalises (kind, scope, value) and returns the accepted fact. The case
/// aborts, reporting the actual issue, when the input was rejected or when the
/// accepted fact does not carry exactly the requested kind.
IdentityFact canonical_fact(IdentityFactKind kind,
                            std::string_view scope,
                            std::string_view value,
                            std::size_t max_bytes = kMaxBytes) {
  const FactResult result = canonicalize_fact(kind, scope, value, max_bytes);
  if (result.issue != IdentityIssue::None || !result.fact.has_value() || result.fact->kind != kind) {
    std::string message = "expected '";
    message.append(value);
    message.append("' in scope '");
    message.append(scope);
    message.append("' to canonicalise but got ");
    message.append(fabric_registry::to_string(result.issue));
    frtest::fail(__FILE__, __LINE__, message);
  }
  return *result.fact;
}

/// The canonical value of (kind, scope, value).
std::string canonical_value(IdentityFactKind kind,
                            std::string_view scope,
                            std::string_view value,
                            std::size_t max_bytes = kMaxBytes) {
  return canonical_fact(kind, scope, value, max_bytes).value;
}

/// Requires that canonicalisation rejected the input with exactly the expected
/// issue and produced no value at all.
void expect_issue(IdentityFactKind kind,
                  std::string_view scope,
                  std::string_view value,
                  std::size_t max_bytes,
                  IdentityIssue expected) {
  const FactResult result = canonicalize_fact(kind, scope, value, max_bytes);
  if (result.issue != expected || result.fact.has_value()) {
    std::string message = "expected ";
    message.append(fabric_registry::to_string(expected));
    message.append(" for '");
    message.append(value);
    message.append("' in scope '");
    message.append(scope);
    message.append("' but got ");
    message.append(fabric_registry::to_string(result.issue));
    if (result.fact.has_value()) {
      message.append(" and a canonical value");
    }
    frtest::fail(__FILE__, __LINE__, message);
  }
}

/// True when the byte sequence is rejected as identity text.
bool rejects_text(std::string_view bytes) {
  return !fabric_registry::is_valid_identity_text(bytes);
}

} // namespace

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityfacts, text_validation_rejects_malformed_utf8) {
  FR_CHECK(fabric_registry::is_valid_identity_text("plain ascii"));
  FR_CHECK(fabric_registry::is_valid_identity_text(""));
  FR_CHECK(fabric_registry::is_valid_identity_text(std::string_view("\xC3\xA9", 2)));       // U+00E9
  FR_CHECK(fabric_registry::is_valid_identity_text(std::string_view("\xE2\x82\xAC", 3)));   // U+20AC
  FR_CHECK(fabric_registry::is_valid_identity_text(std::string_view("\xF0\x9F\x98\x80", 4))); // U+1F600

  FR_CHECK(rejects_text(std::string_view("\xC0\x80", 2)));        // overlong encoding of NUL
  FR_CHECK(rejects_text(std::string_view("\x80", 1)));            // lone continuation byte
  FR_CHECK(rejects_text(std::string_view("\xE2\x82", 2)));        // truncated three-byte sequence
  FR_CHECK(rejects_text(std::string_view("\xED\xA0\x80", 3)));    // CESU-8 surrogate U+D800
  FR_CHECK(rejects_text(std::string_view("\xF5\x80\x80\x80", 4))); // above U+10FFFF
  FR_CHECK(rejects_text(std::string_view("a\0b", 3)));            // embedded NUL
  FR_CHECK(rejects_text(std::string_view("\x01", 1)));            // ASCII control character
  FR_CHECK(rejects_text(std::string_view("ok\x7F", 3)));          // DEL is a control character

  // Valid multi-byte text stays valid next to an ASCII control-free tail.
  FR_CHECK(fabric_registry::is_valid_identity_text(std::string_view("a\xC3\xA9z", 4)));
  FR_CHECK(rejects_text(std::string_view("a\xC3", 2)));           // truncated two-byte sequence
}

FR_TEST_CASE(identityfacts, trim_ascii_and_whitespace_classification) {
  constexpr std::array<char, 6> kWhitespace{' ', '\t', '\r', '\n', '\v', '\f'};
  for (char value : kWhitespace) {
    FR_CHECK(fabric_registry::is_ascii_whitespace(value));
  }
  FR_CHECK(!fabric_registry::is_ascii_whitespace('x'));
  FR_CHECK(!fabric_registry::is_ascii_whitespace('0'));
  FR_CHECK(!fabric_registry::is_ascii_whitespace('\0'));
  FR_CHECK(!fabric_registry::is_ascii_whitespace('-'));

  FR_CHECK_EQ(fabric_registry::trim_ascii("  value  "), std::string_view("value"));
  FR_CHECK_EQ(fabric_registry::trim_ascii("\t\r\n\v\fvalue\f\v\n\r\t"), std::string_view("value"));
  FR_CHECK_EQ(fabric_registry::trim_ascii("value"), std::string_view("value"));
  FR_CHECK_EQ(fabric_registry::trim_ascii("  a  b  "), std::string_view("a  b"));
  FR_CHECK_EQ(fabric_registry::trim_ascii("   "), std::string_view());
  FR_CHECK_EQ(fabric_registry::trim_ascii(""), std::string_view());
  FR_CHECK_EQ(fabric_registry::trim_ascii("\tvalue\n").front(), 'v');
  FR_CHECK_EQ(fabric_registry::trim_ascii("\tvalue\n").back(), 'e');
}

// ---------------------------------------------------------------------------
// Per-kind canonicalisation
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityfacts, unspecified_and_unknown_kinds_are_rejected) {
  expect_issue(IdentityFactKind::Unspecified, "scope", "value", kMaxBytes, IdentityIssue::UnknownFactKind);
  expect_issue(IdentityFactKind::Unspecified, "", "", kMaxBytes, IdentityIssue::UnknownFactKind);
  expect_issue(static_cast<IdentityFactKind>(200), "scope", "value", kMaxBytes, IdentityIssue::UnknownFactKind);
}

FR_TEST_CASE(identityfacts, serial_number_is_trimmed_and_scope_bound) {
  const IdentityFact fact = canonical_fact(IdentityFactKind::SerialNumber, "  acme:switch:1000  ", "  SN-0001  ");
  FR_CHECK_EQ(fact.scope, std::string("acme:switch:1000"));
  FR_CHECK_EQ(fact.value, std::string("SN-0001"));

  // The value is trimmed but its case is preserved; the scope is kept verbatim.
  FR_CHECK_EQ(canonical_value(IdentityFactKind::SerialNumber, "acme", "sn-0001"), std::string("sn-0001"));
  FR_CHECK_EQ(canonical_fact(IdentityFactKind::SerialNumber, "  acme  ", "SN-1").scope, std::string("acme"));

  // Serial numbers are only unique inside the scope that issued them.
  expect_issue(IdentityFactKind::SerialNumber, "", "SN-0001", kMaxBytes, IdentityIssue::ScopeRequired);
  expect_issue(IdentityFactKind::SerialNumber, " \t\r\n ", "SN-0001", kMaxBytes, IdentityIssue::ScopeRequired);

  expect_issue(IdentityFactKind::SerialNumber, "acme", "", kMaxBytes, IdentityIssue::EmptyValue);
  expect_issue(IdentityFactKind::SerialNumber, "acme", "   \t ", kMaxBytes, IdentityIssue::EmptyValue);

  // Exactly the bound is accepted; one byte more is refused.
  FR_CHECK_EQ(canonical_value(IdentityFactKind::SerialNumber, "acme", "SN-00001", 8), std::string("SN-00001"));
  expect_issue(IdentityFactKind::SerialNumber, "acme", "SN-000001", 8, IdentityIssue::ValueTooLong);

  // The scope has its own bound, checked before the value is even looked at.
  expect_issue(IdentityFactKind::SerialNumber, "acme-vendor", "SN-1", 8, IdentityIssue::ScopeTooLong);

  // NUL and control characters are refused in the scope and in the value.
  expect_issue(IdentityFactKind::SerialNumber, "acme", std::string("SN\0X", 4), kMaxBytes, IdentityIssue::InvalidText);
  expect_issue(IdentityFactKind::SerialNumber, "acme", std::string("SN\x01X", 4), kMaxBytes, IdentityIssue::InvalidText);
  expect_issue(IdentityFactKind::SerialNumber, std::string("ac\0me", 5), "SN-1", kMaxBytes, IdentityIssue::InvalidText);
  expect_issue(IdentityFactKind::SerialNumber, "ac\tme", "SN-1", kMaxBytes, IdentityIssue::InvalidText);
}

FR_TEST_CASE(identityfacts, guid_kinds_normalise_to_dashed_lowercase) {
  constexpr std::array<IdentityFactKind, 4> kGuidKinds{IdentityFactKind::DeviceUuid,
                                                       IdentityFactKind::SwitchGuid,
                                                       IdentityFactKind::PortGuid,
                                                       IdentityFactKind::FabricGuid};
  const std::string dashed("01234567-89ab-cdef-0123-456789abcdef");
  const std::string zero("00000000-0000-0000-0000-000000000000");

  for (IdentityFactKind kind : kGuidKinds) {
    FR_CHECK_EQ(canonical_value(kind, "", "0123456789abcdef0123456789abcdef"), dashed);
    FR_CHECK_EQ(canonical_value(kind, "", "{0123456789abcdef0123456789abcdef}"), dashed);
    FR_CHECK_EQ(canonical_value(kind, "", "{01234567-89ab-cdef-0123-456789abcdef}"), dashed);
    FR_CHECK_EQ(canonical_value(kind, "", "01234567-89ab-cdef-0123-456789ABCDEF"), dashed);
    FR_CHECK_EQ(canonical_value(kind, "", "  0123456789ABCDEF0123456789ABCDEF  "), dashed);

    // The all-zero GUID is a legal value, not an absent one.
    FR_CHECK_EQ(canonical_value(kind, "", "00000000000000000000000000000000"), zero);
    FR_CHECK_EQ(canonical_value(kind, "", "00000000-0000-0000-0000-000000000000"), zero);

    expect_issue(kind, "", "0123456789abcdef0123456789abcde", kMaxBytes, IdentityIssue::InvalidGuid);
    expect_issue(kind, "", "0123456789abcdef0123456789abcdef0", kMaxBytes, IdentityIssue::InvalidGuid);
    expect_issue(kind, "", "0123456789abcdef0123456789abcdeg", kMaxBytes, IdentityIssue::InvalidGuid);
    expect_issue(kind, "", "not-a-guid", kMaxBytes, IdentityIssue::InvalidGuid);
    expect_issue(kind, "", "01234567-89ab-cdef-0123-456789abcde", kMaxBytes, IdentityIssue::InvalidGuid);
    expect_issue(kind, "", "", kMaxBytes, IdentityIssue::EmptyValue);
  }
}

FR_TEST_CASE(identityfacts, chassis_board_and_slot_preserve_case) {
  constexpr std::array<IdentityFactKind, 3> kLocationKinds{
      IdentityFactKind::ChassisId, IdentityFactKind::BoardId, IdentityFactKind::SlotId};

  for (IdentityFactKind kind : kLocationKinds) {
    FR_CHECK_EQ(canonical_value(kind, "", "  Chassis-A/7  "), std::string("Chassis-A/7"));
    FR_CHECK_EQ(canonical_value(kind, "", "chassis-a/7"), std::string("chassis-a/7"));
    FR_CHECK_EQ(canonical_value(kind, "", "0"), std::string("0"));
    expect_issue(kind, "", "", kMaxBytes, IdentityIssue::EmptyValue);
    expect_issue(kind, "", " \t\r\n ", kMaxBytes, IdentityIssue::EmptyValue);
  }
}

FR_TEST_CASE(identityfacts, pci_address_normalises_to_bdf_form) {
  const IdentityFact fact = canonical_fact(IdentityFactKind::PciAddress, "", "0000:3b:00.0");
  FR_CHECK_EQ(fact.scope, std::string());
  FR_CHECK_EQ(fact.value, std::string("0000:3b:00.0"));

  FR_CHECK_EQ(canonical_value(IdentityFactKind::PciAddress, "", "3b:00.0"), std::string("0000:3b:00.0"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PciAddress, "", "0000:3B:00.0"), std::string("0000:3b:00.0"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PciAddress, "", "0:0.0"), std::string("0000:00:00.0"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PciAddress, "", "0000:3b:00.a"), std::string("0000:3b:00.a"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PciAddress, "", "  0000:3b:00.0  "), std::string("0000:3b:00.0"));

  expect_issue(IdentityFactKind::PciAddress, "", "0000:3b:00", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "0000:3b:00.10", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "zz:00.0", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "0000:3b:00.", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "0000:3b:00.g", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "00000:3b:00.0", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "0000:3b:000.0", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "0000:3b:00.0.1", kMaxBytes, IdentityIssue::InvalidPciAddress);
  expect_issue(IdentityFactKind::PciAddress, "", "", kMaxBytes, IdentityIssue::EmptyValue);
}

FR_TEST_CASE(identityfacts, permanent_mac_requires_universal_administration) {
  // The U/L bit is bit 1 of the first octet: 0x00 is universally administered,
  // 0x02 is local. A permanent MAC must be universal.
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PermanentMac, "", "00:11:22:33:44:55"), std::string("001122334455"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PermanentMac, "", "00-11-22-33-44-55"), std::string("001122334455"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PermanentMac, "", "0011.2233.4455"), std::string("001122334455"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PermanentMac, "", "001122334455"), std::string("001122334455"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::PermanentMac, "", "  00:11:22:33:44:55  "), std::string("001122334455"));

  // 0xAA has bit 1 set, so AA:BB:CC:DD:EE:FF is a locally administered address
  // however it is spelled, and it is refused for a permanent MAC.
  expect_issue(IdentityFactKind::PermanentMac, "", "AA:BB:CC:DD:EE:FF", kMaxBytes, IdentityIssue::LocallyAdministeredMac);
  expect_issue(IdentityFactKind::PermanentMac, "", "aa-bb-cc-dd-ee-ff", kMaxBytes, IdentityIssue::LocallyAdministeredMac);
  expect_issue(IdentityFactKind::PermanentMac, "", "aabb.ccdd.eeff", kMaxBytes, IdentityIssue::LocallyAdministeredMac);
  expect_issue(IdentityFactKind::PermanentMac, "", "AABBCCDDEEFF", kMaxBytes, IdentityIssue::LocallyAdministeredMac);
  expect_issue(IdentityFactKind::PermanentMac, "", "02:00:00:00:00:01", kMaxBytes, IdentityIssue::LocallyAdministeredMac);
  expect_issue(IdentityFactKind::PermanentMac, "", "020000000001", kMaxBytes, IdentityIssue::LocallyAdministeredMac);
  expect_issue(IdentityFactKind::PermanentMac, "", "06-00-00-00-00-01", kMaxBytes, IdentityIssue::LocallyAdministeredMac);

  // A five-byte value is not a MAC address, and neither is a longer one.
  expect_issue(IdentityFactKind::PermanentMac, "", "AA:BB:CC:DD:EE", kMaxBytes, IdentityIssue::InvalidMacAddress);
  expect_issue(IdentityFactKind::PermanentMac, "", "AA:BB:CC:DD:EE:FF:00", kMaxBytes, IdentityIssue::InvalidMacAddress);
  expect_issue(IdentityFactKind::PermanentMac, "", "zz:bb:cc:dd:ee:ff", kMaxBytes, IdentityIssue::InvalidMacAddress);
  expect_issue(IdentityFactKind::PermanentMac, "", "", kMaxBytes, IdentityIssue::EmptyValue);
}

FR_TEST_CASE(identityfacts, mac_address_accepts_local_administration) {
  const IdentityFact fact = canonical_fact(IdentityFactKind::MacAddress, "", "02:00:00:00:00:01");
  FR_CHECK_EQ(fact.kind, IdentityFactKind::MacAddress);
  FR_CHECK_EQ(fact.value, std::string("020000000001"));

  FR_CHECK_EQ(canonical_value(IdentityFactKind::MacAddress, "", "AA-BB-CC-DD-EE-FF"), std::string("aabbccddeeff"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::MacAddress, "", "02:00:00:00:00:01"), std::string("020000000001"));

  expect_issue(IdentityFactKind::MacAddress, "", "AA:BB:CC:DD:EE", kMaxBytes, IdentityIssue::InvalidMacAddress);
  expect_issue(IdentityFactKind::MacAddress, "", "", kMaxBytes, IdentityIssue::EmptyValue);
}

FR_TEST_CASE(identityfacts, device_instance_id_is_lowercase_and_scope_bound) {
  const IdentityFact fact =
      canonical_fact(IdentityFactKind::DeviceInstanceId, "  host:SW-01  ", "  PCI\\VEN_15B3&DEV_1017  ");
  FR_CHECK_EQ(fact.scope, std::string("host:SW-01"));
  FR_CHECK_EQ(fact.value, std::string("pci\\ven_15b3&dev_1017"));

  expect_issue(IdentityFactKind::DeviceInstanceId, "", "PCI\\VEN_15B3", kMaxBytes, IdentityIssue::ScopeRequired);
  expect_issue(IdentityFactKind::DeviceInstanceId, "   ", "PCI\\VEN_15B3", kMaxBytes, IdentityIssue::ScopeRequired);
  expect_issue(IdentityFactKind::DeviceInstanceId, "host:SW-01", "", kMaxBytes, IdentityIssue::EmptyValue);
  expect_issue(IdentityFactKind::DeviceInstanceId,
               "host:SW-01",
               std::string("PCI\0VEN", 7),
               kMaxBytes,
               IdentityIssue::InvalidText);
}

FR_TEST_CASE(identityfacts, numeric_identifiers_render_canonical_hex) {
  constexpr std::array<IdentityFactKind, 3> kNumericKinds{
      IdentityFactKind::VendorId, IdentityFactKind::ProductId, IdentityFactKind::SubsystemId};

  for (IdentityFactKind kind : kNumericKinds) {
    FR_CHECK_EQ(canonical_value(kind, "", "0x15b3"), std::string("0x15b3"));
    FR_CHECK_EQ(canonical_value(kind, "", "15B3"), std::string("0x15b3"));
    FR_CHECK_EQ(canonical_value(kind, "", "15b3"), std::string("0x15b3"));
    FR_CHECK_EQ(canonical_value(kind, "", "  0X15B3  "), std::string("0x15b3"));
    FR_CHECK_EQ(canonical_value(kind, "", "1"), std::string("0x0001"));

    expect_issue(kind, "", "0x0", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "0", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "0x0000", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "12345", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "15b300", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "zzzz", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "0x", kMaxBytes, IdentityIssue::InvalidNumericId);
    expect_issue(kind, "", "", kMaxBytes, IdentityIssue::EmptyValue);
  }
}

FR_TEST_CASE(identityfacts, host_name_is_lowercased_and_label_checked) {
  const IdentityFact fact = canonical_fact(IdentityFactKind::HostName, "", "  SW-01.Example.COM.  ");
  FR_CHECK_EQ(fact.scope, std::string());
  FR_CHECK_EQ(fact.value, std::string("sw-01.example.com"));

  FR_CHECK_EQ(canonical_value(IdentityFactKind::HostName, "", "SW-01.Example.COM."), std::string("sw-01.example.com"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::HostName, "", "a_b"), std::string("a_b"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::HostName, "", "SW_01"), std::string("sw_01"));
  FR_CHECK_EQ(canonical_value(IdentityFactKind::HostName, "", "host-7"), std::string("host-7"));

  // A 63-byte label is the longest legal one; a 64-byte label is refused.
  const std::string max_label(63, 'a');
  const std::string too_long_label(64, 'a');
  FR_CHECK_EQ(canonical_value(IdentityFactKind::HostName, "", max_label), max_label);
  FR_CHECK_EQ(canonical_value(IdentityFactKind::HostName, "", max_label + "." + max_label), max_label + "." + max_label);
  expect_issue(IdentityFactKind::HostName, "", too_long_label, kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "a." + too_long_label, kMaxBytes, IdentityIssue::InvalidHostName);

  expect_issue(IdentityFactKind::HostName, "", "a..b", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "sw-01..example.com", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", ".example.com", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "-a", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "sw-01.-example.com", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "sw-01-.example.com", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "sw 01", kMaxBytes, IdentityIssue::InvalidHostName);
  expect_issue(IdentityFactKind::HostName, "", "", kMaxBytes, IdentityIssue::EmptyValue);
}

FR_TEST_CASE(identityfacts, free_form_kinds_are_trimmed_and_case_preserved) {
  constexpr std::array<IdentityFactKind, 8> kFreeFormKinds{IdentityFactKind::DeviceModel,
                                                           IdentityFactKind::FirmwareFamily,
                                                           IdentityFactKind::FriendlyName,
                                                           IdentityFactKind::InventoryAssetId,
                                                           IdentityFactKind::CloudResourceId,
                                                           IdentityFactKind::OperatorLabel,
                                                           IdentityFactKind::RackSlotLabel,
                                                           IdentityFactKind::PortHardwareName};

  for (IdentityFactKind kind : kFreeFormKinds) {
    FR_CHECK_EQ(canonical_value(kind, "", "  Rack-7 / Slot B  "), std::string("Rack-7 / Slot B"));
    FR_CHECK_EQ(canonical_value(kind, "", "Tahoe 25G"), std::string("Tahoe 25G"));
    FR_CHECK_EQ(canonical_value(kind, "", "tahoe 25g"), std::string("tahoe 25g"));
    expect_issue(kind, "", "", kMaxBytes, IdentityIssue::EmptyValue);
    expect_issue(kind, "", "  \t\r\n ", kMaxBytes, IdentityIssue::EmptyValue);
    expect_issue(kind, "", std::string("a\0b", 3), kMaxBytes, IdentityIssue::InvalidText);
    expect_issue(kind, "", std::string("a\x01b", 3), kMaxBytes, IdentityIssue::InvalidText);
    expect_issue(kind, "", std::string(kMaxBytes + 1, 'x'), kMaxBytes, IdentityIssue::ValueTooLong);
  }

  // These kinds do not require a scope, but a scope that is supplied is kept.
  const IdentityFact scoped = canonical_fact(IdentityFactKind::FriendlyName, "  acme  ", "  Tahoe  ");
  FR_CHECK_EQ(scoped.scope, std::string("acme"));
  FR_CHECK_EQ(scoped.value, std::string("Tahoe"));
}

// ---------------------------------------------------------------------------
// Strength and naming
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityfacts, fact_strength_covers_every_kind) {
  struct Expectation {
    IdentityFactKind kind;
    FactStrength strength;
  };

  const std::array<Expectation, fabric_registry::kIdentityFactKindCount> expectations{{
      {IdentityFactKind::SerialNumber, FactStrength::Strong},
      {IdentityFactKind::DeviceUuid, FactStrength::Strong},
      {IdentityFactKind::SwitchGuid, FactStrength::Strong},
      {IdentityFactKind::PortGuid, FactStrength::Strong},
      {IdentityFactKind::FabricGuid, FactStrength::Strong},
      {IdentityFactKind::ChassisId, FactStrength::Strong},
      {IdentityFactKind::SlotId, FactStrength::Moderate},
      {IdentityFactKind::BoardId, FactStrength::Moderate},
      {IdentityFactKind::PciAddress, FactStrength::Strong},
      {IdentityFactKind::PermanentMac, FactStrength::Strong},
      {IdentityFactKind::MacAddress, FactStrength::Moderate},
      {IdentityFactKind::DeviceInstanceId, FactStrength::Strong},
      {IdentityFactKind::VendorId, FactStrength::Weak},
      {IdentityFactKind::ProductId, FactStrength::Weak},
      {IdentityFactKind::SubsystemId, FactStrength::Weak},
      {IdentityFactKind::DeviceModel, FactStrength::Weak},
      {IdentityFactKind::FirmwareFamily, FactStrength::Weak},
      {IdentityFactKind::HostName, FactStrength::Weak},
      {IdentityFactKind::FriendlyName, FactStrength::Weak},
      {IdentityFactKind::InventoryAssetId, FactStrength::Moderate},
      {IdentityFactKind::CloudResourceId, FactStrength::Moderate},
      {IdentityFactKind::OperatorLabel, FactStrength::Weak},
      {IdentityFactKind::RackSlotLabel, FactStrength::Weak},
      {IdentityFactKind::PortHardwareName, FactStrength::Moderate},
  }};

  for (const Expectation& expectation : expectations) {
    FR_CHECK_EQ(fact_strength(expectation.kind), expectation.strength);
  }

  // The sentinel kind is not a real kind and never carries weight.
  FR_CHECK_EQ(fact_strength(IdentityFactKind::Unspecified), FactStrength::Weak);

  // Scope-bound kinds: only a serial number and a device instance id.
  FR_CHECK(fabric_registry::fact_requires_scope(IdentityFactKind::SerialNumber));
  FR_CHECK(fabric_registry::fact_requires_scope(IdentityFactKind::DeviceInstanceId));
  FR_CHECK(!fabric_registry::fact_requires_scope(IdentityFactKind::DeviceUuid));
  FR_CHECK(!fabric_registry::fact_requires_scope(IdentityFactKind::MacAddress));
  FR_CHECK(!fabric_registry::fact_requires_scope(IdentityFactKind::Unspecified));
}

FR_TEST_CASE(identityfacts, fact_kind_names_round_trip) {
  std::size_t named = 0;
  for (IdentityFactKind kind : kAllKinds) {
    const std::string_view name = fabric_registry::to_string(kind);
    FR_CHECK(!name.empty());
    FR_CHECK(name != std::string_view("unspecified"));
    const std::optional<IdentityFactKind> parsed = fabric_registry::identity_fact_kind_from_string(name);
    FR_CHECK(parsed.has_value());
    FR_CHECK_EQ(*parsed, kind);
    ++named;
  }
  FR_CHECK_EQ(named, static_cast<std::size_t>(fabric_registry::kIdentityFactKindCount));

  FR_CHECK(!fabric_registry::identity_fact_kind_from_string("not-a-kind").has_value());
  FR_CHECK(!fabric_registry::identity_fact_kind_from_string("").has_value());
  FR_CHECK(!fabric_registry::identity_fact_kind_from_string("Serial-Number").has_value());
  FR_CHECK(!fabric_registry::identity_fact_kind_from_string("serial number").has_value());

  FR_CHECK_EQ(fabric_registry::to_string(IdentityFactKind::Unspecified), std::string_view("unspecified"));
  FR_CHECK_EQ(fabric_registry::to_string(FactStrength::Weak), std::string_view("weak"));
  FR_CHECK_EQ(fabric_registry::to_string(FactStrength::Moderate), std::string_view("moderate"));
  FR_CHECK_EQ(fabric_registry::to_string(FactStrength::Strong), std::string_view("strong"));
}

// ---------------------------------------------------------------------------
// Whole fact sets
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityfacts, normalize_fact_set_detects_duplicates_and_contradictions) {
  std::vector<IdentityFact> out;
  const IdentityFact serial = canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1");
  const IdentityFact duplicate = canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1");
  const IdentityFact other_value = canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-2");
  const IdentityFact other_scope = canonical_fact(IdentityFactKind::SerialNumber, "other", "SN-1");

  IdentityIssue issue = normalize_fact_set(std::vector<IdentityFact>{serial, duplicate}, 8, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::DuplicateFact);

  issue = normalize_fact_set(std::vector<IdentityFact>{serial, other_value}, 8, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::ContradictoryFact);

  // Trimming happens before the comparison, so padded input collides too.
  issue = normalize_fact_set(std::vector<IdentityFact>{serial, canonical_fact(IdentityFactKind::SerialNumber, " acme ", "SN-2")},
                             8,
                             kMaxBytes,
                             out);
  FR_CHECK_EQ(issue, IdentityIssue::ContradictoryFact);

  // Equivalent MAC spellings are one and the same fact.
  issue = normalize_fact_set(std::vector<IdentityFact>{IdentityFact{IdentityFactKind::MacAddress, "", "AA:BB:CC:DD:EE:FF"},
                                                       IdentityFact{IdentityFactKind::MacAddress, "", "aabbccddeeff"}},
                             8,
                             kMaxBytes,
                             out);
  FR_CHECK_EQ(issue, IdentityIssue::DuplicateFact);

  // The same value under a different scope is a different fact, not a clash.
  issue = normalize_fact_set(std::vector<IdentityFact>{serial, other_scope}, 8, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::None);
  FR_CHECK_EQ(out.size(), std::size_t{2});
  FR_CHECK_EQ(out[0].scope, std::string("acme"));
  FR_CHECK_EQ(out[0].value, std::string("SN-1"));
  FR_CHECK_EQ(out[1].scope, std::string("other"));
  FR_CHECK_EQ(out[1].value, std::string("SN-1"));

  // Two different kinds carrying the same text never collide.
  issue = normalize_fact_set(std::vector<IdentityFact>{canonical_fact(IdentityFactKind::ChassisId, "", "chassis-1"),
                                                       canonical_fact(IdentityFactKind::BoardId, "", "chassis-1")},
                             8,
                             kMaxBytes,
                             out);
  FR_CHECK_EQ(issue, IdentityIssue::None);
  FR_CHECK_EQ(out.size(), std::size_t{2});

  // The output vector is replaced by each call, never appended to, so a
  // refused set cannot leave a partial result for the next call to extend.
  issue = normalize_fact_set(std::vector<IdentityFact>{serial}, 8, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::None);
  FR_CHECK_EQ(out.size(), std::size_t{1});
  FR_CHECK_EQ(out[0], serial);
}

FR_TEST_CASE(identityfacts, normalize_fact_set_enforces_the_bound_and_sorts) {
  std::vector<IdentityFact> out;

  // Bound first: an over-long set is refused before any fact is looked at.
  std::vector<IdentityFact> too_many{canonical_fact(IdentityFactKind::PciAddress, "", "0000:3b:00.0"),
                                     canonical_fact(IdentityFactKind::SlotId, "", "1"),
                                     canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1")};
  IdentityIssue issue = normalize_fact_set(too_many, 2, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::TooManyFacts);
  FR_CHECK(out.empty());

  // The bound is reported before the malformed fact inside the set is seen.
  too_many[0] = IdentityFact{IdentityFactKind::SerialNumber, "", ""};
  issue = normalize_fact_set(too_many, 2, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::TooManyFacts);
  FR_CHECK(out.empty());

  too_many[0] = canonical_fact(IdentityFactKind::PciAddress, "", "0000:3b:00.0");

  // A set at the bound is accepted and sorted by (kind, scope, value).
  issue = normalize_fact_set(too_many, 3, kMaxBytes, out);
  FR_CHECK_EQ(issue, IdentityIssue::None);
  FR_CHECK_EQ(out.size(), std::size_t{3});
  FR_CHECK_EQ(out[0].kind, IdentityFactKind::SerialNumber);
  FR_CHECK_EQ(out[0].scope, std::string("acme"));
  FR_CHECK_EQ(out[0].value, std::string("SN-1"));
  FR_CHECK_EQ(out[1].kind, IdentityFactKind::SlotId);
  FR_CHECK_EQ(out[1].scope, std::string());
  FR_CHECK_EQ(out[1].value, std::string("1"));
  FR_CHECK_EQ(out[2].kind, IdentityFactKind::PciAddress);
  FR_CHECK_EQ(out[2].value, std::string("0000:3b:00.0"));

  // Within one kind the ordering is by canonical scope text, compared
  // lexicographically rather than by length or by any numeric reading.
  issue = normalize_fact_set(std::vector<IdentityFact>{canonical_fact(IdentityFactKind::SlotId, "bay-10", "3"),
                                                       canonical_fact(IdentityFactKind::SlotId, "bay-1", "2"),
                                                       canonical_fact(IdentityFactKind::SlotId, "", "1")},
                             8,
                             kMaxBytes,
                             out);
  FR_CHECK_EQ(issue, IdentityIssue::None);
  FR_CHECK_EQ(out.size(), std::size_t{3});
  FR_CHECK_EQ(out[0].scope, std::string());
  FR_CHECK_EQ(out[0].value, std::string("1"));
  FR_CHECK_EQ(out[1].scope, std::string("bay-1"));
  FR_CHECK_EQ(out[1].value, std::string("2"));
  FR_CHECK_EQ(out[2].scope, std::string("bay-10"));
  FR_CHECK_EQ(out[2].value, std::string("3"));

  // Raw input is canonicalised on the way through.
  issue = normalize_fact_set(std::vector<IdentityFact>{IdentityFact{IdentityFactKind::SerialNumber, "  acme  ", "  SN-1  "}},
                             8,
                             kMaxBytes,
                             out);
  FR_CHECK_EQ(issue, IdentityIssue::None);
  FR_CHECK_EQ(out.size(), std::size_t{1});
  FR_CHECK_EQ(out[0].scope, std::string("acme"));
  FR_CHECK_EQ(out[0].value, std::string("SN-1"));

  // A rejected fact propagates its own specific issue, not a generic failure.
  issue = normalize_fact_set(std::vector<IdentityFact>{canonical_fact(IdentityFactKind::SlotId, "", "1"),
                                                       IdentityFact{IdentityFactKind::SerialNumber, "", "SN-1"}},
                             8,
                             kMaxBytes,
                             out);
  FR_CHECK_EQ(issue, IdentityIssue::ScopeRequired);
}

// ---------------------------------------------------------------------------
// Digests and derivation
// ---------------------------------------------------------------------------

FR_TEST_CASE(identityfacts, stable_hardware_identity_uses_only_strong_facts) {
  const std::vector<IdentityFact> strong{canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1"),
                                         canonical_fact(IdentityFactKind::PciAddress, "", "0000:3b:00.0"),
                                         canonical_fact(IdentityFactKind::PermanentMac, "", "00:11:22:33:44:55")};
  const std::vector<IdentityFact> permuted{strong[2], strong[0], strong[1]};
  const StableHardwareIdentity baseline = compute_stable_hardware_identity(strong);
  FR_CHECK(!baseline.is_null());
  FR_CHECK_EQ(compute_stable_hardware_identity(permuted), baseline);

  // Weak and moderate facts never move the digest.
  std::vector<IdentityFact> with_extra = strong;
  with_extra.push_back(canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe"));
  with_extra.push_back(canonical_fact(IdentityFactKind::VendorId, "", "15b3"));
  with_extra.push_back(canonical_fact(IdentityFactKind::SlotId, "", "3"));
  with_extra.push_back(canonical_fact(IdentityFactKind::MacAddress, "", "02:00:00:00:00:01"));
  FR_CHECK_EQ(compute_stable_hardware_identity(with_extra), baseline);

  // Changing a strong value or its scope changes the digest.
  std::vector<IdentityFact> changed = strong;
  changed[1] = canonical_fact(IdentityFactKind::PciAddress, "", "0000:3b:00.1");
  FR_CHECK(!(compute_stable_hardware_identity(changed) == baseline));

  std::vector<IdentityFact> rescoped = strong;
  rescoped[0] = canonical_fact(IdentityFactKind::SerialNumber, "other", "SN-1");
  FR_CHECK(!(compute_stable_hardware_identity(rescoped) == baseline));

  // A set with no strong fact digests exactly like the empty strong set.
  const std::vector<IdentityFact> weak_only{canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe"),
                                            canonical_fact(IdentityFactKind::VendorId, "", "15b3"),
                                            canonical_fact(IdentityFactKind::SlotId, "", "3")};
  const std::vector<IdentityFact> no_facts;
  const StableHardwareIdentity empty_digest = compute_stable_hardware_identity(no_facts);
  FR_CHECK(!empty_digest.is_null());
  FR_CHECK_EQ(compute_stable_hardware_identity(weak_only), empty_digest);
}

FR_TEST_CASE(identityfacts, identity_fingerprint_covers_namespace_and_class) {
  const std::vector<IdentityFact> facts{canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1"),
                                        canonical_fact(IdentityFactKind::SlotId, "", "3")};
  const FingerprintDigest baseline = compute_identity_fingerprint(EntityClass::Switch, "ns-a", facts);
  FR_CHECK(!baseline.is_null());
  FR_CHECK_EQ(compute_identity_fingerprint(EntityClass::Switch, "ns-a", facts), baseline);

  FR_CHECK(!(compute_identity_fingerprint(EntityClass::Switch, "ns-b", facts) == baseline));
  FR_CHECK(!(compute_identity_fingerprint(EntityClass::Router, "ns-a", facts) == baseline));

  // Weak facts are outside the fingerprint.
  std::vector<IdentityFact> with_weak = facts;
  with_weak.push_back(canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe"));
  FR_CHECK_EQ(compute_identity_fingerprint(EntityClass::Switch, "ns-a", with_weak), baseline);

  std::vector<IdentityFact> other_weak = facts;
  other_weak.push_back(canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe 2"));
  other_weak.push_back(canonical_fact(IdentityFactKind::HostName, "", "SW-01"));
  FR_CHECK_EQ(compute_identity_fingerprint(EntityClass::Switch, "ns-a", other_weak), baseline);

  // A different strong fact moves the fingerprint.
  const std::vector<IdentityFact> changed{canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-2"),
                                          canonical_fact(IdentityFactKind::SlotId, "", "3")};
  FR_CHECK(!(compute_identity_fingerprint(EntityClass::Switch, "ns-a", changed) == baseline));
}

FR_TEST_CASE(identityfacts, derive_canonical_id_is_deterministic_and_class_qualified) {
  const std::vector<IdentityFact> facts{canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1"),
                                        canonical_fact(IdentityFactKind::PciAddress, "", "0000:3b:00.0")};
  const CanonicalIdResult first = derive_canonical_id(EntityClass::Switch, "ns-a", facts, kMaxBytes);
  FR_CHECK_EQ(first.issue, IdentityIssue::None);
  FR_CHECK(first.id.has_value());
  FR_CHECK(!first.id->is_null());
  FR_CHECK_EQ(first.id->entity_class(), EntityClass::Switch);
  FR_CHECK(static_cast<bool>(first));

  const std::string rendered = first.id->to_string();
  FR_CHECK_EQ(rendered.size(), std::size_t{7} + fabric_registry::kOpaqueIdTextLength);
  FR_CHECK_EQ(rendered.substr(0, 7), std::string("switch:"));

  // Same inputs, same id.
  const CanonicalIdResult second = derive_canonical_id(EntityClass::Switch, "ns-a", facts, kMaxBytes);
  FR_CHECK(second.id.has_value());
  FR_CHECK_EQ(*second.id, *first.id);
  FR_CHECK_EQ(second.id->to_string(), rendered);

  // A different namespace or a different class derives a different id.
  const CanonicalIdResult other_namespace = derive_canonical_id(EntityClass::Switch, "ns-b", facts, kMaxBytes);
  FR_CHECK(other_namespace.id.has_value());
  FR_CHECK(!(*other_namespace.id == *first.id));

  const CanonicalIdResult other_class = derive_canonical_id(EntityClass::Router, "ns-a", facts, kMaxBytes);
  FR_CHECK(other_class.id.has_value());
  FR_CHECK_EQ(other_class.id->entity_class(), EntityClass::Router);
  FR_CHECK(!(*other_class.id == *first.id));

  // A namespace exactly at the bound is accepted.
  const CanonicalIdResult at_bound = derive_canonical_id(EntityClass::Switch, "12345678", facts, 8);
  FR_CHECK_EQ(at_bound.issue, IdentityIssue::None);
  FR_CHECK(at_bound.id.has_value());
}

FR_TEST_CASE(identityfacts, derive_canonical_id_rejects_unusable_inputs) {
  const std::vector<IdentityFact> strong{canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1")};
  const std::vector<IdentityFact> weak_only{canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe"),
                                            canonical_fact(IdentityFactKind::SlotId, "", "3")};
  const std::vector<IdentityFact> no_facts;

  const CanonicalIdResult unknown_class = derive_canonical_id(EntityClass::Unknown, "ns-a", strong, kMaxBytes);
  FR_CHECK_EQ(unknown_class.issue, IdentityIssue::InvalidEntityClass);
  FR_CHECK(!unknown_class.id.has_value());
  FR_CHECK(!static_cast<bool>(unknown_class));

  const CanonicalIdResult empty_namespace = derive_canonical_id(EntityClass::Switch, "", strong, kMaxBytes);
  FR_CHECK_EQ(empty_namespace.issue, IdentityIssue::EmptyDerivationNamespace);
  FR_CHECK(!empty_namespace.id.has_value());

  const CanonicalIdResult long_namespace = derive_canonical_id(EntityClass::Switch, "012345678", strong, 8);
  FR_CHECK_EQ(long_namespace.issue, IdentityIssue::NamespaceTooLong);
  FR_CHECK(!long_namespace.id.has_value());

  const CanonicalIdResult no_strong_fact = derive_canonical_id(EntityClass::Switch, "ns-a", weak_only, kMaxBytes);
  FR_CHECK_EQ(no_strong_fact.issue, IdentityIssue::NoStrongFact);
  FR_CHECK(!no_strong_fact.id.has_value());

  const CanonicalIdResult empty_set = derive_canonical_id(EntityClass::Switch, "ns-a", no_facts, kMaxBytes);
  FR_CHECK_EQ(empty_set.issue, IdentityIssue::NoStrongFact);
  FR_CHECK(!empty_set.id.has_value());

  // The class is decided before the namespace and the facts: an unknown class
  // never loses its diagnosis to a later, less specific complaint.
  const CanonicalIdResult class_first = derive_canonical_id(EntityClass::Unknown, "", no_facts, kMaxBytes);
  FR_CHECK_EQ(class_first.issue, IdentityIssue::InvalidEntityClass);
  FR_CHECK(!class_first.id.has_value());
}

FR_TEST_CASE(identityfacts, strong_and_significant_fact_helpers_agree_with_strength) {
  // Deliberately unsorted: weak, moderate, strong, weak, moderate.
  const std::vector<IdentityFact> mixed{canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe"),
                                        canonical_fact(IdentityFactKind::SlotId, "", "3"),
                                        canonical_fact(IdentityFactKind::SerialNumber, "acme", "SN-1"),
                                        canonical_fact(IdentityFactKind::VendorId, "", "15b3"),
                                        canonical_fact(IdentityFactKind::MacAddress, "", "02:00:00:00:00:01")};

  std::size_t strong_count = 0;
  std::size_t significant_count = 0;
  for (const IdentityFact& fact : mixed) {
    const FactStrength strength = fact_strength(fact.kind);
    if (strength == FactStrength::Strong) {
      ++strong_count;
    }
    if (strength != FactStrength::Weak) {
      ++significant_count;
    }
  }
  FR_CHECK_EQ(strong_count, std::size_t{1});
  FR_CHECK_EQ(significant_count, std::size_t{3});
  FR_CHECK_EQ(has_strong_fact(mixed), strong_count != 0);

  const std::vector<IdentityFact> significant = significant_facts(mixed);
  FR_CHECK_EQ(significant.size(), significant_count);
  for (const IdentityFact& fact : significant) {
    FR_CHECK(fact_strength(fact.kind) != FactStrength::Weak);
  }
  FR_CHECK_EQ(significant[0].kind, IdentityFactKind::SerialNumber);
  FR_CHECK_EQ(significant[0].scope, std::string("acme"));
  FR_CHECK_EQ(significant[1].kind, IdentityFactKind::SlotId);
  FR_CHECK_EQ(significant[2].kind, IdentityFactKind::MacAddress);
  FR_CHECK_EQ(significant[2].value, std::string("020000000001"));

  const std::vector<IdentityFact> weak_only{canonical_fact(IdentityFactKind::DeviceModel, "", "Tahoe"),
                                            canonical_fact(IdentityFactKind::VendorId, "", "15b3"),
                                            canonical_fact(IdentityFactKind::HostName, "", "sw-01")};
  FR_CHECK(!has_strong_fact(weak_only));
  FR_CHECK_EQ(has_strong_fact(std::vector<IdentityFact>{}), false);
  FR_CHECK(significant_facts(weak_only).empty());
}
