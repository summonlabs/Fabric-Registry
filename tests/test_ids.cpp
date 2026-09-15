// Fabric Registry — strongly typed identifier proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These checks pin the frozen identifier contract of
// include/fabric_registry/ids.hpp to observable behaviour. Every id type either
// renders the exact canonical form the contract promises, or it is rejected
// with no value produced: no check here is satisfied by bare truthiness and no
// rejection is checked without also proving that nothing was returned.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include "fabric_registry/entity_class.hpp"
#include "fabric_registry/ids.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::CanonicalId;
using fabric_registry::Counter;
using fabric_registry::DeviceId;
using fabric_registry::DigestValue;
using fabric_registry::EntityClass;
using fabric_registry::IdBytes;
using fabric_registry::OpaqueId;
using fabric_registry::SerialIdentity;
using fabric_registry::VendorId;

/// A non-null, non-repeating 128-bit pattern. The first byte is 0x37, so the
/// rendering always contains hexadecimal letters.
IdBytes pattern_bytes() {
  IdBytes out{};
  for (std::size_t index = 0; index < out.size(); ++index) {
    out[index] = static_cast<std::uint8_t>((index * 31u + 0x37u) & 0xFFu);
  }
  return out;
}

std::string ascii_upper(std::string_view text) {
  std::string out(text);
  for (char& value : out) {
    if (value >= 'a' && value <= 'f') {
      value = static_cast<char>(value - 'a' + 'A');
    }
  }
  return out;
}

bool is_lowercase_hex(std::string_view text) {
  for (char value : text) {
    const bool digit = value >= '0' && value <= '9';
    const bool letter = value >= 'a' && value <= 'f';
    if (!digit && !letter) {
      return false;
    }
  }
  return true;
}

/// Detects whether CanonicalId::of accepts an id type. The tag traits of the
/// non-entity domains deliberately do not declare `is_entity_id`, so the
/// expression is ill-formed for them: PublisherId, WorkerBootId and
/// RegistrationId must not be usable as canonical identities at all.
template <class TypedId, class = void>
struct canonical_of_accepts : std::false_type {};

template <class TypedId>
struct canonical_of_accepts<
    TypedId,
    std::void_t<decltype(fabric_registry::CanonicalId::of(std::declval<const TypedId&>()))>> : std::true_type {};

template <class TypedId, class = void>
struct canonical_as_accepts : std::false_type {};

template <class TypedId>
struct canonical_as_accepts<
    TypedId,
    std::void_t<decltype(std::declval<const fabric_registry::CanonicalId&>().template as<TypedId>())>>
    : std::true_type {};

} // namespace

FR_TEST_CASE(ids, opaque_default_is_the_null_id) {
  const fabric_registry::SwitchId absent;
  FR_CHECK(absent.is_null());
  FR_CHECK_EQ(absent.to_string(), std::string(fabric_registry::kOpaqueIdTextLength, '0'));

  const fabric_registry::SwitchId present = fabric_registry::SwitchId::from_bytes(pattern_bytes());
  FR_CHECK(!present.is_null());
  FR_CHECK(!(present == absent));
  FR_CHECK(present < absent || absent < present);
}

FR_TEST_CASE(ids, opaque_text_is_32_lowercase_hex) {
  IdBytes raw{};
  for (std::size_t index = 0; index < raw.size(); ++index) {
    raw[index] = static_cast<std::uint8_t>(index);
  }
  const fabric_registry::PortId id = fabric_registry::PortId::from_bytes(raw);
  const std::string text = id.to_string();
  FR_CHECK_EQ(text.size(), std::size_t{32});
  FR_CHECK_EQ(text, std::string("000102030405060708090a0b0c0d0e0f"));
  FR_CHECK(is_lowercase_hex(text));

  char rendered[fabric_registry::kOpaqueIdTextLength] = {};
  fabric_registry::render_hex(raw.data(), raw.size(), rendered);
  FR_CHECK_EQ(std::string(rendered, sizeof(rendered)), text);

  IdBytes parsed{};
  FR_CHECK(fabric_registry::parse_hex(text.data(), text.size(), parsed.data()));
  FR_CHECK_EQ(parsed, raw);

  const std::string non_hex = "z" + text.substr(1);
  FR_CHECK(!fabric_registry::parse_hex(non_hex.data(), non_hex.size(), parsed.data()));
}

FR_TEST_CASE(ids, opaque_id_round_trips_through_text) {
  frtest::Rng rng(0x1D5u);
  for (std::size_t iteration = 0; iteration < 256; ++iteration) {
    IdBytes raw{};
    for (std::size_t index = 0; index < raw.size(); ++index) {
      raw[index] = static_cast<std::uint8_t>(rng.next_u32() & 0xFFu);
    }
    const fabric_registry::SwitchId original = fabric_registry::SwitchId::from_bytes(raw);
    const std::string text = original.to_string();
    FR_CHECK_EQ(text.size(), fabric_registry::kOpaqueIdTextLength);
    FR_CHECK(is_lowercase_hex(text));

    const std::optional<fabric_registry::SwitchId> parsed = fabric_registry::SwitchId::parse(text);
    FR_CHECK(parsed.has_value());
    FR_CHECK_EQ(*parsed, original);
    FR_CHECK_EQ(parsed->bytes(), raw);
  }
}

FR_TEST_CASE(ids, opaque_parse_accepts_both_cases) {
  const fabric_registry::SwitchId id = fabric_registry::SwitchId::from_bytes(pattern_bytes());
  const std::string lower = id.to_string();
  const std::string upper = ascii_upper(lower);
  FR_CHECK(upper != lower);

  const std::optional<fabric_registry::SwitchId> parsed_lower = fabric_registry::SwitchId::parse(lower);
  const std::optional<fabric_registry::SwitchId> parsed_upper = fabric_registry::SwitchId::parse(upper);
  FR_CHECK(parsed_lower.has_value());
  FR_CHECK(parsed_upper.has_value());
  FR_CHECK_EQ(*parsed_lower, id);
  FR_CHECK_EQ(*parsed_upper, id);
  FR_CHECK_EQ(parsed_upper->bytes(), id.bytes());
}

FR_TEST_CASE(ids, opaque_parse_rejects_malformed_text) {
  const fabric_registry::SwitchId id = fabric_registry::SwitchId::from_bytes(pattern_bytes());
  const std::string text = id.to_string();

  FR_CHECK(!fabric_registry::SwitchId::parse(std::string()).has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse(text.substr(0, 31)).has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse(text + "0").has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse("0x" + text.substr(0, 30)).has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse("z" + text.substr(1)).has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse(" " + text.substr(0, 31)).has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse(text + " ").has_value());
  FR_CHECK(!fabric_registry::SwitchId::parse(std::string(32, '0') + "x").has_value());
}

FR_TEST_CASE(ids, typed_ids_are_distinct_types) {
  static_assert(std::is_same_v<fabric_registry::SwitchId, OpaqueId<fabric_registry::SwitchTag>>);
  static_assert(!std::is_same_v<fabric_registry::SwitchId, fabric_registry::PortId>);
  static_assert(!std::is_same_v<fabric_registry::PortId, fabric_registry::FabricId>);
  static_assert(!std::is_same_v<fabric_registry::SwitchId, fabric_registry::PublisherId>);
  static_assert(fabric_registry::IdTagTraits<fabric_registry::SwitchTag>::is_entity_id);
  static_assert(fabric_registry::IdTagTraits<fabric_registry::SwitchTag>::entity_class == EntityClass::Switch);
  static_assert(fabric_registry::IdTagTraits<fabric_registry::PortTag>::entity_class == EntityClass::Port);
  static_assert(fabric_registry::IdTagTraits<fabric_registry::FabricTag>::entity_class == EntityClass::Fabric);
  static_assert(canonical_of_accepts<fabric_registry::SwitchId>::value);
  static_assert(canonical_of_accepts<fabric_registry::PortId>::value);
  static_assert(!canonical_of_accepts<fabric_registry::PublisherId>::value);
  static_assert(!canonical_of_accepts<fabric_registry::WorkerBootId>::value);
  static_assert(!canonical_of_accepts<fabric_registry::RegistrationId>::value);
  static_assert(canonical_as_accepts<fabric_registry::SwitchId>::value);
  static_assert(canonical_as_accepts<fabric_registry::PortId>::value);
  static_assert(!canonical_as_accepts<fabric_registry::PublisherId>::value);
  static_assert(!canonical_as_accepts<fabric_registry::WorkerBootId>::value);
  static_assert(!canonical_as_accepts<fabric_registry::RegistrationId>::value);
  static_assert(fabric_registry::IdTagTraits<fabric_registry::SwitchTag>::domain_name == "switch");
  static_assert(fabric_registry::IdTagTraits<fabric_registry::PortTag>::domain_name == "port");
  static_assert(fabric_registry::IdTagTraits<fabric_registry::PublisherTag>::domain_name == "publisher");
  static_assert(fabric_registry::IdTagTraits<fabric_registry::WorkerBootTag>::domain_name == "worker-boot");
  static_assert(fabric_registry::IdTagTraits<fabric_registry::RegistrationTag>::domain_name == "registration");

  const fabric_registry::SwitchId switch_id = fabric_registry::SwitchId::from_bytes(pattern_bytes());
  const CanonicalId canonical = CanonicalId::of(switch_id);
  FR_CHECK_EQ(canonical.entity_class(), EntityClass::Switch);
  FR_CHECK_EQ(canonical.bytes(), switch_id.bytes());
  FR_CHECK_EQ(fabric_registry::SwitchId::domain_name, std::string_view("switch"));

  const std::optional<fabric_registry::SwitchId> recovered = canonical.as<fabric_registry::SwitchId>();
  FR_CHECK(recovered.has_value());
  FR_CHECK_EQ(*recovered, switch_id);
  FR_CHECK(!canonical.as<fabric_registry::PortId>().has_value());
  FR_CHECK(!canonical.as<fabric_registry::FabricId>().has_value());
  FR_CHECK(!canonical.as<fabric_registry::NicId>().has_value());
  FR_CHECK(!canonical.as<fabric_registry::RouterId>().has_value());
  FR_CHECK(!canonical.as<fabric_registry::VendorDeviceId>().has_value());

  // The same bytes in another domain stay a different identity.
  const fabric_registry::PortId port_id = fabric_registry::PortId::from_bytes(pattern_bytes());
  FR_CHECK_EQ(port_id.bytes(), switch_id.bytes());
  FR_CHECK(CanonicalId::of(port_id) != canonical);
  FR_CHECK_EQ(CanonicalId::of(port_id).entity_class(), EntityClass::Port);
  FR_CHECK(CanonicalId::of(port_id) < canonical || canonical < CanonicalId::of(port_id));
}

FR_TEST_CASE(ids, canonical_id_text_round_trips) {
  const fabric_registry::SwitchId switch_id = fabric_registry::SwitchId::from_bytes(pattern_bytes());
  const CanonicalId canonical = CanonicalId::of(switch_id);
  const std::string text = canonical.to_string();

  FR_CHECK_EQ(text.size(), std::string("switch").size() + 1u + std::size_t{32});
  FR_CHECK_EQ(text.rfind("switch:", 0), std::size_t{0});
  FR_CHECK_EQ(text.substr(7), switch_id.to_string());
  FR_CHECK(is_lowercase_hex(text.substr(7)));

  const std::optional<CanonicalId> parsed = CanonicalId::parse(text);
  FR_CHECK(parsed.has_value());
  FR_CHECK_EQ(*parsed, canonical);
  FR_CHECK_EQ(parsed->entity_class(), EntityClass::Switch);
  FR_CHECK_EQ(parsed->bytes(), switch_id.bytes());
  FR_CHECK(!parsed->is_null());

  const std::optional<CanonicalId> upper = CanonicalId::parse("switch:" + ascii_upper(switch_id.to_string()));
  FR_CHECK(upper.has_value());
  FR_CHECK_EQ(*upper, canonical);

  const std::optional<CanonicalId> explicit_class =
      CanonicalId::parse(EntityClass::Switch, switch_id.to_string());
  FR_CHECK(explicit_class.has_value());
  FR_CHECK_EQ(*explicit_class, canonical);

  const CanonicalId absent;
  FR_CHECK(absent.is_null());
  FR_CHECK_EQ(absent.entity_class(), EntityClass::Unknown);
  FR_CHECK_EQ(absent.to_string(), std::string("unknown:") + std::string(32, '0'));
  FR_CHECK(!CanonicalId::parse(absent.to_string()).has_value());
}

FR_TEST_CASE(ids, canonical_id_parse_rejects_malformed_text) {
  const std::string hex = fabric_registry::SwitchId::from_bytes(pattern_bytes()).to_string();
  const std::string zeros(fabric_registry::kOpaqueIdTextLength, '0');

  FR_CHECK(!CanonicalId::parse(std::string()).has_value());
  FR_CHECK(!CanonicalId::parse(hex).has_value());
  FR_CHECK(!CanonicalId::parse("gateway:" + hex).has_value());
  FR_CHECK(!CanonicalId::parse("Switch:" + hex).has_value());
  FR_CHECK(!CanonicalId::parse("switch:").has_value());
  FR_CHECK(!CanonicalId::parse("switch:" + zeros).has_value());
  FR_CHECK(!CanonicalId::parse("switch:" + hex.substr(0, 31)).has_value());
  FR_CHECK(!CanonicalId::parse("switch:" + hex + "0").has_value());
  FR_CHECK(!CanonicalId::parse("switch:z" + hex.substr(1)).has_value());
  FR_CHECK(!CanonicalId::parse(":" + hex).has_value());

  const std::optional<CanonicalId> as_port = CanonicalId::parse(EntityClass::Port, hex);
  FR_CHECK(as_port.has_value());
  FR_CHECK_EQ(as_port->entity_class(), EntityClass::Port);
  FR_CHECK_EQ(as_port->bytes(), fabric_registry::SwitchId::from_bytes(pattern_bytes()).bytes());
  FR_CHECK(!CanonicalId::parse(EntityClass::Unknown, hex).has_value());
  FR_CHECK(!CanonicalId::parse(EntityClass::Switch, zeros).has_value());
  FR_CHECK(!CanonicalId::parse(EntityClass::Switch, hex.substr(0, 31)).has_value());
  FR_CHECK(!CanonicalId::parse(EntityClass::Switch, hex + "0").has_value());
}

FR_TEST_CASE(ids, device_id_accepts_device_classes_only) {
  for (std::uint8_t raw = 1; raw <= fabric_registry::kEntityClassCount; ++raw) {
    const EntityClass entity_class = static_cast<EntityClass>(raw);
    const CanonicalId candidate(entity_class, pattern_bytes());
    const std::optional<DeviceId> device = DeviceId::from_canonical(candidate);
    FR_CHECK_EQ(device.has_value(), fabric_registry::is_device_class(entity_class));
    if (device.has_value()) {
      FR_CHECK_EQ(device->canonical(), candidate);
      FR_CHECK_EQ(device->entity_class(), entity_class);
      FR_CHECK_EQ(device->to_string(), candidate.to_string());
      const std::optional<DeviceId> parsed = DeviceId::parse(candidate.to_string());
      FR_CHECK(parsed.has_value());
      FR_CHECK_EQ(*parsed, *device);
    } else {
      FR_CHECK(!DeviceId::parse(candidate.to_string()).has_value());
    }
  }

  const CanonicalId switch_canonical(EntityClass::Switch, pattern_bytes());
  FR_CHECK(DeviceId::from_canonical(switch_canonical).has_value());
  FR_CHECK(!DeviceId::from_canonical(CanonicalId(EntityClass::Port, pattern_bytes())).has_value());
  FR_CHECK(!DeviceId::from_canonical(CanonicalId(EntityClass::Fabric, pattern_bytes())).has_value());
  FR_CHECK(!DeviceId::from_canonical(CanonicalId(EntityClass::Switch, IdBytes{})).has_value());
  FR_CHECK(!DeviceId::from_canonical(CanonicalId(EntityClass::Unknown, pattern_bytes())).has_value());
  FR_CHECK(DeviceId().is_null());
}

FR_TEST_CASE(ids, counter_first_next_and_overflow) {
  const fabric_registry::RecordGeneration first = fabric_registry::RecordGeneration::first();
  FR_CHECK_EQ(first.value(), std::uint64_t{1});
  FR_CHECK(!first.is_zero());
  FR_CHECK_EQ(first.to_string(), std::string("1"));

  const std::optional<fabric_registry::RecordGeneration> second = first.next();
  FR_CHECK(second.has_value());
  FR_CHECK_EQ(second->value(), std::uint64_t{2});
  FR_CHECK_EQ(second->value(), first.value() + 1u);
  FR_CHECK(*second > first);

  const fabric_registry::RecordGeneration zero;
  FR_CHECK(zero.is_zero());
  FR_CHECK_EQ(zero.to_string(), std::string("0"));

  const fabric_registry::RecordGeneration last(fabric_registry::RecordGeneration::max_value());
  FR_CHECK_EQ(last.value(), UINT64_MAX);
  FR_CHECK(!last.next().has_value());
  FR_CHECK(last > *second);
}

FR_TEST_CASE(ids, counter_parse_accepts_decimal_and_rejects_junk) {
  const std::optional<fabric_registry::CoordinatorEpoch> zero = fabric_registry::CoordinatorEpoch::parse("0");
  FR_CHECK(zero.has_value());
  FR_CHECK_EQ(zero->value(), std::uint64_t{0});
  FR_CHECK(zero->is_zero());
  FR_CHECK_EQ(zero->to_string(), std::string("0"));

  const std::optional<fabric_registry::CoordinatorEpoch> maximum =
      fabric_registry::CoordinatorEpoch::parse("18446744073709551615");
  FR_CHECK(maximum.has_value());
  FR_CHECK_EQ(maximum->value(), UINT64_MAX);
  FR_CHECK_EQ(maximum->to_string(), std::string("18446744073709551615"));

  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse(std::string()).has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("x").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("12a").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("-1").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("+1").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse(" 1").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("1 ").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("0x10").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("1234567890123456789012345").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("18446744073709551616").has_value());
  FR_CHECK(!fabric_registry::CoordinatorEpoch::parse("99999999999999999999").has_value());
}

FR_TEST_CASE(ids, counter_text_round_trips) {
  const std::uint64_t values[] = {std::uint64_t{0},
                                  std::uint64_t{1},
                                  std::uint64_t{9},
                                  std::uint64_t{10},
                                  std::uint64_t{99},
                                  std::uint64_t{100},
                                  std::uint64_t{12345678901234567890ull},
                                  UINT64_MAX};
  for (std::uint64_t value : values) {
    const fabric_registry::SnapshotSequence original(value);
    const std::string text = original.to_string();
    FR_CHECK(!text.empty());
    FR_CHECK_EQ(text.find_first_not_of("0123456789"), std::string::npos);
    const std::optional<fabric_registry::SnapshotSequence> parsed =
        fabric_registry::SnapshotSequence::parse(text);
    FR_CHECK(parsed.has_value());
    FR_CHECK_EQ(*parsed, original);
    FR_CHECK_EQ(parsed->value(), value);
  }
}

FR_TEST_CASE(ids, vendor_and_product_ids) {
  const std::optional<VendorId> prefixed = VendorId::parse("0x15b3");
  const std::optional<VendorId> upper = VendorId::parse("15B3");
  const std::optional<VendorId> lower = VendorId::parse("15b3");
  FR_CHECK(prefixed.has_value());
  FR_CHECK(upper.has_value());
  FR_CHECK(lower.has_value());
  FR_CHECK_EQ(*prefixed, *upper);
  FR_CHECK_EQ(*prefixed, *lower);
  FR_CHECK_EQ(prefixed->value(), std::uint16_t{0x15b3});
  FR_CHECK_EQ(prefixed->to_string(), std::string("0x15b3"));
  FR_CHECK_EQ(upper->to_string(), std::string("0x15b3"));
  FR_CHECK_EQ(lower->to_string(), std::string("0x15b3"));
  FR_CHECK(!prefixed->is_null());
  FR_CHECK(VendorId().is_null());

  FR_CHECK(!VendorId::parse(std::string()).has_value());
  FR_CHECK(!VendorId::parse("0x0").has_value());
  FR_CHECK(!VendorId::parse("0000").has_value());
  FR_CHECK(!VendorId::parse("0x0000").has_value());
  FR_CHECK(!VendorId::parse("0").has_value());
  FR_CHECK(!VendorId::parse("zzzz").has_value());
  FR_CHECK(!VendorId::parse("12345").has_value());
  FR_CHECK(!VendorId::parse("0x").has_value());
  FR_CHECK(!VendorId::parse("0x15b3 ").has_value());
  FR_CHECK(!VendorId::parse("-15b3").has_value());

  const std::optional<fabric_registry::ProductId> product = fabric_registry::ProductId::parse("0X1017");
  FR_CHECK(product.has_value());
  FR_CHECK_EQ(product->value(), std::uint16_t{0x1017});
  FR_CHECK_EQ(product->to_string(), std::string("0x1017"));
  const std::optional<fabric_registry::ProductId> plain = fabric_registry::ProductId::parse("1017");
  FR_CHECK(plain.has_value());
  FR_CHECK_EQ(*plain, *product);
  FR_CHECK(!fabric_registry::ProductId::parse("0x0").has_value());
  FR_CHECK(!fabric_registry::ProductId::parse("12345").has_value());
}

FR_TEST_CASE(ids, serial_identity_normalisation) {
  const std::optional<SerialIdentity> serial = SerialIdentity::parse("  SN-0001 \t", "vendor:0x15b3");
  FR_CHECK(serial.has_value());
  FR_CHECK_EQ(serial->value(), std::string("SN-0001"));
  FR_CHECK_EQ(serial->scope(), std::string("vendor:0x15b3"));
  FR_CHECK(!serial->is_null());
  FR_CHECK_EQ(serial->to_string(), std::string("serial[vendor:0x15b3]:SN-0001"));

  const std::optional<SerialIdentity> again = SerialIdentity::parse(serial->value(), serial->scope());
  FR_CHECK(again.has_value());
  FR_CHECK_EQ(*again, *serial);
  FR_CHECK_EQ(again->to_string(), serial->to_string());

  FR_CHECK(!SerialIdentity::parse("   ", "scope").has_value());
  FR_CHECK(!SerialIdentity::parse("", "scope").has_value());
  FR_CHECK(!SerialIdentity::parse("SN", "").has_value());
  FR_CHECK(!SerialIdentity::parse("SN", "   ").has_value());
  FR_CHECK(!SerialIdentity::parse(std::string("SN\0X", 4), "scope").has_value());
  FR_CHECK(!SerialIdentity::parse(std::string("SN\x01X", 4), "scope").has_value());
  FR_CHECK(!SerialIdentity::parse(std::string("SN\tX", 4), "scope").has_value());
  FR_CHECK(!SerialIdentity::parse(std::string("SN\x7fX", 4), "scope").has_value());
  FR_CHECK(!SerialIdentity::parse(std::string(257, 'A'), "scope").has_value());
  FR_CHECK(!SerialIdentity::parse("SN", std::string(257, 's')).has_value());

  const std::string max_value(SerialIdentity::max_value_bytes, 'A');
  const std::string max_scope(SerialIdentity::max_scope_bytes, 's');
  const std::optional<SerialIdentity> limit = SerialIdentity::parse(max_value, max_scope);
  FR_CHECK(limit.has_value());
  FR_CHECK_EQ(limit->value(), max_value);
  FR_CHECK_EQ(limit->scope(), max_scope);

  const SerialIdentity absent;
  FR_CHECK(absent.is_null());
  FR_CHECK_EQ(absent.to_string(), std::string("serial:<null>"));
}

FR_TEST_CASE(ids, digest_value_parse_and_render) {
  const std::string text =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const std::optional<fabric_registry::StateDigest> parsed = fabric_registry::StateDigest::parse(text);
  FR_CHECK(parsed.has_value());
  FR_CHECK_EQ(parsed->to_string(), text);
  FR_CHECK(!parsed->is_null());

  const std::optional<fabric_registry::StateDigest> upper =
      fabric_registry::StateDigest::parse(ascii_upper(text));
  FR_CHECK(upper.has_value());
  FR_CHECK_EQ(*upper, *parsed);

  const std::string short_text(63, 'a');
  const std::string long_text(65, 'a');
  FR_CHECK(!fabric_registry::StateDigest::parse(short_text).has_value());
  FR_CHECK(!fabric_registry::StateDigest::parse(long_text).has_value());

  std::string non_hex = text;
  non_hex[63] = 'z';
  FR_CHECK(!fabric_registry::StateDigest::parse(non_hex).has_value());
  FR_CHECK(!fabric_registry::StateDigest::parse(std::string()).has_value());

  const std::optional<fabric_registry::StateDigest> all_zero =
      fabric_registry::StateDigest::parse(std::string(fabric_registry::kDigestBytes * 2, '0'));
  FR_CHECK(all_zero.has_value());
  FR_CHECK(all_zero->is_null());
  FR_CHECK_EQ(fabric_registry::StateDigest().to_string(), std::string(64, '0'));

  const fabric_registry::RequestDigest other = fabric_registry::RequestDigest::from_bytes(parsed->bytes());
  FR_CHECK_EQ(other.to_string(), text);
  FR_CHECK(!(other == fabric_registry::RequestDigest()));
}

FR_TEST_CASE(ids, hashes_support_unordered_maps) {
  constexpr std::uint32_t kCount = 64;

  std::unordered_map<fabric_registry::SwitchId, std::uint32_t> switches;
  std::unordered_map<fabric_registry::PortId, std::uint32_t> ports;
  std::unordered_map<fabric_registry::PublisherId, std::uint32_t> publishers;
  std::unordered_map<CanonicalId, std::uint32_t> canonical;
  std::unordered_map<fabric_registry::RecordGeneration, std::uint32_t> generations;
  std::unordered_map<fabric_registry::StateDigest, std::uint32_t> digests;

  for (std::uint32_t index = 0; index < kCount; ++index) {
    IdBytes raw{};
    raw[0] = static_cast<std::uint8_t>(index + 1u);
    raw[15] = static_cast<std::uint8_t>(index);
    fabric_registry::DigestBytes digest{};
    digest[0] = static_cast<std::uint8_t>(index + 1u);
    digest[31] = static_cast<std::uint8_t>(index * 3u);

    switches.emplace(fabric_registry::SwitchId::from_bytes(raw), index);
    ports.emplace(fabric_registry::PortId::from_bytes(raw), index);
    publishers.emplace(fabric_registry::PublisherId::from_bytes(raw), index);
    canonical.emplace(CanonicalId(EntityClass::Switch, raw), index);
    generations.emplace(fabric_registry::RecordGeneration(index + 1u), index);
    digests.emplace(fabric_registry::StateDigest::from_bytes(digest), index);
  }

  FR_CHECK_EQ(switches.size(), static_cast<std::size_t>(kCount));
  FR_CHECK_EQ(ports.size(), static_cast<std::size_t>(kCount));
  FR_CHECK_EQ(publishers.size(), static_cast<std::size_t>(kCount));
  FR_CHECK_EQ(canonical.size(), static_cast<std::size_t>(kCount));
  FR_CHECK_EQ(generations.size(), static_cast<std::size_t>(kCount));
  FR_CHECK_EQ(digests.size(), static_cast<std::size_t>(kCount));

  for (std::uint32_t index = 0; index < kCount; ++index) {
    IdBytes raw{};
    raw[0] = static_cast<std::uint8_t>(index + 1u);
    raw[15] = static_cast<std::uint8_t>(index);
    fabric_registry::DigestBytes digest{};
    digest[0] = static_cast<std::uint8_t>(index + 1u);
    digest[31] = static_cast<std::uint8_t>(index * 3u);

    const fabric_registry::SwitchId switch_key = fabric_registry::SwitchId::from_bytes(raw);
    const std::unordered_map<fabric_registry::SwitchId, std::uint32_t>::const_iterator switch_entry =
        switches.find(switch_key);
    FR_CHECK(switch_entry != switches.end());
    FR_CHECK_EQ(switch_entry->second, index);
    FR_CHECK_EQ(std::hash<fabric_registry::SwitchId>{}(switch_key),
                std::hash<fabric_registry::SwitchId>{}(fabric_registry::SwitchId::from_bytes(raw)));

    FR_CHECK_EQ(ports.count(fabric_registry::PortId::from_bytes(raw)), std::size_t{1});
    FR_CHECK_EQ(publishers.count(fabric_registry::PublisherId::from_bytes(raw)), std::size_t{1});
    FR_CHECK_EQ(canonical.count(CanonicalId(EntityClass::Switch, raw)), std::size_t{1});
    FR_CHECK_EQ(generations.count(fabric_registry::RecordGeneration(index + 1u)), std::size_t{1});
    FR_CHECK_EQ(digests.count(fabric_registry::StateDigest::from_bytes(digest)), std::size_t{1});

    const std::unordered_map<fabric_registry::StateDigest, std::uint32_t>::const_iterator digest_entry =
        digests.find(fabric_registry::StateDigest::from_bytes(digest));
    FR_CHECK(digest_entry != digests.end());
    FR_CHECK_EQ(digest_entry->second, index);
  }

  FR_CHECK(!switches.count(fabric_registry::SwitchId()));
  FR_CHECK(!generations.count(fabric_registry::RecordGeneration()));
}

int main(int argc, char** argv) { return frtest::run_all(argc, argv); }
