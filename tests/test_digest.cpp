// Fabric Registry — SHA-256 and canonical digest proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The library implementation is checked against a second SHA-256 written from
// scratch inside this file. That reference shares no code with
// fabric_registry::Sha256 and is never allowed to call it: the two
// implementations agree only if both compute the algorithm FIPS 180-4 defines.
// On top of that the padding boundaries (55, 56, 63, 64, 119, 120, ...), every
// streaming shape and the CanonicalHasher framing are pinned.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/digest.hpp"
#include "support/test_harness.hpp"

namespace {

using fabric_registry::CanonicalHasher;
using fabric_registry::DigestBytes;
using fabric_registry::Sha256;

// ---------------------------------------------------------------------------
// An independent SHA-256 (FIPS 180-4).
// ---------------------------------------------------------------------------

constexpr std::uint32_t kReferenceRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t rotate_right(std::uint32_t value, std::uint32_t amount) noexcept {
  return (value >> amount) | (value << (32u - amount));
}

class ReferenceSha256 {
 public:
  void update(const std::uint8_t* data, std::size_t size) noexcept {
    total_bits_ += static_cast<std::uint64_t>(size) * 8u;
    for (std::size_t index = 0; index < size; ++index) {
      buffer_[buffered_] = data[index];
      ++buffered_;
      if (buffered_ == buffer_.size()) {
        compress();
        buffered_ = 0;
      }
    }
  }

  void update(std::string_view text) noexcept {
    update(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
  }

  DigestBytes finish() noexcept {
    // The bit count is captured before padding, and the padding is written
    // through the same byte buffer so the tail of the message is never
    // special-cased.
    const std::uint64_t message_bits = total_bits_;
    const std::uint8_t terminator = 0x80u;
    update(&terminator, 1u);
    const std::uint8_t zero = 0x00u;
    while (buffered_ != 56u) {
      update(&zero, 1u);
    }
    std::uint8_t length[8] = {};
    for (std::size_t index = 0; index < 8; ++index) {
      length[index] = static_cast<std::uint8_t>(message_bits >> ((7u - index) * 8u));
    }
    update(length, sizeof(length));

    DigestBytes digest{};
    for (std::size_t index = 0; index < 8; ++index) {
      digest[index * 4u] = static_cast<std::uint8_t>(state_[index] >> 24u);
      digest[index * 4u + 1u] = static_cast<std::uint8_t>(state_[index] >> 16u);
      digest[index * 4u + 2u] = static_cast<std::uint8_t>(state_[index] >> 8u);
      digest[index * 4u + 3u] = static_cast<std::uint8_t>(state_[index]);
    }
    return digest;
  }

 private:
  void compress() noexcept {
    std::uint32_t schedule[64] = {};
    for (std::size_t index = 0; index < 16; ++index) {
      schedule[index] = (static_cast<std::uint32_t>(buffer_[index * 4u]) << 24u) |
                        (static_cast<std::uint32_t>(buffer_[index * 4u + 1u]) << 16u) |
                        (static_cast<std::uint32_t>(buffer_[index * 4u + 2u]) << 8u) |
                        static_cast<std::uint32_t>(buffer_[index * 4u + 3u]);
    }
    for (std::size_t index = 16; index < 64; ++index) {
      const std::uint32_t first = schedule[index - 15u];
      const std::uint32_t second = schedule[index - 2u];
      const std::uint32_t small0 = rotate_right(first, 7u) ^ rotate_right(first, 18u) ^ (first >> 3u);
      const std::uint32_t small1 = rotate_right(second, 17u) ^ rotate_right(second, 19u) ^ (second >> 10u);
      schedule[index] = schedule[index - 16u] + small0 + schedule[index - 7u] + small1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (std::size_t index = 0; index < 64; ++index) {
      const std::uint32_t big1 = rotate_right(e, 6u) ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
      const std::uint32_t choose = (e & f) ^ (~e & g);
      const std::uint32_t temp1 = h + big1 + choose + kReferenceRoundConstants[index] + schedule[index];
      const std::uint32_t big0 = rotate_right(a, 2u) ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = big0 + majority;
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

  std::uint32_t state_[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  std::uint64_t total_bits_{0};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_{0};
};

// ---------------------------------------------------------------------------
// Test-local rendering and probe builders
// ---------------------------------------------------------------------------

std::string hex_of(const DigestBytes& digest) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(digest.size() * 2u);
  for (std::uint8_t byte : digest) {
    out.push_back(kHexDigits[(byte >> 4u) & 0x0Fu]);
    out.push_back(kHexDigits[byte & 0x0Fu]);
  }
  return out;
}

DigestBytes reference_digest(std::string_view text) {
  ReferenceSha256 hasher;
  hasher.update(text);
  return hasher.finish();
}

std::string reference_hex(std::string_view text) { return hex_of(reference_digest(text)); }

std::string library_hex(std::string_view text) { return hex_of(Sha256::hash(text)); }

/// One fixed field sequence with exactly one member changed at a time.
struct CanonicalFields {
  std::uint8_t small{0x11u};
  std::uint16_t medium{0x2233u};
  std::uint32_t wide{0x44556677u};
  std::uint64_t widest{0x8899aabbccddeeffull};
  std::array<std::uint8_t, 3> raw{0x01u, 0x02u, 0x03u};
  std::string_view text{"text"};
  std::uint64_t sequence_count{1u};
};

DigestBytes canonical_digest(const CanonicalFields& fields) {
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/test/canonical-hasher/1");
  hasher.u8(fields.small);
  hasher.u16(fields.medium);
  hasher.u32(fields.wide);
  hasher.u64(fields.widest);
  hasher.bytes(fields.raw);
  hasher.text(fields.text);
  hasher.sequence(fields.sequence_count);
  hasher.u8(0xFEu);
  return hasher.finish();
}

DigestBytes digest_of_text_pair(std::string_view first, std::string_view second) {
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/test/length-prefix/1");
  hasher.text(first);
  hasher.text(second);
  return hasher.finish();
}

DigestBytes digest_of_text(std::string_view value) {
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/test/length-prefix/1");
  hasher.text(value);
  return hasher.finish();
}

DigestBytes digest_of_byte_pair(std::span<const std::uint8_t> first, std::span<const std::uint8_t> second) {
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/test/length-prefix/1");
  hasher.bytes(first);
  hasher.bytes(second);
  return hasher.finish();
}

DigestBytes digest_of_u8_pair(std::uint8_t first, std::uint8_t second) {
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/test/length-prefix/1");
  hasher.u8(first);
  hasher.u8(second);
  return hasher.finish();
}

} // namespace

FR_TEST_CASE(digest, sha256_matches_the_nist_vectors) {
  struct Vector {
    std::string_view message;
    std::string_view expected;
  };
  // The message is held in a named string: the vector table only borrows it.
  const std::string sixty_four_a(64, 'a');
  const Vector vectors[] = {
      {std::string_view(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {sixty_four_a, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
  };

  for (const Vector& vector : vectors) {
    const std::string expected(vector.expected);
    FR_CHECK_EQ(hex_of(Sha256::hash(vector.message)), expected);
    FR_CHECK_EQ(reference_hex(vector.message), expected);
    FR_CHECK_EQ(library_hex(vector.message), reference_hex(vector.message));
    FR_CHECK_EQ(fabric_registry::to_hex(Sha256::hash(vector.message)), hex_of(Sha256::hash(vector.message)));
  }

  // The pointer/length overload computes the same digest as the text overload.
  const std::string abc = "abc";
  FR_CHECK_EQ(hex_of(Sha256::hash(abc.data(), abc.size())), library_hex(abc));
  FR_CHECK_EQ(hex_of(Sha256::hash(nullptr, 0)), library_hex(std::string_view()));
}

FR_TEST_CASE(digest, sha256_one_million_a) {
  const std::string million(1'000'000u, 'a');
  const std::string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

  FR_CHECK_EQ(library_hex(million), expected);
  FR_CHECK_EQ(reference_hex(million), expected);

  Sha256 chunked;
  for (std::size_t offset = 0; offset < million.size(); offset += 1000u) {
    chunked.update(std::string_view(million).substr(offset, 1000u));
  }
  FR_CHECK_EQ(hex_of(chunked.finish()), expected);
}

FR_TEST_CASE(digest, sha256_covers_the_padding_boundaries) {
  const std::size_t lengths[] = {0u, 1u, 55u, 56u, 57u, 63u, 64u, 65u, 119u, 120u, 127u, 128u, 1000u};
  for (std::size_t length : lengths) {
    const std::string message(length, 'a');
    const DigestBytes one_shot = Sha256::hash(message);
    FR_CHECK_EQ(hex_of(one_shot), hex_of(reference_digest(message)));

    Sha256 chunked;
    for (std::size_t offset = 0; offset < message.size(); offset += 7u) {
      chunked.update(std::string_view(message).substr(offset, 7u));
    }
    FR_CHECK_EQ(hex_of(chunked.finish()), hex_of(one_shot));
  }
}

FR_TEST_CASE(digest, sha256_streaming_shapes_agree) {
  frtest::Rng rng(0x5A17u);
  for (std::size_t iteration = 0; iteration < 32; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.in_range(0, 300));
    const std::string message = frtest::random_text(rng, length);
    const DigestBytes expected = Sha256::hash(message);

    Sha256 single_byte;
    for (char value : message) {
      single_byte.update(&value, 1u);
    }
    FR_CHECK_EQ(hex_of(single_byte.finish()), hex_of(expected));

    Sha256 seven_byte;
    for (std::size_t offset = 0; offset < message.size(); offset += 7u) {
      seven_byte.update(std::string_view(message).substr(offset, 7u));
    }
    FR_CHECK_EQ(hex_of(seven_byte.finish()), hex_of(expected));

    const std::vector<std::uint8_t> raw(message.begin(), message.end());
    Sha256 span_hasher;
    span_hasher.update(std::span<const std::uint8_t>(raw));
    FR_CHECK_EQ(hex_of(span_hasher.finish()), hex_of(expected));

    Sha256 view_hasher;
    view_hasher.update(std::string_view(message));
    FR_CHECK_EQ(hex_of(view_hasher.finish()), hex_of(expected));

    Sha256 pointer_hasher;
    pointer_hasher.update(message.data(), message.size());
    FR_CHECK_EQ(hex_of(pointer_hasher.finish()), hex_of(expected));

    FR_CHECK_EQ(hex_of(expected), reference_hex(message));
  }
}

FR_TEST_CASE(digest, sha256_reset_restores_a_clean_state) {
  const std::string empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const std::string abc = "abc";
  const DigestBytes expected_abc = Sha256::hash(abc);

  Sha256 hasher;
  hasher.update("some earlier message that must not survive a reset");
  FR_CHECK_EQ(hex_of(hasher.finish()), library_hex("some earlier message that must not survive a reset"));

  hasher.reset();
  hasher.update(abc);
  FR_CHECK_EQ(hex_of(hasher.finish()), hex_of(expected_abc));

  hasher.reset();
  FR_CHECK_EQ(hex_of(hasher.finish()), empty_digest);

  Sha256 fresh;
  fresh.update(abc);
  hasher.reset();
  hasher.update(abc);
  FR_CHECK_EQ(hex_of(hasher.finish()), hex_of(fresh.finish()));

  hasher.reset();
  for (int index = 0; index < 100; ++index) {
    hasher.update(&index, sizeof(index));
  }
  hasher.finish();
  hasher.reset();
  FR_CHECK_EQ(hex_of(hasher.finish()), empty_digest);
}

FR_TEST_CASE(digest, canonical_hasher_is_domain_separated) {
  const CanonicalFields fields;
  const std::string baseline = hex_of(canonical_digest(fields));
  FR_CHECK_EQ(hex_of(canonical_digest(fields)), baseline);

  CanonicalHasher other_domain;
  other_domain.begin("fabric-registry/test/canonical-hasher/2");
  other_domain.u8(fields.small);
  other_domain.u16(fields.medium);
  other_domain.u32(fields.wide);
  other_domain.u64(fields.widest);
  other_domain.bytes(fields.raw);
  other_domain.text(fields.text);
  other_domain.sequence(fields.sequence_count);
  other_domain.u8(0xFEu);
  FR_CHECK(hex_of(other_domain.finish()) != baseline);

  CanonicalHasher short_domain;
  short_domain.begin("fabric-registry/test/canonical-hasher/");
  short_domain.u8(fields.small);
  FR_CHECK(hex_of(short_domain.finish()) != hex_of(canonical_digest(fields)));
}

FR_TEST_CASE(digest, canonical_hasher_observes_every_field_change) {
  const CanonicalFields baseline_fields;
  const std::string baseline = hex_of(canonical_digest(baseline_fields));

  CanonicalFields changed = baseline_fields;
  changed.small = 0x12u;
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.medium = 0x2234u;
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.wide = 0x44556678u;
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.widest = 0x8899aabbccddee00ull;
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.raw = {0x01u, 0x02u, 0x04u};
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.text = "tesu";
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.sequence_count = 2u;
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.text = std::string_view();
  FR_CHECK(hex_of(canonical_digest(changed)) != baseline);

  changed = baseline_fields;
  changed.raw = {0x01u, 0x02u, 0x03u};
  changed.small = baseline_fields.small;
  FR_CHECK_EQ(hex_of(canonical_digest(changed)), baseline);
}

FR_TEST_CASE(digest, canonical_hasher_length_prefixes_text_and_bytes) {
  const std::string ab_c = hex_of(digest_of_text_pair("ab", "c"));
  const std::string a_bc = hex_of(digest_of_text_pair("a", "bc"));
  const std::string abc = hex_of(digest_of_text("abc"));
  const std::string empty_abc = hex_of(digest_of_text_pair("", "abc"));
  const std::string abc_empty = hex_of(digest_of_text_pair("abc", ""));
  const std::string two_empty = hex_of(digest_of_text_pair("", ""));

  FR_CHECK(ab_c != a_bc);
  FR_CHECK(ab_c != abc);
  FR_CHECK(a_bc != abc);
  FR_CHECK(empty_abc != abc_empty);
  FR_CHECK(two_empty != hex_of(digest_of_text(std::string_view())));

  const std::array<std::uint8_t, 2> first{0x01u, 0x02u};
  const std::array<std::uint8_t, 1> second{0x03u};
  const std::array<std::uint8_t, 1> third{0x02u};
  const std::array<std::uint8_t, 2> fourth{0x03u, 0x00u};
  FR_CHECK(hex_of(digest_of_byte_pair(first, second)) != hex_of(digest_of_byte_pair(third, fourth)));
  FR_CHECK(hex_of(digest_of_u8_pair(0x01u, 0x02u)) != hex_of(digest_of_u8_pair(0x02u, 0x01u)));
  FR_CHECK(hex_of(digest_of_u8_pair(0x01u, 0x02u)) != hex_of(digest_of_byte_pair(first, std::span<const std::uint8_t>())));
}

int main(int argc, char** argv) { return frtest::run_all(argc, argv); }
