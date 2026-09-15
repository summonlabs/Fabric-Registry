// Fabric Registry — canonical binary encoding of a record.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// This is the single encoder/decoder pair used by both durable state files and
// the wire protocol, so a record can never mean two different things depending
// on where it was read. The encoding is versioned by the enclosing container;
// this module rejects anything that is not exactly one well-formed record.

#ifndef FABRIC_REGISTRY_RECORD_CODEC_HPP
#define FABRIC_REGISTRY_RECORD_CODEC_HPP

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "fabric_registry/codec.hpp"
#include "fabric_registry/entity.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/limits.hpp"

namespace fabric_registry {

/// Appends the canonical encoding of `record` to `writer`.
/// Throws nothing; the caller bounds the total size.
FABRIC_REGISTRY_API void write_record(ByteWriter& writer, const EntityRecord& record);

/// Decodes exactly one record from `reader`. Returns false and fills `error`
/// with a specific stage description when the encoding is invalid, out of
/// bounds, or semantically inconsistent.
FABRIC_REGISTRY_API bool read_record(ByteReader& reader, const RegistryLimits& limits, EntityRecord& out, std::string& error);

FABRIC_REGISTRY_API std::vector<std::uint8_t> encode_record(const EntityRecord& record);
FABRIC_REGISTRY_API bool decode_record(std::span<const std::uint8_t> bytes,
                                       const RegistryLimits& limits,
                                       EntityRecord& out,
                                       std::string& error);

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_RECORD_CODEC_HPP
