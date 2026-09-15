// Fabric Registry — deterministic rendering.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every rendering in this module is a pure function of its input. Two runs, two
// processes and two machines produce byte-identical output for byte-identical
// state. The canonical text form is line oriented and script friendly; the JSON
// form is emitted with sorted keys for the same reason.

#ifndef FABRIC_REGISTRY_SERIALIZATION_HPP
#define FABRIC_REGISTRY_SERIALIZATION_HPP

#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/authority.hpp"
#include "fabric_registry/entity.hpp"
#include "fabric_registry/errors.hpp"
#include "fabric_registry/export.hpp"
#include "fabric_registry/identity.hpp"
#include "fabric_registry/ids.hpp"

namespace fabric_registry {

/// Escapes a string for inclusion in a JSON document. Invalid UTF-8 input is
/// escaped byte-wise so the output is always valid JSON.
FABRIC_REGISTRY_API std::string json_escape(std::string_view text);

FABRIC_REGISTRY_API std::string render_provenance(const Provenance& provenance);
FABRIC_REGISTRY_API std::string render_fact(const IdentityFact& fact);
FABRIC_REGISTRY_API std::string render_facts(const std::vector<IdentityFact>& facts);
FABRIC_REGISTRY_API std::string render_metadata(const std::vector<MetadataEntry>& metadata);

/// Canonical multi-line rendering of one record.
FABRIC_REGISTRY_API std::string render_record(const EntityRecord& record);
/// Canonical JSON object rendering of one record, keys sorted.
FABRIC_REGISTRY_API std::string render_record_json(const EntityRecord& record);

FABRIC_REGISTRY_API std::string render_publisher(const PublisherRecord& publisher);
FABRIC_REGISTRY_API std::string render_publisher_json(const PublisherRecord& publisher);

FABRIC_REGISTRY_API std::string render_history(const RecordHistory& history);
FABRIC_REGISTRY_API std::string render_history_json(const RecordHistory& history);

FABRIC_REGISTRY_API std::string render_outcome_json(const Outcome& outcome);

FABRIC_REGISTRY_API std::string render_alias_keys(const std::vector<AliasKey>& aliases);
FABRIC_REGISTRY_API std::string render_lineage_entry(const LineageEntry& entry);

} // namespace fabric_registry

#endif // FABRIC_REGISTRY_SERIALIZATION_HPP
