// Fabric Registry — deterministic rendering of a discovery report.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// DiscoveryReport::render() is platform independent: it renders exactly the
// report it is handed and never consults the host. It lives in its own
// translation unit so that the library defines the symbol exactly once,
// whichever platform discovery adapter (discovery_windows.cpp on Windows,
// discovery_stub.cpp everywhere else) was compiled.

#include "fabric_registry/discovery.hpp"

#include <string>
#include <string_view>

namespace fabric_registry {
namespace {

void append_key_value(std::string& out, std::string_view key, std::string_view value) {
  out.append(key);
  out.append(": ");
  out.append(value);
  out.push_back('\n');
}

std::string_view or_dash(std::string_view value) {
  return value.empty() ? std::string_view("-") : value;
}

template <class Id>
std::string id_text(const std::optional<Id>& value) {
  return value.has_value() ? value->to_string() : std::string("-");
}

std::string scope_text(const ScopeRef& scope) {
  std::string out = "fabric=";
  out += id_text(scope.fabric);
  out += " site=";
  out += id_text(scope.site);
  out += " control-domain=";
  out += id_text(scope.control_domain);
  out += " parent-device=";
  out += id_text(scope.parent_device);
  return out;
}

std::string provenance_text(const Provenance& provenance) {
  std::string out = "source=";
  out += to_string(provenance.source);
  out += " class=";
  out += to_string(provenance.validity_class);
  out += " mechanism=";
  out += or_dash(provenance.mechanism);
  out += " source-identity=";
  out += or_dash(provenance.source_identity);
  return out;
}

/// A fact is rendered with every component it was canonicalised with, so two
/// renders of the same fact set are byte identical.
std::string fact_text(const IdentityFact& fact) {
  std::string out = "kind=";
  out += to_string(fact.kind);
  out += " scope=";
  out += or_dash(fact.scope);
  out += " value=";
  out += fact.value;
  out += " strength=";
  out += to_string(fact_strength(fact.kind));
  return out;
}

} // namespace

std::string DiscoveryReport::render() const {
  std::string out;
  append_key_value(out, "platform", or_dash(platform));
  append_key_value(out, "source", to_string(source));
  append_key_value(out, "validity-class", to_string(validity_class));
  append_key_value(out, "observation-count", std::to_string(observations.size()));
  append_key_value(out, "truncated", truncated ? "true" : "false");

  out += "capabilities:\n";
  for (const CapabilityReport& capability : capabilities) {
    out += "  - capability=";
    out += to_string(capability.capability);
    out += " status=";
    out += to_string(capability.status);
    out += " detail=";
    out += or_dash(capability.detail);
    out.push_back('\n');
  }

  out += "diagnostics:\n";
  for (const std::string& diagnostic : diagnostics) {
    out += "  - ";
    out += diagnostic;
    out.push_back('\n');
  }

  out += "observations:\n";
  for (const DiscoveryObservation& observation : observations) {
    out += "  - class=";
    out += to_string(observation.entity_class);
    out += " friendly-name=";
    out += or_dash(observation.friendly_name);
    out += " platform-detail=";
    out += or_dash(observation.platform_detail);
    out.push_back('\n');
    out += "    scope: ";
    out += scope_text(observation.scope);
    out.push_back('\n');
    out += "    provenance: ";
    out += provenance_text(observation.provenance);
    out.push_back('\n');
    out += "    facts:\n";
    for (const IdentityFact& fact : observation.facts) {
      out += "      - ";
      out += fact_text(fact);
      out.push_back('\n');
    }
    out += "    aliases:\n";
    for (const AliasInput& alias : observation.aliases) {
      out += "      - namespace=";
      out += to_string(alias.alias_namespace);
      out += " value=";
      out += alias.value;
      out.push_back('\n');
    }
    out += "    metadata:\n";
    for (const MetadataEntry& entry : observation.metadata) {
      out += "      - key=";
      out += entry.key;
      out += " value=";
      out += entry.value;
      out.push_back('\n');
    }
  }
  return out;
}

} // namespace fabric_registry
