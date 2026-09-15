// Fabric Registry — deterministic rendering.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/serialization.hpp"

#include <algorithm>
#include <array>
#include <charconv>

namespace fabric_registry {
namespace {

std::string bool_text(bool value) { return value ? "true" : "false"; }

std::string u64_text(std::uint64_t value) { return std::to_string(value); }

void append_key_value(std::string& out, std::string_view key, std::string_view value) {
  out.append(key);
  out.append(": ");
  out.append(value);
  out.push_back('\n');
}

/// Minimal accumulating JSON object writer. Keys are collected and emitted in
/// lexicographic order so the output is independent of insertion order.
class JsonObject {
public:
  void add(std::string key, std::string value) { entries_.emplace_back(std::move(key), std::move(value)); }

  void add_string(std::string key, std::string_view value) {
    add(std::move(key), std::string("\"") + json_escape(value) + "\"");
  }

  void add_raw(std::string key, std::string value) { add(std::move(key), std::move(value)); }

  std::string finish() const {
    std::vector<std::pair<std::string, std::string>> sorted = entries_;
    std::stable_sort(sorted.begin(), sorted.end(),
                     [](const std::pair<std::string, std::string>& left,
                        const std::pair<std::string, std::string>& right) { return left.first < right.first; });
    std::string out = "{";
    for (std::size_t i = 0; i < sorted.size(); ++i) {
      if (i != 0) {
        out.push_back(',');
      }
      out.push_back('\n');
      out.append("  \"");
      out.append(json_escape(sorted[i].first));
      out.append("\": ");
      out.append(sorted[i].second);
    }
    if (!sorted.empty()) {
      out.push_back('\n');
    }
    out.push_back('}');
    return out;
  }

private:
  std::vector<std::pair<std::string, std::string>> entries_;
};

std::string json_string_array(const std::vector<std::string>& values) {
  std::string out = "[";
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      out.push_back(',');
    }
    out.push_back('"');
    out.append(json_escape(values[i]));
    out.push_back('"');
  }
  out.push_back(']');
  return out;
}

std::string json_object_array(const std::vector<std::string>& rendered) {
  std::string out = "[";
  for (std::size_t i = 0; i < rendered.size(); ++i) {
    if (i != 0) {
      out.push_back(',');
    }
    out.push_back('\n');
    out.append("  ");
    out.append(rendered[i]);
  }
  if (!rendered.empty()) {
    out.push_back('\n');
  }
  out.push_back(']');
  return out;
}

std::string render_fact_json_body(const IdentityFact& fact) {
  JsonObject object;
  object.add_string("kind", to_string(fact.kind));
  object.add_string("scope", fact.scope);
  object.add_string("strength", to_string(fact_strength(fact.kind)));
  object.add_string("value", fact.value);
  return object.finish();
}

std::string render_alias_json_body(const AliasKey& key) {
  JsonObject object;
  object.add_string("namespace", to_string(key.alias_namespace));
  object.add_string("scope", key.scope);
  object.add_string("value", key.value);
  return object.finish();
}

std::string render_metadata_json_body(const MetadataEntry& entry) {
  JsonObject object;
  object.add_string("key", entry.key);
  object.add_string("value", entry.value);
  return object.finish();
}

std::string render_provenance_json_body(const Provenance& provenance) {
  JsonObject object;
  object.add_string("class", to_string(provenance.validity_class));
  object.add_string("mechanism", provenance.mechanism);
  object.add_string("source", to_string(provenance.source));
  object.add_string("source_identity", provenance.source_identity);
  return object.finish();
}

std::string render_evidence_json_body(const EvidenceState& evidence) {
  JsonObject object;
  object.add_raw("accepted_at", u64_text(evidence.accepted_at.value()));
  object.add_string("class", to_string(evidence.evidence_class));
  object.add_raw("epoch", u64_text(evidence.epoch.value()));
  object.add_raw("generation", u64_text(evidence.generation.value()));
  object.add_raw("provenance", render_provenance_json_body(evidence.provenance));
  object.add_string("publisher", evidence.publisher.to_string());
  object.add_string("publisher_boot", evidence.publisher_boot.to_string());
  object.add_raw("valid", bool_text(evidence.valid));
  return object.finish();
}

std::string render_lineage_json_body(const LineageEntry& entry) {
  JsonObject object;
  object.add_string("attempt", entry.attempt.to_string());
  object.add_string("detail", entry.detail);
  object.add_raw("epoch", u64_text(entry.epoch.value()));
  object.add_string("publisher", entry.publisher.to_string());
  object.add_string("reason", to_string(entry.reason));
  object.add_raw("resulting_generation", u64_text(entry.resulting_generation.value()));
  object.add_raw("previous_generation",
                 entry.previous_generation.has_value() ? u64_text(entry.previous_generation->value()) : "null");
  return object.finish();
}

std::string render_publisher_json_body(const PublisherRecord& publisher) {
  JsonObject object;
  object.add_raw("attach_count", u64_text(publisher.attach_count));
  object.add_raw("attached_epoch", u64_text(publisher.attached_epoch.value()));
  object.add_string("current_boot", publisher.current_boot.to_string());
  std::vector<std::string> fenced;
  fenced.reserve(publisher.fenced_boots.size());
  for (const WorkerBootId& boot : publisher.fenced_boots) {
    fenced.push_back(boot.to_string());
  }
  object.add_raw("fenced_boots", json_string_array(fenced));
  object.add_string("id", publisher.id.to_string());
  object.add_raw("last_modified", u64_text(publisher.last_modified.value()));
  object.add_string("name", publisher.name);
  object.add_raw("participant",
                 publisher.participant.has_value() ? "\"" + json_escape(publisher.participant->to_string()) + "\"" : "null");
  object.add_string("state", to_string(publisher.state));
  object.add_string("status_reason", publisher.status_reason);
  return object.finish();
}

} // namespace

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 8);
  static constexpr char kHex[] = "0123456789abcdef";
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char value = static_cast<unsigned char>(text[i]);
    switch (value) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\b':
        out.append("\\b");
        break;
      case '\f':
        out.append("\\f");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (value < 0x20u) {
          out.append("\\u00");
          out.push_back(kHex[(value >> 4) & 0xFu]);
          out.push_back(kHex[value & 0xFu]);
        } else {
          out.push_back(static_cast<char>(value));
        }
        break;
    }
  }
  return out;
}

std::string render_provenance(const Provenance& provenance) {
  std::string out = "source=";
  out += to_string(provenance.source);
  out += " class=";
  out += to_string(provenance.validity_class);
  out += " mechanism=";
  out += provenance.mechanism;
  out += " source-identity=";
  out += provenance.source_identity;
  return out;
}

std::string render_fact(const IdentityFact& fact) {
  std::string out = "kind=";
  out += to_string(fact.kind);
  out += " scope=";
  out += fact.scope;
  out += " value=";
  out += fact.value;
  out += " strength=";
  out += to_string(fact_strength(fact.kind));
  return out;
}

std::string render_facts(const std::vector<IdentityFact>& facts) {
  std::string out;
  for (const IdentityFact& fact : facts) {
    out += "  - ";
    out += render_fact(fact);
    out += '\n';
  }
  return out;
}

std::string render_metadata(const std::vector<MetadataEntry>& metadata) {
  std::string out;
  for (const MetadataEntry& entry : metadata) {
    out += "  - key=";
    out += entry.key;
    out += " value=";
    out += entry.value;
    out += '\n';
  }
  return out;
}

std::string render_alias_keys(const std::vector<AliasKey>& aliases) {
  std::string out;
  for (const AliasKey& alias : aliases) {
    out += "  - ";
    out += alias.to_string();
    out += '\n';
  }
  return out;
}

std::string render_lineage_entry(const LineageEntry& entry) {
  std::string out = "reason=";
  out += to_string(entry.reason);
  out += " resulting-generation=";
  out += entry.resulting_generation.to_string();
  out += " previous-generation=";
  out += entry.previous_generation.has_value() ? entry.previous_generation->to_string() : std::string("-");
  out += " epoch=";
  out += entry.epoch.to_string();
  out += " publisher=";
  out += entry.publisher.to_string();
  out += " attempt=";
  out += entry.attempt.to_string();
  if (!entry.detail.empty()) {
    out += " detail=";
    out += entry.detail;
  }
  return out;
}

std::string render_record(const EntityRecord& record) {
  std::string out;
  append_key_value(out, "record", record.id.to_string());
  append_key_value(out, "class", to_string(record.entity_class));
  append_key_value(out, "lifecycle", to_string(record.lifecycle));
  append_key_value(out, "record-generation", record.record_generation.to_string());
  append_key_value(out, "creation-generation", record.creation_generation.to_string());
  append_key_value(out, "evidence-generation", record.evidence_generation.to_string());
  append_key_value(out, "hardware-identity", record.hardware_identity.to_string());
  append_key_value(out, "fingerprint", record.fingerprint.to_string());
  append_key_value(out, "derivation-namespace", record.derivation_namespace);
  append_key_value(out, "friendly-name", record.friendly_name);
  append_key_value(out, "fabric", record.fabric.has_value() ? record.fabric->to_string() : std::string("-"));
  append_key_value(out, "site", record.site.has_value() ? record.site->to_string() : std::string("-"));
  append_key_value(out, "control-domain",
                   record.control_domain.has_value() ? record.control_domain->to_string() : std::string("-"));
  append_key_value(out, "parent-device",
                   record.parent_device.has_value() ? record.parent_device->to_string() : std::string("-"));
  append_key_value(out, "superseded-by",
                   record.superseded_by.has_value() ? record.superseded_by->to_string() : std::string("-"));
  append_key_value(out, "supersedes",
                   record.supersedes.has_value() ? record.supersedes->to_string() : std::string("-"));
  append_key_value(out, "status-reason", record.status_reason);
  append_key_value(out, "created-by", record.created_by.to_string());
  append_key_value(out, "created-boot", record.created_boot.to_string());
  append_key_value(out, "created-epoch", record.created_epoch.to_string());
  append_key_value(out, "last-modified", record.last_modified.to_string());
  append_key_value(out, "evidence-class", to_string(record.evidence.evidence_class));
  append_key_value(out, "evidence-valid", bool_text(record.evidence.valid));
  append_key_value(out, "evidence-epoch", record.evidence.epoch.to_string());
  append_key_value(out, "evidence-accepted-at", record.evidence.accepted_at.to_string());
  append_key_value(out, "evidence-publisher", record.evidence.publisher.to_string());
  append_key_value(out, "evidence-publisher-boot", record.evidence.publisher_boot.to_string());
  append_key_value(out, "provenance", render_provenance(record.evidence.provenance));
  out += "facts:\n";
  out += render_facts(record.facts);
  out += "aliases:\n";
  out += render_alias_keys(record.aliases);
  out += "metadata:\n";
  out += render_metadata(record.metadata);
  return out;
}

std::string render_record_json(const EntityRecord& record) {
  JsonObject object;
  object.add_string("class", to_string(record.entity_class));
  object.add_string("control_domain",
                    record.control_domain.has_value() ? record.control_domain->to_string() : std::string());
  object.add_string("created_boot", record.created_boot.to_string());
  object.add_string("created_by", record.created_by.to_string());
  object.add_raw("created_epoch", u64_text(record.created_epoch.value()));
  object.add_raw("creation_generation", u64_text(record.creation_generation.value()));
  object.add_string("derivation_namespace", record.derivation_namespace);
  object.add_raw("evidence", render_evidence_json_body(record.evidence));
  object.add_raw("evidence_generation", u64_text(record.evidence_generation.value()));
  object.add_string("fabric", record.fabric.has_value() ? record.fabric->to_string() : std::string());
  std::vector<std::string> facts;
  facts.reserve(record.facts.size());
  for (const IdentityFact& fact : record.facts) {
    facts.push_back(render_fact_json_body(fact));
  }
  object.add_raw("facts", json_object_array(facts));
  object.add_string("fingerprint", record.fingerprint.to_string());
  object.add_string("friendly_name", record.friendly_name);
  object.add_string("hardware_identity", record.hardware_identity.to_string());
  object.add_string("id", record.id.to_string());
  object.add_raw("last_modified", u64_text(record.last_modified.value()));
  object.add_string("lifecycle", to_string(record.lifecycle));
  std::vector<std::string> metadata;
  metadata.reserve(record.metadata.size());
  for (const MetadataEntry& entry : record.metadata) {
    metadata.push_back(render_metadata_json_body(entry));
  }
  object.add_raw("metadata", json_object_array(metadata));
  object.add_string("parent_device",
                    record.parent_device.has_value() ? record.parent_device->to_string() : std::string());
  object.add_raw("record_generation", u64_text(record.record_generation.value()));
  object.add_string("site", record.site.has_value() ? record.site->to_string() : std::string());
  object.add_string("status_reason", record.status_reason);
  object.add_string("superseded_by",
                    record.superseded_by.has_value() ? record.superseded_by->to_string() : std::string());
  object.add_string("supersedes", record.supersedes.has_value() ? record.supersedes->to_string() : std::string());
  std::vector<std::string> aliases;
  aliases.reserve(record.aliases.size());
  for (const AliasKey& alias : record.aliases) {
    aliases.push_back(render_alias_json_body(alias));
  }
  object.add_raw("aliases", json_object_array(aliases));
  return object.finish();
}

std::string render_publisher(const PublisherRecord& publisher) {
  std::string out;
  append_key_value(out, "publisher", publisher.id.to_string());
  append_key_value(out, "name", publisher.name);
  append_key_value(out, "state", to_string(publisher.state));
  append_key_value(out, "current-boot", publisher.current_boot.to_string());
  append_key_value(out, "attached-epoch", publisher.attached_epoch.to_string());
  append_key_value(out, "attach-count", u64_text(publisher.attach_count));
  append_key_value(out, "last-modified", publisher.last_modified.to_string());
  append_key_value(out, "participant",
                   publisher.participant.has_value() ? publisher.participant->to_string() : std::string("-"));
  append_key_value(out, "status-reason", publisher.status_reason);
  out += "fenced-boots:\n";
  for (const WorkerBootId& boot : publisher.fenced_boots) {
    out += "  - ";
    out += boot.to_string();
    out += '\n';
  }
  return out;
}

std::string render_publisher_json(const PublisherRecord& publisher) {
  return render_publisher_json_body(publisher);
}

std::string render_history(const RecordHistory& history) {
  std::string out;
  append_key_value(out, "record", history.id.to_string());
  append_key_value(out, "truncated", bool_text(history.truncated));
  append_key_value(out, "entries", u64_text(history.entries.size()));
  for (const LineageEntry& entry : history.entries) {
    out += "  - ";
    out += render_lineage_entry(entry);
    out += '\n';
  }
  return out;
}

std::string render_history_json(const RecordHistory& history) {
  JsonObject object;
  object.add_string("id", history.id.to_string());
  std::vector<std::string> entries;
  entries.reserve(history.entries.size());
  for (const LineageEntry& entry : history.entries) {
    entries.push_back(render_lineage_json_body(entry));
  }
  object.add_raw("entries", json_object_array(entries));
  object.add_raw("truncated", bool_text(history.truncated));
  return object.finish();
}

std::string render_outcome_json(const Outcome& outcome) {
  JsonObject object;
  object.add_string("code", to_string(outcome.code));
  object.add_string("message", outcome.message);
  object.add_string("record", outcome.record.has_value() ? outcome.record->to_string() : std::string());
  object.add_raw("record_generation",
                 outcome.record_generation.has_value() ? u64_text(outcome.record_generation->value()) : "null");
  object.add_raw("evidence_generation",
                 outcome.evidence_generation.has_value() ? u64_text(outcome.evidence_generation->value()) : "null");
  object.add_raw("epoch", outcome.epoch.has_value() ? u64_text(outcome.epoch->value()) : "null");
  object.add_string("match", outcome.match.has_value() ? std::string(to_string(*outcome.match)) : std::string());
  object.add_string("request_digest",
                    outcome.request_digest.has_value() ? outcome.request_digest->to_string() : std::string());
  object.add_raw("state_generation",
                 outcome.state_generation.has_value() ? u64_text(outcome.state_generation->value()) : "null");
  std::vector<std::string> steps;
  steps.reserve(outcome.steps.size());
  for (const ExplanationStep& entry : outcome.steps) {
    JsonObject step;
    step.add_string("detail", entry.detail);
    step.add_string("field", entry.field);
    step.add_string("stage", entry.stage);
    step.add_string("value", entry.value);
    steps.push_back(step.finish());
  }
  object.add_raw("steps", json_object_array(steps));
  std::vector<std::string> related;
  related.reserve(outcome.related.size());
  for (const CanonicalId& id : outcome.related) {
    related.push_back(id.to_string());
  }
  object.add_raw("related", json_string_array(related));
  return object.finish();
}

} // namespace fabric_registry
