// Fabric Registry — inspection CLI.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The CLI is an inspection surface over the library, not an architecture. Every
// command is read-only except none: this tool never mutates a registry. Output
// is deterministic and line oriented so it can be scripted.

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_registry/discovery.hpp"
#include "fabric_registry/fabric_registry.hpp"
#include "fabric_registry/persistence.hpp"
#include "fabric_registry/serialization.hpp"

namespace {

struct Arguments {
  std::string command;
  std::string state_path;
  std::string id;
  std::string alias;
  bool json{false};
  bool help{false};
};

void print_usage() {
  std::cout << "fabric-registry-cli " << fabric_registry::version_string() << "\n"
            << "usage: fabric-registry-cli <command> [options]\n"
            << "\n"
            << "commands:\n"
            << "  version                     print the runtime version and format versions\n"
            << "  capabilities                print the discovery capability report for this host\n"
            << "  discover [--json]           enumerate host-visible device identity (REAL)\n"
            << "  inspect --state PATH        summarise a durable state file and its recovery outcome\n"
            << "  validate --state PATH       recompute every index and report consistency\n"
            << "  snapshot --state PATH [--json]  dump the complete registry deterministically\n"
            << "  show --state PATH --id ID   print one record by canonical identity\n"
            << "  explain --state PATH --id ID    print the lineage of one record\n"
            << "  resolve --state PATH --alias KEY  resolve a fully qualified alias\n"
            << "  publishers --state PATH     list the publishers held in the durable state\n";
}

bool parse(int argc, char** argv, Arguments& out, std::string& error) {
  if (argc < 2) {
    out.help = true;
    return true;
  }
  out.command = argv[1];
  if (out.command == "--help" || out.command == "-h" || out.command == "help") {
    out.help = true;
    return true;
  }
  for (int index = 2; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    const auto next = [&](std::string& target) -> bool {
      if (index + 1 >= argc) {
        error = std::string("missing value for ") + std::string(argument);
        return false;
      }
      target = argv[++index];
      return true;
    };
    if (argument == "--state") {
      if (!next(out.state_path)) {
        return false;
      }
    } else if (argument == "--id") {
      if (!next(out.id)) {
        return false;
      }
    } else if (argument == "--alias") {
      if (!next(out.alias)) {
        return false;
      }
    } else if (argument == "--json") {
      out.json = true;
    } else {
      error = std::string("unknown argument: ") + std::string(argument);
      return false;
    }
  }
  return true;
}

bool require_state(const Arguments& arguments) {
  if (!arguments.state_path.empty()) {
    return true;
  }
  std::cerr << "fabric-registry-cli: this command requires --state PATH\n";
  return false;
}

/// Loads a durable state file into a fresh registry. Returns false and prints
/// the specific failure when the file is missing, corrupt or truncated.
bool load_state(const Arguments& arguments,
                std::unique_ptr<fabric_registry::Registry>& registry,
                fabric_registry::RecoveryReport& report) {
  fabric_registry::RegistryOptions options;
  registry = std::make_unique<fabric_registry::Registry>(options);
  const fabric_registry::Outcome outcome = registry->load(arguments.state_path, report);
  if (!outcome.committed()) {
    std::cerr << "fabric-registry-cli: " << fabric_registry::to_string(outcome.code) << ": " << outcome.message
              << "\n";
    for (const fabric_registry::ExplanationStep& step : outcome.steps) {
      std::cerr << "  - stage=" << step.stage << " field=" << step.field << " value=" << step.value << " :: "
                << step.detail << "\n";
    }
    return false;
  }
  return true;
}

int command_capabilities() {
  for (const fabric_registry::CapabilityReport& capability : fabric_registry::discovery_capabilities()) {
    std::cout << fabric_registry::to_string(capability.capability) << " " << fabric_registry::to_string(capability.status)
              << " " << capability.detail << "\n";
  }
  return 0;
}

int command_discover(bool json) {
  const fabric_registry::DiscoveryReport report = fabric_registry::discover_local_host();
  if (json) {
    std::cout << "{\n";
    std::cout << "  \"platform\": \"" << fabric_registry::json_escape(report.platform) << "\",\n";
    std::cout << "  \"validity_class\": \"" << fabric_registry::to_string(report.validity_class) << "\",\n";
    std::cout << "  \"observations\": " << report.observations.size() << ",\n";
    std::cout << "  \"truncated\": " << (report.truncated ? "true" : "false") << "\n";
    std::cout << "}\n";
    return 0;
  }
  std::cout << report.render();
  return 0;
}

int command_inspect(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  const fabric_registry::RegistryStats stats = registry->stats();
  std::cout << "state: " << arguments.state_path << "\n";
  std::cout << report.render();
  std::cout << "entities " << stats.entities << "\n";
  std::cout << "current " << stats.current_entities << "\n";
  std::cout << "revalidation-required " << stats.revalidation_required_entities << "\n";
  std::cout << "retired " << stats.retired_entities << "\n";
  std::cout << "tombstoned " << stats.tombstoned_entities << "\n";
  std::cout << "aliases " << stats.aliases << "\n";
  std::cout << "indexed-aliases " << stats.indexed_aliases << "\n";
  std::cout << "publishers " << stats.publishers << "\n";
  std::cout << "registry-generation " << stats.generation.to_string() << "\n";
  std::cout << "coordinator-epoch " << stats.epoch.to_string() << "\n";
  std::cout << "state-digest " << registry->state_digest().to_string() << "\n";
  return 0;
}

int command_validate(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  std::string rendered;
  const fabric_registry::Outcome outcome = registry->validate_state(rendered);
  std::cout << rendered;
  if (!outcome.committed()) {
    std::cerr << "fabric-registry-cli: " << fabric_registry::to_string(outcome.code) << ": " << outcome.message
              << "\n";
    return 1;
  }
  return 0;
}

int command_snapshot(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  const fabric_registry::Snapshot snapshot = registry->snapshot();
  std::cout << (arguments.json ? snapshot.render_json() : snapshot.render());
  std::cout << "snapshot-current "
            << (registry->snapshot_current(snapshot) ? "true" : "false") << "\n";
  return 0;
}

int command_show(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  const std::optional<fabric_registry::CanonicalId> id = fabric_registry::CanonicalId::parse(arguments.id);
  if (!id.has_value()) {
    std::cerr << "fabric-registry-cli: --id is not a valid canonical identity (expected class:hex)\n";
    return 2;
  }
  std::shared_ptr<const fabric_registry::EntityRecord> record;
  const fabric_registry::Outcome outcome = registry->lookup(*id, record);
  if (!outcome.committed()) {
    std::cerr << "fabric-registry-cli: " << fabric_registry::to_string(outcome.code) << ": " << outcome.message
              << "\n";
    return 1;
  }
  std::cout << (arguments.json ? fabric_registry::render_record_json(*record) + "\n"
                               : fabric_registry::render_record(*record));
  return 0;
}

int command_explain(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  const std::optional<fabric_registry::CanonicalId> id = fabric_registry::CanonicalId::parse(arguments.id);
  if (!id.has_value()) {
    std::cerr << "fabric-registry-cli: --id is not a valid canonical identity (expected class:hex)\n";
    return 2;
  }
  fabric_registry::RecordHistory history;
  const fabric_registry::Outcome outcome = registry->history(*id, history);
  if (!outcome.committed()) {
    std::cerr << "fabric-registry-cli: " << fabric_registry::to_string(outcome.code) << ": " << outcome.message
              << "\n";
    return 1;
  }
  if (arguments.json) {
    std::cout << fabric_registry::render_history_json(history) << "\n";
    return 0;
  }
  std::cout << fabric_registry::render_history(history);
  std::shared_ptr<const fabric_registry::EntityRecord> record;
  if (registry->lookup(*id, record).committed()) {
    std::cout << "why: lifecycle=" << fabric_registry::to_string(record->lifecycle)
              << " status-reason=" << (record->status_reason.empty() ? std::string("-") : record->status_reason)
              << "\n";
  }
  return 0;
}

int command_resolve(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  const std::optional<fabric_registry::AliasKey> key = fabric_registry::AliasKey::parse(arguments.alias);
  if (!key.has_value()) {
    std::cerr << "fabric-registry-cli: --alias is not a valid alias key (expected namespace:scope=value)\n";
    return 2;
  }
  std::shared_ptr<const fabric_registry::EntityRecord> record;
  const fabric_registry::Outcome outcome = registry->lookup_by_alias(*key, record);
  if (!outcome.committed()) {
    std::cerr << "fabric-registry-cli: " << fabric_registry::to_string(outcome.code) << ": " << outcome.message
              << "\n";
    return 1;
  }
  std::cout << (arguments.json ? fabric_registry::render_record_json(*record) + "\n"
                               : fabric_registry::render_record(*record));
  return 0;
}

int command_publishers(const Arguments& arguments) {
  std::unique_ptr<fabric_registry::Registry> registry;
  fabric_registry::RecoveryReport report;
  if (!load_state(arguments, registry, report)) {
    return 1;
  }
  for (const fabric_registry::PublisherRecord& publisher : registry->publishers()) {
    std::cout << fabric_registry::render_publisher(publisher);
  }
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  Arguments arguments;
  std::string error;
  if (!parse(argc, argv, arguments, error)) {
    std::cerr << "fabric-registry-cli: " << error << "\n";
    return 2;
  }
  if (arguments.help) {
    print_usage();
    return 0;
  }
  if (arguments.command == "version") {
    std::cout << "fabric-registry " << fabric_registry::version_string() << "\n";
    std::cout << "state-format-version " << fabric_registry::state_format_version() << "\n";
    std::cout << "protocol-version " << fabric_registry::protocol_version() << "\n";
    return 0;
  }
  if (arguments.command == "capabilities") {
    return command_capabilities();
  }
  if (arguments.command == "discover") {
    return command_discover(arguments.json);
  }
  if (arguments.command == "inspect") {
    return require_state(arguments) ? command_inspect(arguments) : 2;
  }
  if (arguments.command == "validate") {
    return require_state(arguments) ? command_validate(arguments) : 2;
  }
  if (arguments.command == "snapshot") {
    return require_state(arguments) ? command_snapshot(arguments) : 2;
  }
  if (arguments.command == "show") {
    return require_state(arguments) ? command_show(arguments) : 2;
  }
  if (arguments.command == "explain") {
    return require_state(arguments) ? command_explain(arguments) : 2;
  }
  if (arguments.command == "resolve") {
    return require_state(arguments) ? command_resolve(arguments) : 2;
  }
  if (arguments.command == "publishers") {
    return require_state(arguments) ? command_publishers(arguments) : 2;
  }
  std::cerr << "fabric-registry-cli: unknown command: " << arguments.command << "\n";
  print_usage();
  return 2;
}
