// Fabric Registry — publisher (worker) executable.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Two modes:
//   attach  connect, attach a fresh incarnation, optionally register entities,
//           optionally hold the session open while sending heartbeats, then
//           optionally detach.
//   replay  connect and send one registration carrying an EXPLICIT authority
//           claim supplied on the command line, without attaching. This is how
//           the multiprocess proof replays traffic from a fenced incarnation.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "fabric_registry/codec.hpp"
#include "fabric_registry/digest.hpp"
#include "fabric_registry/publisher.hpp"
#include "fabric_registry/transport.hpp"
#include "fabric_registry/version.hpp"

namespace {

struct Options {
  std::string mode{"attach"};
  std::string coordinator;
  std::string name{"publisher"};
  std::string publisher_hex;
  std::string boot_hex;
  std::string epoch_text{"0"};
  std::string report_path;
  std::string derivation_namespace{"fabric-registry/publisher"};
  std::string serial_prefix{"SN"};
  std::string entity_class_text{"switch"};
  std::vector<std::string> revalidate_targets;
  long long register_count{0};
  long long hold_ms{0};
  bool detach{false};
  bool synthetic{false};
  bool durable{false};
  bool help{false};
};

void print_usage() {
  std::cout << "fabric-registry-publisher " << fabric_registry::version_string() << "\n"
            << "usage: fabric-registry-publisher [options]\n"
            << "  --mode attach|replay    attach a fresh incarnation (default) or replay a forged claim\n"
            << "  --coordinator HOST:PORT coordinator address (required)\n"
            << "  --name NAME             publisher name\n"
            << "  --publisher HEX         reattach to this stable publisher identity\n"
            << "  --boot HEX              replay mode: the worker incarnation to present\n"
            << "  --epoch N               replay mode: the coordinator epoch to present\n"
            << "  --class NAME            entity class for registered entities (default switch)\n"
            << "  --count N               register N entities\n"
            << "  --namespace NS          derivation namespace\n"
            << "  --serial-prefix P       serial prefix for the generated entities\n"
            << "  --hold-ms N             keep the session open for N milliseconds, sending heartbeats\n"
            << "  --detach                detach gracefully at the end\n"
            << "  --synthetic             label the generated records synthetic\n"
            << "  --evidence KIND         process-bound (default) or durable\n"
            << "  --revalidate ID         revalidate this canonical identity with fresh evidence (repeatable)\n"
            << "  --report PATH           write a deterministic result report to PATH\n"
            << "  --help                  print this message\n";
}

bool parse_options(int argc, char** argv, Options& options, std::string& error) {
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    const auto next = [&](std::string& out) -> bool {
      if (index + 1 >= argc) {
        error = std::string("missing value for ") + std::string(argument);
        return false;
      }
      out = argv[++index];
      return true;
    };
    const auto next_number = [&](long long& out) -> bool {
      std::string value;
      if (!next(value)) {
        return false;
      }
      out = std::strtoll(value.c_str(), nullptr, 10);
      return true;
    };
    if (argument == "--help" || argument == "-h") {
      options.help = true;
    } else if (argument == "--mode") {
      if (!next(options.mode)) {
        return false;
      }
    } else if (argument == "--coordinator") {
      if (!next(options.coordinator)) {
        return false;
      }
    } else if (argument == "--name") {
      if (!next(options.name)) {
        return false;
      }
    } else if (argument == "--publisher") {
      if (!next(options.publisher_hex)) {
        return false;
      }
    } else if (argument == "--boot") {
      if (!next(options.boot_hex)) {
        return false;
      }
    } else if (argument == "--epoch") {
      if (!next(options.epoch_text)) {
        return false;
      }
    } else if (argument == "--class") {
      if (!next(options.entity_class_text)) {
        return false;
      }
    } else if (argument == "--count") {
      if (!next_number(options.register_count)) {
        return false;
      }
    } else if (argument == "--namespace") {
      if (!next(options.derivation_namespace)) {
        return false;
      }
    } else if (argument == "--serial-prefix") {
      if (!next(options.serial_prefix)) {
        return false;
      }
    } else if (argument == "--hold-ms") {
      if (!next_number(options.hold_ms)) {
        return false;
      }
    } else if (argument == "--report") {
      if (!next(options.report_path)) {
        return false;
      }
    } else if (argument == "--detach") {
      options.detach = true;
    } else if (argument == "--synthetic") {
      options.synthetic = true;
    } else if (argument == "--evidence") {
      std::string value;
      if (!next(value)) {
        return false;
      }
      if (value == "durable") {
        options.durable = true;
      } else if (value == "process-bound") {
        options.durable = false;
      } else {
        error = "--evidence must be durable or process-bound";
        return false;
      }
    } else if (argument == "--revalidate") {
      std::string value;
      if (!next(value)) {
        return false;
      }
      options.revalidate_targets.push_back(value);
    } else {
      error = std::string("unknown argument: ") + std::string(argument);
      return false;
    }
  }
  return true;
}

/// Deterministic attempt identifier derived from the run parameters, so a
/// replayed run presents exactly the same attempt and is recognized as an
/// idempotent replay, while a run with different parameters produces a distinct
/// attempt.
fabric_registry::RegistrationId mint_registration_id(const Options& options, std::uint64_t value) {
  fabric_registry::Sha256 hasher;
  hasher.update("fabric-registry/publisher-attempt/1");
  hasher.update(options.name);
  hasher.update(options.derivation_namespace);
  hasher.update(options.serial_prefix);
  for (int shift = 0; shift < 64; shift += 8) {
    const std::uint8_t byte = static_cast<std::uint8_t>((value >> shift) & 0xFFu);
    hasher.update(&byte, 1);
  }
  const fabric_registry::DigestBytes digest = hasher.finish();
  fabric_registry::IdBytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = digest[index];
  }
  if (bytes[0] == 0 && bytes[1] == 0) {
    bytes[0] = 0x5A;
  }
  return fabric_registry::RegistrationId::from_bytes(bytes);
}

fabric_registry::Outcome register_one(fabric_registry::PublisherClient& client,
                                      const Options& options,
                                      fabric_registry::EntityClass entity_class,
                                      std::uint64_t index) {
  fabric_registry::RegisterEntityRequest request;
  request.attempt = mint_registration_id(options, index + 1);
  request.entity_class = entity_class;
  request.derivation_namespace = options.derivation_namespace;
  request.friendly_name = options.serial_prefix + "-" + std::to_string(index);
  fabric_registry::IdentityFact serial;
  serial.kind = fabric_registry::IdentityFactKind::SerialNumber;
  serial.scope = std::string("vendor:0x15b3/product:0x1017");
  serial.value = options.serial_prefix + "-" + std::to_string(index);
  request.facts.push_back(serial);
  fabric_registry::AliasInput alias;
  alias.alias_namespace = fabric_registry::AliasNamespace::CloudResourceId;
  alias.value = "fabric-registry/" + options.serial_prefix + "/" + std::to_string(index);
  request.aliases.push_back(alias);
  request.provenance.source = fabric_registry::ObservationSource::DeviceAgent;
  request.provenance.validity_class = options.synthetic ? fabric_registry::ProvenanceClass::Synthetic
                                                        : fabric_registry::ProvenanceClass::Real;
  request.provenance.mechanism = "fabric-registry-publisher";
  request.provenance.source_identity = options.name;
  request.evidence_class = options.durable ? fabric_registry::EvidenceClass::DurableAuthority
                                           : fabric_registry::EvidenceClass::ProcessBound;
  request.admission = fabric_registry::AdmissionMode::RequireCurrent;
  return client.register_entity(std::move(request)).outcome;
}

/// Re-establishes current authority for one record using fresh evidence from
/// this incarnation. The fact set is left untouched: merge_facts with an empty
/// list renews the evidence without rewriting identity.
fabric_registry::Outcome revalidate_one(fabric_registry::PublisherClient& client,
                                        const Options& options,
                                        const fabric_registry::CanonicalId& target,
                                        std::uint64_t index) {
  fabric_registry::RevalidateEntityRequest request;
  request.attempt = mint_registration_id(options, 50000 + index);
  request.target = target;
  request.merge_facts = true;
  request.provenance.source = fabric_registry::ObservationSource::DeviceAgent;
  request.provenance.validity_class = options.synthetic ? fabric_registry::ProvenanceClass::Synthetic
                                                        : fabric_registry::ProvenanceClass::Real;
  request.provenance.mechanism = "fabric-registry-publisher";
  request.provenance.source_identity = options.name;
  request.evidence_class = options.durable ? fabric_registry::EvidenceClass::DurableAuthority
                                           : fabric_registry::EvidenceClass::ProcessBound;
  return client.revalidate_entity(std::move(request)).outcome;
}

int run_replay(const Options& options, std::string& report) {
  const std::optional<fabric_registry::Endpoint> endpoint = fabric_registry::Endpoint::parse(options.coordinator);
  if (!endpoint.has_value()) {
    std::cerr << "fabric-registry-publisher: --coordinator is not a valid HOST:PORT endpoint\n";
    return 2;
  }
  const std::optional<fabric_registry::PublisherId> publisher =
      fabric_registry::PublisherId::parse(options.publisher_hex);
  const std::optional<fabric_registry::WorkerBootId> boot = fabric_registry::WorkerBootId::parse(options.boot_hex);
  if (!publisher.has_value() || !boot.has_value()) {
    std::cerr << "fabric-registry-publisher: replay mode needs a valid --publisher and --boot\n";
    return 2;
  }
  const std::optional<fabric_registry::CoordinatorEpoch> epoch =
      fabric_registry::CoordinatorEpoch::parse(options.epoch_text);
  if (!epoch.has_value()) {
    std::cerr << "fabric-registry-publisher: --epoch is not a valid counter\n";
    return 2;
  }

  fabric_registry::TransportConfig transport;
  std::string error;
  std::optional<fabric_registry::Socket> socket =
      fabric_registry::connect_to(*endpoint, transport.connect_timeout, error);
  if (!socket.has_value()) {
    std::cerr << "fabric-registry-publisher: " << error << "\n";
    return 1;
  }
  fabric_registry::Connection connection(std::move(*socket), transport);
  fabric_registry::HelloRequest hello;
  hello.protocol_version = fabric_registry::protocol_version();
  hello.client_name = "replay";
  fabric_registry::Frame response;
  if (!connection.round_trip(fabric_registry::MessageType::Hello, 1,
                             fabric_registry::encode_hello_request(hello), response, error)) {
    std::cerr << "fabric-registry-publisher: " << error << "\n";
    return 1;
  }

  fabric_registry::RegisterEntityRequest request;
  request.attempt = mint_registration_id(options, 9001);
  request.authority.publisher = *publisher;
  request.authority.worker_boot = *boot;
  request.authority.epoch = *epoch;
  request.entity_class = fabric_registry::EntityClass::Switch;
  request.derivation_namespace = options.derivation_namespace;
  request.friendly_name = "replay-attempt";
  fabric_registry::IdentityFact serial;
  serial.kind = fabric_registry::IdentityFactKind::SerialNumber;
  serial.scope = "vendor:0x15b3/product:0x1017";
  serial.value = "REPLAY-1";
  request.facts.push_back(serial);
  request.provenance.source = fabric_registry::ObservationSource::DeviceAgent;
  request.provenance.validity_class = fabric_registry::ProvenanceClass::Real;
  request.provenance.mechanism = "fabric-registry-publisher";
  request.evidence_class = fabric_registry::EvidenceClass::ProcessBound;
  request.admission = fabric_registry::AdmissionMode::RequireCurrent;

  if (!connection.round_trip(fabric_registry::MessageType::RegisterEntity, 2,
                             fabric_registry::encode_register_request(request), response, error)) {
    std::cerr << "fabric-registry-publisher: " << error << "\n";
    return 1;
  }
  fabric_registry::Outcome outcome;
  if (response.type == fabric_registry::MessageType::Error) {
    fabric_registry::ErrorPayload payload;
    if (!fabric_registry::decode_error(response.payload, payload, error)) {
      std::cerr << "fabric-registry-publisher: " << error << "\n";
      return 1;
    }
    outcome = fabric_registry::Outcome(payload.code, payload.message);
  } else if (!fabric_registry::decode_outcome(response.payload, outcome, error)) {
    std::cerr << "fabric-registry-publisher: " << error << "\n";
    return 1;
  }
  connection.close();

  report += "mode=replay\n";
  report += "outcome=";
  report += fabric_registry::to_string(outcome.code);
  report += "\n";
  report += "message=";
  report += outcome.message;
  report += "\n";
  std::cout << "replay outcome " << fabric_registry::to_string(outcome.code) << ": " << outcome.message << "\n";
  std::cout.flush();
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  Options options;
  std::string error;
  if (!parse_options(argc, argv, options, error)) {
    std::cerr << "fabric-registry-publisher: " << error << "\n";
    print_usage();
    return 2;
  }
  if (options.help) {
    print_usage();
    return 0;
  }
  std::string report;
  if (options.mode == "replay") {
    const int status = run_replay(options, report);
    if (!options.report_path.empty()) {
      std::ofstream stream(options.report_path, std::ios::binary | std::ios::trunc);
      stream << report;
    }
    return status;
  }
  if (options.mode != "attach") {
    std::cerr << "fabric-registry-publisher: unknown mode " << options.mode << "\n";
    return 2;
  }

  const std::optional<fabric_registry::Endpoint> endpoint = fabric_registry::Endpoint::parse(options.coordinator);
  if (!endpoint.has_value()) {
    std::cerr << "fabric-registry-publisher: --coordinator is not a valid HOST:PORT endpoint\n";
    return 2;
  }
  const std::optional<fabric_registry::EntityClass> entity_class =
      fabric_registry::entity_class_from_string(options.entity_class_text);
  if (!entity_class.has_value()) {
    std::cerr << "fabric-registry-publisher: --class is not a known entity class\n";
    return 2;
  }

  fabric_registry::PublisherClientOptions client_options;
  client_options.coordinator = *endpoint;
  client_options.name = options.name;
  if (!options.publisher_hex.empty()) {
    const std::optional<fabric_registry::PublisherId> publisher =
        fabric_registry::PublisherId::parse(options.publisher_hex);
    if (!publisher.has_value()) {
      std::cerr << "fabric-registry-publisher: --publisher is not a valid identifier\n";
      return 2;
    }
    client_options.publisher = *publisher;
  }

  std::unique_ptr<fabric_registry::PublisherClient> client =
      fabric_registry::PublisherClient::connect(client_options, error);
  if (!client) {
    std::cerr << "fabric-registry-publisher: " << error << "\n";
    return 1;
  }

  const auto publish_report = [&options](const std::string& text) {
    if (options.report_path.empty()) {
      return;
    }
    std::ofstream stream(options.report_path, std::ios::binary | std::ios::trunc);
    stream << text;
    stream.flush();
  };

  report += "mode=attach\n";
  report += "publisher=";
  report += client->authority().publisher.to_string();
  report += "\n";
  report += "boot=";
  report += client->authority().worker_boot.to_string();
  report += "\n";
  report += "epoch=";
  report += client->authority().epoch.to_string();
  report += "\n";
  report += "status=attached\n";
  publish_report(report);
  std::cout << "attached publisher=" << client->authority().publisher.to_string()
            << " boot=" << client->authority().worker_boot.to_string()
            << " epoch=" << client->authority().epoch.to_string() << "\n";
  std::cout.flush();

  int failures = 0;
  for (long long index = 0; index < options.register_count; ++index) {
    const fabric_registry::Outcome outcome =
        register_one(*client, options, *entity_class, static_cast<std::uint64_t>(index) + 1);
    report += "registered[";
    report += std::to_string(index);
    report += "]=";
    report += fabric_registry::to_string(outcome.code);
    report += "\n";
    if (outcome.record.has_value()) {
      report += "record[";
      report += std::to_string(index);
      report += "]=";
      report += outcome.record->to_string();
      report += "\n";
    }
    if (outcome.record_generation.has_value()) {
      report += "generation[";
      report += std::to_string(index);
      report += "]=";
      report += outcome.record_generation->to_string();
      report += "\n";
    }
    if (!outcome.succeeded()) {
      ++failures;
      std::cerr << "fabric-registry-publisher: registration " << index << " failed: "
                << fabric_registry::to_string(outcome.code) << " " << outcome.message << "\n";
    }
    publish_report(report);
  }
  report += "status=registered\n";
  publish_report(report);

  std::uint64_t revalidation_index = 0;
  for (const std::string& text : options.revalidate_targets) {
    const std::optional<fabric_registry::CanonicalId> target = fabric_registry::CanonicalId::parse(text);
    if (!target.has_value()) {
      std::cerr << "fabric-registry-publisher: --revalidate is not a valid canonical identity: " << text << "\n";
      return 2;
    }
    const fabric_registry::Outcome outcome = revalidate_one(*client, options, *target, revalidation_index++);
    report += "revalidated[";
    report += text;
    report += "]=";
    report += fabric_registry::to_string(outcome.code);
    report += "\n";
    if (outcome.record_generation.has_value()) {
      report += "revalidated-generation[";
      report += text;
      report += "]=";
      report += outcome.record_generation->to_string();
      report += "\n";
    }
    if (!outcome.succeeded()) {
      ++failures;
      std::cerr << "fabric-registry-publisher: revalidation of " << text << " failed: "
                << fabric_registry::to_string(outcome.code) << " " << outcome.message << "\n";
    }
    publish_report(report);
  }
  if (!options.revalidate_targets.empty()) {
    report += "status=revalidated\n";
    publish_report(report);
  }

  if (options.hold_ms > 0) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.hold_ms);
    while (std::chrono::steady_clock::now() < deadline) {
      if (!client->heartbeat(error)) {
        std::cerr << "fabric-registry-publisher: heartbeat failed: " << error << "\n";
        ++failures;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  if (options.detach) {
    const fabric_registry::Outcome outcome = client->detach();
    report += "detached=";
    report += fabric_registry::to_string(outcome.code);
    report += "\n";
  } else {
    client->close();
  }
  report += "status=exited\n";
  report += "failures=";
  report += std::to_string(failures);
  report += "\n";
  publish_report(report);
  return failures == 0 ? 0 : 1;
}
