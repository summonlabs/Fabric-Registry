// Example 6 — a real coordinator session over loopback TCP.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "support.hpp"

int main() {
  fabric_registry::CoordinatorOptions options;
  options.listen.host = "127.0.0.1";
  options.listen.port = 0;
  std::string error;
  std::unique_ptr<fabric_registry::Coordinator> coordinator =
      fabric_registry::Coordinator::start(options, error);
  if (!coordinator) {
    return example::fail("the coordinator could not start: " + error);
  }

  fabric_registry::PublisherClientOptions client_options;
  client_options.coordinator = coordinator->endpoint();
  client_options.name = "example-publisher";
  std::unique_ptr<fabric_registry::PublisherClient> client =
      fabric_registry::PublisherClient::connect(client_options, error);
  if (!client) {
    return example::fail("the publisher could not attach: " + error);
  }
  std::cout << "attached publisher=" << client->authority().publisher.to_string()
            << " boot=" << client->authority().worker_boot.to_string()
            << " epoch=" << client->authority().epoch.to_string() << "\n";

  fabric_registry::RegisterEntityRequest request;
  request.attempt = example::attempt_from("ex6-register");
  request.entity_class = fabric_registry::EntityClass::Switch;
  request.derivation_namespace = "example/fabric-remote";
  request.friendly_name = "remote-leaf";
  request.facts.push_back(example::serial_fact("REMOTE-1"));
  request.provenance = example::real_provenance("device-agent", "example-publisher");
  request.evidence_class = fabric_registry::EvidenceClass::ProcessBound;

  const fabric_registry::RemoteOutcome remote = client->register_entity(request);
  example::report(remote.outcome, "remote register");
  if (!remote.outcome.committed()) {
    return example::fail("the remote registration must commit");
  }

  const fabric_registry::RemoteOutcome replayed = client->register_entity(request);
  example::report(replayed.outcome, "remote replay");
  if (replayed.outcome.code != fabric_registry::OutcomeCode::Idempotent) {
    return example::fail("the remote replay must be idempotent");
  }

  fabric_registry::SnapshotSummary summary;
  if (!client->snapshot_summary(summary, error)) {
    return example::fail("the snapshot summary could not be read: " + error);
  }
  std::cout << "coordinator snapshot generation=" << summary.generation.to_string()
            << " epoch=" << summary.epoch.to_string() << " records=" << summary.record_count
            << " digest=" << summary.digest.to_string() << "\n";

  const fabric_registry::Outcome detached = client->detach();
  example::report(detached, "detach");
  coordinator->stop();
  std::cout << "publishers fenced on the way out: " << coordinator->fenced_publisher_count() << "\n";
  return 0;
}
