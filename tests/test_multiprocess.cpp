// Fabric Registry — multiprocess proofs.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every proof in this file uses real operating-system processes: a coordinator
// executable and one or more publisher executables, started through
// CreateProcessW (or fork/exec) and terminated with the operating system's own
// forced termination. Nothing is simulated with threads and no failure is faked
// with an in-memory flag.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"
#include "support/test_harness.hpp"
#include "support/test_process.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

/// Resolved once from the harness option table: "test-multiprocess" is registered
/// with "--coordinator <path> --publisher <path>".
std::string coordinator_path() { return frtest::option("--coordinator"); }
std::string publisher_path() { return frtest::option("--publisher"); }

constexpr long long kReadyBudgetMs = 30000;
constexpr long long kReportBudgetMs = 60000;
constexpr long long kStateBudgetMs = 30000;

/// Turns a rendered outcome code back into its enumerator so a proof can assert
/// on the classification rather than on a spelling.
bool outcome_code_from_text(const std::string& text, fabric_registry::OutcomeCode& out) {
  for (std::uint8_t raw = 0; raw < fabric_registry::kOutcomeCodeCount; ++raw) {
    const fabric_registry::OutcomeCode candidate = static_cast<fabric_registry::OutcomeCode>(raw);
    if (fabric_registry::to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

std::string report_value(const std::string& text, const std::string& key) {
  const std::string needle = key + "=";
  std::size_t position = 0;
  while (position < text.size()) {
    const std::size_t end = text.find('\n', position);
    const std::string line = text.substr(position, end == std::string::npos ? std::string::npos : end - position);
    if (line.rfind(needle, 0) == 0) {
      return line.substr(needle.size());
    }
    if (end == std::string::npos) {
      break;
    }
    position = end + 1;
  }
  return std::string();
}

struct CoordinatorHandle {
  frtest::ChildProcess process;
  std::string directory;
  std::string state_path;
  std::string ready_path;
  std::uint16_t port{0};

  bool start(const std::string& directory_in, const std::string& state_name, bool keep_state, std::string& error) {
    directory = directory_in;
    state_path = (std::filesystem::path(directory) / state_name).string();
    ready_path = (std::filesystem::path(directory) / (state_name + ".port")).string();
    if (!keep_state) {
      std::error_code ignored;
      std::filesystem::remove(state_path, ignored);
      std::filesystem::remove(ready_path, ignored);
    } else {
      std::error_code ignored;
      std::filesystem::remove(ready_path, ignored);
    }
    std::vector<std::string> arguments{"--listen", "127.0.0.1:0", "--ready-file", ready_path, "--quiet", "--state",
                                       state_path};
    std::optional<frtest::ChildProcess> child =
        frtest::ChildProcess::spawn(coordinator_path(), arguments, error);
    if (!child.has_value()) {
      return false;
    }
    process = std::move(*child);
    if (!frtest::ChildProcess::wait_for_file(ready_path, kReadyBudgetMs)) {
      error = "the coordinator did not publish its port within the readiness budget";
      return false;
    }
    std::string text;
    if (!frtest::ChildProcess::read_file(ready_path, text)) {
      error = "the coordinator ready file could not be read";
      return false;
    }
    const long value = std::strtol(text.c_str(), nullptr, 10);
    if (value <= 0 || value > 65535) {
      error = "the coordinator published an invalid port";
      return false;
    }
    port = static_cast<std::uint16_t>(value);
    return true;
  }

  void kill_hard() {
    std::string error;
    process.kill(error);
    process.wait(error);
  }

  void stop_gracefully() {
    process.close_stdin();
    std::string error;
    process.wait(error);
  }

  fabric_registry::Endpoint endpoint() const {
    fabric_registry::Endpoint result;
    result.host = "127.0.0.1";
    result.port = port;
    return result;
  }
};

struct PublisherHandle {
  frtest::ChildProcess process;
  std::string report_path;

  bool start(const std::vector<std::string>& extra,
             std::uint16_t port,
             const std::string& directory,
             const std::string& label,
             std::string& error) {
    report_path = (std::filesystem::path(directory) / ("publisher-" + label + ".report")).string();
    std::error_code ignored;
    std::filesystem::remove(report_path, ignored);
    std::vector<std::string> arguments{"--coordinator", "127.0.0.1:" + std::to_string(port), "--report", report_path};
    arguments.insert(arguments.end(), extra.begin(), extra.end());
    std::optional<frtest::ChildProcess> child = frtest::ChildProcess::spawn(publisher_path(), arguments, error);
    if (!child.has_value()) {
      return false;
    }
    process = std::move(*child);
    return true;
  }

  /// Waits until the report contains `marker` and returns the whole report. The
  /// publisher republishes its report at every stage, so a supervisor never has
  /// to wait for the process to exit.
  bool await_report(const std::string& marker, std::string& text) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kReportBudgetMs);
    for (;;) {
      if (frtest::ChildProcess::read_file(report_path, text) && text.find(marker) != std::string::npos) {
        return true;
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      frtest::sleep_milliseconds(10);
    }
  }

  void kill_hard() {
    std::string error;
    process.kill(error);
    process.wait(error);
  }
};

/// Runs one replay attempt in a separate process and returns its outcome text.
bool run_replay(std::uint16_t port,
                const std::string& directory,
                const std::string& label,
                const std::string& publisher,
                const std::string& boot,
                const std::string& epoch,
                std::string& outcome,
                std::string& detail) {
  const std::string report = (std::filesystem::path(directory) / ("replay-" + label + ".report")).string();
  std::error_code ignored;
  std::filesystem::remove(report, ignored);
  const std::vector<std::string> arguments{"--mode",  "replay", "--coordinator", "127.0.0.1:" + std::to_string(port),
                                           "--publisher", publisher, "--boot", boot, "--epoch", epoch,
                                           "--report", report};
  std::string error;
  std::optional<frtest::ChildProcess> child = frtest::ChildProcess::spawn(publisher_path(), arguments, error);
  if (!child.has_value()) {
    detail = error;
    return false;
  }
  std::string text;
  if (!frtest::ChildProcess::wait_for_file(report, kReportBudgetMs) ||
      !frtest::ChildProcess::read_file(report, text)) {
    detail = "the replay process produced no report";
    child->kill(error);
    child->wait(error);
    return false;
  }
  std::string wait_error;
  child->wait(wait_error);
  outcome = report_value(text, "outcome");
  detail = report_value(text, "message");
  return !outcome.empty();
}

struct Observer {
  std::unique_ptr<fabric_registry::PublisherClient> client;

  bool attach(std::uint16_t port, std::string& error) {
    fabric_registry::PublisherClientOptions options;
    options.coordinator.host = "127.0.0.1";
    options.coordinator.port = port;
    options.name = "test-observer";
    client = fabric_registry::PublisherClient::connect(options, error);
    return client != nullptr;
  }

  bool stats(fabric_registry::RegistryStats& out) {
    fabric_registry::StatsPayload payload;
    std::string error;
    if (!client->statistics(payload, error)) {
      return false;
    }
    out = payload.stats;
    return true;
  }

  bool lookup(const std::string& canonical, fabric_registry::Lifecycle& lifecycle,
              fabric_registry::RecordGeneration& generation, std::string& error) {
    const std::optional<fabric_registry::CanonicalId> id = fabric_registry::CanonicalId::parse(canonical);
    if (!id.has_value()) {
      error = "the test supplied an invalid canonical identity: " + canonical;
      return false;
    }
    fabric_registry::Outcome outcome;
    std::shared_ptr<const fabric_registry::EntityRecord> record;
    if (!client->lookup(*id, outcome, record, error)) {
      return false;
    }
    if (!outcome.committed() || record == nullptr) {
      error = "lookup failed with " + std::string(fabric_registry::to_string(outcome.code)) + ": " + outcome.message;
      return false;
    }
    lifecycle = record->lifecycle;
    generation = record->record_generation;
    return true;
  }

  bool current_count(std::size_t& out) {
    fabric_registry::RegistryStats snapshot;
    if (!stats(snapshot)) {
      return false;
    }
    out = snapshot.current_entities;
    return true;
  }
};

bool wait_for_condition(const std::function<bool()>& predicate, long long budget_ms) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
  for (;;) {
    if (predicate()) {
      return true;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    frtest::sleep_milliseconds(20);
  }
}

struct LoadedState {
  fabric_registry::Registry registry;
  fabric_registry::RecoveryReport report;
};

std::string temporary_root(const std::string& label) {
  static int counter = 0;
  ++counter;
  return frtest::make_temporary_directory(label + "-" + std::to_string(counter));
}

} // namespace

FR_TEST_CASE(multiprocess, publisher_death_fencing_and_reincarnation) {
  FR_CHECK_MSG(!coordinator_path().empty(), "the coordinator executable path was not supplied");
  FR_CHECK_MSG(!publisher_path().empty(), "the publisher executable path was not supplied");
  const std::string directory = temporary_root("death");
  FR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");

  std::string error;
  CoordinatorHandle coordinator;
  FR_CHECK_MSG(coordinator.start(directory, "state.bin", false, error), error.c_str());

  // Peer B is started first and must remain unaffected throughout.
  PublisherHandle peer_b;
  FR_CHECK_MSG(peer_b.start({"--name", "B", "--count", "1", "--serial-prefix", "B", "--hold-ms", "120000"},
                            coordinator.port, directory, "b", error),
               error.c_str());
  std::string report_b;
  FR_CHECK_MSG(peer_b.await_report("record[0]=", report_b), "publisher B produced no report");
  const std::string record_b = report_value(report_b, "record[0]");
  FR_CHECK_MSG(!record_b.empty(), "publisher B did not report a canonical identity");

  // Publisher A registers two authoritative records under incarnation A1.
  PublisherHandle publisher_a;
  FR_CHECK_MSG(publisher_a.start({"--name", "A", "--count", "2", "--serial-prefix", "A", "--hold-ms", "120000"},
                                 coordinator.port, directory, "a", error),
               error.c_str());
  std::string report_a;
  FR_CHECK_MSG(publisher_a.await_report("record[1]=", report_a), "publisher A produced no report");
  const std::string publisher_a_id = report_value(report_a, "publisher");
  const std::string boot_a1 = report_value(report_a, "boot");
  const std::string epoch_a = report_value(report_a, "epoch");
  const std::string record_a0 = report_value(report_a, "record[0]");
  const std::string record_a1 = report_value(report_a, "record[1]");
  FR_CHECK_MSG(!publisher_a_id.empty() && !boot_a1.empty() && !epoch_a.empty() && !record_a0.empty() &&
                   !record_a1.empty(),
               "publisher A did not report its incarnation and records");

  Observer observer;
  FR_CHECK_MSG(observer.attach(coordinator.port, error), error.c_str());
  fabric_registry::RegistryStats stats;
  FR_CHECK_MSG(observer.stats(stats), "the observer could not read statistics");
  FR_CHECK_EQ(stats.current_entities, static_cast<std::size_t>(3));
  FR_CHECK_EQ(stats.revalidation_required_entities, static_cast<std::size_t>(0));

  // Kill publisher A as a real operating-system process. No graceful shutdown of
  // any kind runs in the child.
  publisher_a.kill_hard();

  // The coordinator must notice through the real control path: the session ends,
  // the publisher is fenced and its process-bound evidence stops being current.
  FR_CHECK_MSG(wait_for_condition(
                   [&]() {
                     fabric_registry::RegistryStats current;
                     return observer.stats(current) && current.revalidation_required_entities >= 2 &&
                            current.current_entities == 1;
                   },
                   kStateBudgetMs),
               "the coordinator did not fence the dead publisher's evidence");

  fabric_registry::Lifecycle lifecycle = fabric_registry::Lifecycle::Current;
  fabric_registry::RecordGeneration generation;
  FR_CHECK_MSG(observer.lookup(record_a0, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::RevalidationRequired);
  FR_CHECK_MSG(observer.lookup(record_b, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::Current);

  // Replaying the dead incarnation is rejected before any mutation happens.
  std::string outcome;
  std::string detail;
  FR_CHECK_MSG(run_replay(coordinator.port, directory, "before-reattach", publisher_a_id, boot_a1, epoch_a, outcome,
                          detail),
               "the replay process did not run");
  fabric_registry::OutcomeCode first_replay_code = fabric_registry::OutcomeCode::Committed;
  FR_CHECK_MSG(outcome_code_from_text(outcome, first_replay_code), ("unknown outcome text: " + outcome).c_str());
  FR_CHECK_MSG(fabric_registry::is_stale(first_replay_code),
               ("traffic from the dead incarnation must be classed as stale, saw: " + outcome).c_str());

  // Replacement A' reattaches under the same stable publisher identity and
  // receives a freshly minted incarnation.
  PublisherHandle replacement;
  FR_CHECK_MSG(replacement.start({"--name", "A", "--publisher", publisher_a_id, "--count", "0", "--hold-ms", "120000"},
                                 coordinator.port, directory, "a2", error),
               error.c_str());
  std::string report_a2;
  FR_CHECK_MSG(replacement.await_report("status=attached", report_a2), "the replacement publisher produced no report");
  const std::string boot_a2 = report_value(report_a2, "boot");
  FR_CHECK_MSG(!boot_a2.empty(), "the replacement publisher did not report its incarnation");
  FR_CHECK_MSG(boot_a2 != boot_a1, "a restarted publisher must receive a fresh incarnation");

  // The old incarnation is now permanently fenced: the publisher is active, so
  // the rejection is specifically a stale worker boot.
  FR_CHECK_MSG(run_replay(coordinator.port, directory, "after-reattach", publisher_a_id, boot_a1, epoch_a, outcome,
                          detail),
               "the replay process did not run");
  FR_CHECK_EQ(outcome, std::string("stale-worker-boot"));

  // Fresh evidence from the new incarnation is required before the records are
  // current again.
  PublisherHandle revalidator;
  FR_CHECK_MSG(revalidator.start({"--name", "A", "--publisher", publisher_a_id, "--count", "0", "--revalidate",
                                  record_a0, "--revalidate", record_a1, "--hold-ms", "60000"},
                                 coordinator.port, directory, "a3", error),
               error.c_str());
  std::string report_a3;
  FR_CHECK_MSG(revalidator.await_report("status=revalidated", report_a3), "the revalidating publisher produced no report");
  FR_CHECK_MSG(report_value(report_a3, "revalidated[" + record_a0 + "]") == "committed",
               "revalidation of the first record must commit");
  FR_CHECK_MSG(report_value(report_a3, "revalidated[" + record_a1 + "]") == "committed",
               "revalidation of the second record must commit");
  FR_CHECK_MSG(observer.lookup(record_a0, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::Current);
  FR_CHECK_MSG(observer.lookup(record_b, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::Current);

  // The dead incarnation still cannot act.
  FR_CHECK_MSG(run_replay(coordinator.port, directory, "after-revalidation", publisher_a_id, boot_a1, epoch_a, outcome,
                          detail),
               "the replay process did not run");
  FR_CHECK_EQ(outcome, std::string("stale-worker-boot"));

  observer.client->detach();
  peer_b.kill_hard();
  replacement.kill_hard();
  revalidator.kill_hard();
  coordinator.stop_gracefully();

  // The durable state must be loadable and internally consistent.
  fabric_registry::Registry loaded;
  fabric_registry::RecoveryReport report;
  const fabric_registry::Outcome load_outcome = loaded.load(coordinator.state_path, report);
  FR_CHECK_MSG(load_outcome.committed(), ("the durable state did not load: " + load_outcome.message).c_str());
  std::string rendered;
  FR_CHECK_MSG(loaded.validate_state(rendered).committed(), ("state inconsistent: " + rendered).c_str());
  FR_CHECK_MSG(loaded.stats().entities >= 3, "the durable state lost records");
  frtest::remove_directory(directory);
}

FR_TEST_CASE(multiprocess, coordinator_restart_epoch_and_conservative_recovery) {
  FR_CHECK_MSG(!coordinator_path().empty(), "the coordinator executable path was not supplied");
  const std::string directory = temporary_root("restart");
  FR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");

  std::string error;
  CoordinatorHandle first;
  FR_CHECK_MSG(first.start(directory, "state.bin", false, error), error.c_str());

  PublisherHandle durable;
  FR_CHECK_MSG(durable.start({"--name", "D", "--count", "1", "--serial-prefix", "D", "--evidence", "durable",
                              "--hold-ms", "120000"},
                             first.port, directory, "durable", error),
               error.c_str());
  std::string durable_report;
  FR_CHECK_MSG(durable.await_report("record[0]=", durable_report), "the durable publisher produced no report");
  const std::string durable_record = report_value(durable_report, "record[0]");
  const std::string durable_publisher = report_value(durable_report, "publisher");
  const std::string durable_boot = report_value(durable_report, "boot");
  const std::string first_epoch = report_value(durable_report, "epoch");
  FR_CHECK_MSG(!durable_record.empty() && !durable_publisher.empty() && !first_epoch.empty(),
               "the durable publisher did not report its record and incarnation");

  PublisherHandle ephemeral;
  FR_CHECK_MSG(ephemeral.start({"--name", "E", "--count", "1", "--serial-prefix", "E", "--hold-ms", "120000"},
                               first.port, directory, "ephemeral", error),
               error.c_str());
  std::string ephemeral_report;
  FR_CHECK_MSG(ephemeral.await_report("record[0]=", ephemeral_report), "the process-bound publisher produced no report");
  const std::string ephemeral_record = report_value(ephemeral_report, "record[0]");
  const std::string ephemeral_publisher = report_value(ephemeral_report, "publisher");
  const std::string ephemeral_boot = report_value(ephemeral_report, "boot");
  FR_CHECK_MSG(!ephemeral_record.empty() && !ephemeral_publisher.empty(), "the process-bound publisher reported no record");

  // Kill the coordinator as a real process. Durable state survives on disk; live
  // authority does not survive anywhere.
  first.kill_hard();
  durable.kill_hard();
  ephemeral.kill_hard();

  CoordinatorHandle second;
  FR_CHECK_MSG(second.start(directory, "state.bin", true, error), error.c_str());

  // The fresh coordinator must have advanced the epoch.
  Observer observer;
  FR_CHECK_MSG(observer.attach(second.port, error), error.c_str());
  const std::string second_epoch = observer.client->coordinator_epoch().to_string();
  FR_CHECK_MSG(second_epoch != first_epoch, "a restarted coordinator must advance the coordinator epoch");

  fabric_registry::Lifecycle lifecycle = fabric_registry::Lifecycle::Discovered;
  fabric_registry::RecordGeneration generation;
  FR_CHECK_MSG(observer.lookup(durable_record, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::Current);
  FR_CHECK_MSG(observer.lookup(ephemeral_record, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::RevalidationRequired);

  // Old-epoch traffic is rejected outright.
  std::string outcome;
  std::string detail;
  FR_CHECK_MSG(run_replay(second.port, directory, "old-epoch", durable_publisher, durable_boot, first_epoch, outcome,
                          detail),
               "the replay process did not run");
  FR_CHECK_EQ(outcome, std::string("stale-epoch"));

  // Old-incarnation traffic at the new epoch is rejected because recovery never
  // restores a process incarnation as live.
  FR_CHECK_MSG(run_replay(second.port, directory, "old-boot", ephemeral_publisher, ephemeral_boot, second_epoch,
                          outcome, detail),
               "the replay process did not run");
  fabric_registry::OutcomeCode recovery_replay_code = fabric_registry::OutcomeCode::Committed;
  FR_CHECK_MSG(outcome_code_from_text(outcome, recovery_replay_code), ("unknown outcome text: " + outcome).c_str());
  FR_CHECK_MSG(fabric_registry::is_stale(recovery_replay_code),
               ("traffic from a pre-restart incarnation must be stale, saw: " + outcome).c_str());

  // A fresh incarnation of the same stable publisher may act again after it
  // supplies fresh evidence.
  PublisherHandle reincarnation;
  FR_CHECK_MSG(reincarnation.start({"--name", "E", "--publisher", ephemeral_publisher, "--count", "0",
                                    "--revalidate", ephemeral_record, "--hold-ms", "60000"},
                                   second.port, directory, "reincarnation", error),
               error.c_str());
  std::string reincarnation_report;
  FR_CHECK_MSG(reincarnation.await_report("status=revalidated", reincarnation_report), "the reincarnated publisher produced no report");
  FR_CHECK_MSG(report_value(reincarnation_report, "revalidated[" + ephemeral_record + "]") == "committed",
               "the reincarnated publisher must be able to revalidate with fresh evidence");
  FR_CHECK_MSG(observer.lookup(ephemeral_record, lifecycle, generation, error), error.c_str());
  FR_CHECK_EQ(lifecycle, fabric_registry::Lifecycle::Current);

  // Fresh registrations proceed after recovery.
  PublisherHandle after;
  FR_CHECK_MSG(after.start({"--name", "F", "--count", "1", "--serial-prefix", "F", "--hold-ms", "60000"}, second.port,
                           directory, "after", error),
               error.c_str());
  std::string after_report;
  FR_CHECK_MSG(after.await_report("record[0]=", after_report), "the post-recovery publisher produced no report");
  FR_CHECK_EQ(report_value(after_report, "registered[0]"), std::string("committed"));

  observer.client->detach();
  reincarnation.kill_hard();
  after.kill_hard();
  second.stop_gracefully();

  fabric_registry::Registry loaded;
  fabric_registry::RecoveryReport report;
  FR_CHECK_MSG(loaded.load(second.state_path, report).committed(), "the recovered state did not load");
  std::string rendered;
  FR_CHECK_MSG(loaded.validate_state(rendered).committed(), ("state inconsistent: " + rendered).c_str());
  // Canonical identity survived; the identifiers are byte for byte the ones the
  // first coordinator issued.
  std::shared_ptr<const fabric_registry::EntityRecord> record;
  const std::optional<fabric_registry::CanonicalId> durable_id =
      fabric_registry::CanonicalId::parse(durable_record);
  FR_CHECK(durable_id.has_value());
  FR_CHECK_MSG(loaded.lookup(*durable_id, record).committed(), "canonical identity did not survive the restart");
  frtest::remove_directory(directory);
}

FR_TEST_CASE(multiprocess, coordinator_killed_during_persistence) {
  FR_CHECK_MSG(!coordinator_path().empty(), "the coordinator executable path was not supplied");
  const std::string directory = temporary_root("persist");
  FR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");

  std::size_t previous_records = 0;
  for (int round = 0; round < 6; ++round) {
    std::string error;
    CoordinatorHandle coordinator;
    FR_CHECK_MSG(coordinator.start(directory, "state.bin", true, error), error.c_str());
    PublisherHandle publisher;
    FR_CHECK_MSG(publisher.start({"--name", "K" + std::to_string(round), "--count", "40", "--serial-prefix",
                                  "K" + std::to_string(round), "--hold-ms", "120000"},
                                 coordinator.port, directory, "k" + std::to_string(round), error),
                 error.c_str());
    frtest::sleep_milliseconds(20 + round * 25);
    coordinator.kill_hard();
    publisher.kill_hard();

    // The authoritative file must be either absent (nothing committed yet) or a
    // complete, self-consistent state. A partially written file can never be
    // observed because replacement is atomic.
    const std::string state_path = coordinator.state_path;
    std::error_code exists_error;
    if (!std::filesystem::exists(state_path, exists_error)) {
      continue;
    }
    fabric_registry::Registry loaded;
    fabric_registry::RecoveryReport report;
    const fabric_registry::Outcome outcome = loaded.load(state_path, report);
    FR_CHECK_MSG(outcome.committed(),
                 ("round " + std::to_string(round) + ": the state file did not load: " + outcome.message).c_str());
    std::string rendered;
    FR_CHECK_MSG(loaded.validate_state(rendered).committed(),
                 ("round " + std::to_string(round) + ": state inconsistent: " + rendered).c_str());
    const std::size_t records = loaded.stats().entities;
    FR_CHECK_MSG(records >= previous_records, "the record count went backwards across a crash");
    FR_CHECK_MSG(records <= static_cast<std::size_t>(40) * static_cast<std::size_t>(round + 1),
                 "the record count exceeds everything that could have been committed");
    previous_records = records;
    // Loading removes the leftover temporary file; none may remain.
    const std::filesystem::path temporary = fabric_registry::persistence::temporary_path_for(state_path);
    FR_CHECK_MSG(!std::filesystem::exists(temporary, exists_error),
                 "a temporary state file was left behind after recovery");
  }
  frtest::remove_directory(directory);
}

FR_TEST_CASE(multiprocess, malformed_and_abrupt_sessions_do_not_break_the_coordinator) {
  FR_CHECK_MSG(!coordinator_path().empty(), "the coordinator executable path was not supplied");
  const std::string directory = temporary_root("sessions");
  FR_CHECK_MSG(!directory.empty(), "the temporary directory could not be created");

  std::string error;
  CoordinatorHandle coordinator;
  FR_CHECK_MSG(coordinator.start(directory, "state.bin", false, error), error.c_str());

  const auto send_raw = [](fabric_registry::Socket& socket, const std::vector<std::uint8_t>& bytes) {
#if defined(_WIN32)
    const SOCKET native = static_cast<SOCKET>(socket.native_handle());
    return ::send(native, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0) >= 0;
#else
    const int native = static_cast<int>(socket.native_handle());
    return ::send(native, bytes.data(), bytes.size(), 0) >= 0;
#endif
  };

  const fabric_registry::FrameLimits limits;
  // A structurally valid frame whose checksum is wrong.
  std::vector<std::uint8_t> corrupted =
      fabric_registry::encode_frame(fabric_registry::MessageType::StatsRequest, 7, {}, limits, error);
  FR_CHECK_MSG(!corrupted.empty(), error.c_str());
  corrupted.back() ^= 0xFFu;
  // A frame declaring a payload far above the bound.
  std::vector<std::uint8_t> oversized(24, 0);
  oversized[0] = 'F';
  oversized[1] = 'R';
  oversized[2] = 'G';
  oversized[3] = '1';
  oversized[4] = 1;
  oversized[6] = static_cast<std::uint8_t>(fabric_registry::MessageType::StatsRequest);
  oversized[20] = 0xFF;
  oversized[21] = 0xFF;
  oversized[22] = 0xFF;
  oversized[23] = 0x7F;
  // A frame with an unknown message type.
  std::vector<std::uint8_t> unknown(24, 0);
  unknown[0] = 'F';
  unknown[1] = 'R';
  unknown[2] = 'G';
  unknown[3] = '1';
  unknown[4] = 1;
  unknown[6] = 0xEE;
  unknown[7] = 0xEE;
  // Garbage.
  std::vector<std::uint8_t> garbage{'n', 'o', 't', 'a', 'f', 'r', 'a', 'm', 'e'};

  for (const std::vector<std::uint8_t>& payload : {corrupted, oversized, unknown, garbage}) {
    std::optional<fabric_registry::Socket> socket =
        fabric_registry::connect_to(coordinator.endpoint(), std::chrono::milliseconds(5000), error);
    FR_CHECK_MSG(socket.has_value(), error.c_str());
    send_raw(*socket, payload);
    socket->shutdown_both();
    socket->close();
  }

  // Fifty abrupt connect/close cycles with no handshake at all.
  for (int index = 0; index < 50; ++index) {
    std::optional<fabric_registry::Socket> socket =
        fabric_registry::connect_to(coordinator.endpoint(), std::chrono::milliseconds(5000), error);
    FR_CHECK_MSG(socket.has_value(), error.c_str());
    socket->close();
  }

  // The coordinator must still serve a well-behaved publisher.
  Observer observer;
  FR_CHECK_MSG(observer.attach(coordinator.port, error), error.c_str());
  fabric_registry::RegistryStats stats;
  FR_CHECK_MSG(observer.stats(stats), "the coordinator stopped serving after malformed sessions");
  FR_CHECK_EQ(stats.entities, static_cast<std::size_t>(0));

  PublisherHandle publisher;
  FR_CHECK_MSG(publisher.start({"--name", "S", "--count", "1", "--serial-prefix", "S", "--hold-ms", "30000"},
                               coordinator.port, directory, "s", error),
               error.c_str());
  std::string report;
  FR_CHECK_MSG(publisher.await_report("record[0]=", report), "the publisher produced no report");
  FR_CHECK_EQ(report_value(report, "registered[0]"), std::string("committed"));

  observer.client->detach();
  publisher.kill_hard();
  coordinator.stop_gracefully();
  frtest::remove_directory(directory);
}


