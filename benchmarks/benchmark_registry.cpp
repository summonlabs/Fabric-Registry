// Fabric Registry — benchmarks for the registry engine.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every measurement here reports *completed* operations: the clock starts after
// a warmup pass and stops only once the whole body has returned, and the count
// that is printed is the number of operations that actually completed. No number
// in the output is an enqueue rate, a projection or the latency of a submission.
// Each line prints the workload, the measured count and the wall-clock time next
// to the rate, so the claim can be checked by reading it; a workload that could
// not complete every requested operation says so on stderr.
//
// There are no performance assertions and no thresholds: the program measures
// and reports, and always exits zero.
//
//   fabric-registry-benchmarks [--quick] [--json]
//
//   --quick  run only the 1k sizes
//   --json   print one JSON object per measurement with the keys
//            workload, n, seconds and ops_per_second
//
// The 100k sizes are skipped automatically in a build without NDEBUG.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "fabric_registry/fabric_registry.hpp"

namespace fr = fabric_registry;

namespace {

#if defined(NDEBUG)
constexpr bool kReleaseBuild = true;
#else
constexpr bool kReleaseBuild = false;
#endif

/// How many operations each workload requests. The reported count is the number
/// of those that completed.
constexpr std::size_t kIncrementalRegistrations = 1000;
constexpr std::size_t kLookupOperations = 100000;
constexpr std::size_t kReconcileOperations = 20000;
constexpr std::size_t kPersistenceOperations = 5;
constexpr std::size_t kWarmupRegistrations = 128;

struct Measurement {
  std::string workload;
  /// Operations that completed, which is what the rate is computed from.
  std::size_t operations{0};
  double seconds{0.0};
  double ops_per_second{0.0};
  /// Requested operations that did not complete. Reported on stderr only.
  std::size_t rejected{0};
};

/// The whole timing surface of this program: one steady clock, started when the
/// caller says so and read once, after the work has completed.
class Stopwatch {
public:
  void start() noexcept { begin_ = std::chrono::steady_clock::now(); }

  double elapsed_seconds() const noexcept {
    const std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(end - begin_).count();
  }

private:
  std::chrono::steady_clock::time_point begin_{};
};

/// Runs the warmup pass first, then times \`body\` to completion. \`body\` returns
/// the number of operations it completed; the rate is computed from that count
/// and the wall-clock time of the measured pass.
template <class Warmup, class Body>
Measurement measure(const std::string& workload, std::size_t requested, Warmup warmup, Body body) {
  warmup();
  Stopwatch watch;
  watch.start();
  const std::size_t completed = body();
  const double seconds = watch.elapsed_seconds();
  Measurement measurement;
  measurement.workload = workload;
  measurement.operations = completed;
  measurement.seconds = seconds;
  measurement.ops_per_second = seconds > 0.0 ? static_cast<double>(completed) / seconds : 0.0;
  measurement.rejected = requested > completed ? requested - completed : 0;
  return measurement;
}

void report(const Measurement& measurement, bool json_output) {
  if (json_output) {
    std::printf("{\"workload\":\"%s\",\"n\":%llu,\"seconds\":%.6f,\"ops_per_second\":%.4g}\n",
                measurement.workload.c_str(),
                static_cast<unsigned long long>(measurement.operations),
                measurement.seconds,
                measurement.ops_per_second);
  } else {
    std::printf("%-32s n=%-9llu %9.3f s %14.4g ops/s\n",
                measurement.workload.c_str(),
                static_cast<unsigned long long>(measurement.operations),
                measurement.seconds,
                measurement.ops_per_second);
  }
  if (measurement.rejected != 0) {
    std::fprintf(stderr,
                 "benchmark warning: %s completed %llu of %llu requested operations\n",
                 measurement.workload.c_str(),
                 static_cast<unsigned long long>(measurement.operations),
                 static_cast<unsigned long long>(measurement.operations + measurement.rejected));
  }
}

std::string size_tag(std::size_t size) {
  if (size % 1000 == 0) {
    return std::to_string(size / 1000) + "k";
  }
  return std::to_string(size);
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

/// A deterministic, non-null, unique attempt identifier for one operation.
fr::RegistrationId attempt_for(std::size_t index) {
  fr::IdBytes bytes{};
  for (std::size_t byte = 0; byte < 8; ++byte) {
    bytes[byte] = static_cast<std::uint8_t>((index >> (8 * byte)) & 0xFFu);
  }
  bytes[15] = 0x5Au;
  return fr::RegistrationId::from_bytes(bytes);
}

fr::Provenance benchmark_provenance() {
  fr::Provenance provenance;
  provenance.source = fr::ObservationSource::DeviceAgent;
  provenance.validity_class = fr::ProvenanceClass::Real;
  provenance.mechanism = "benchmark";
  provenance.source_identity = "benchmark-host";
  return provenance;
}

fr::IdentityFact serial_fact_for(std::size_t index) {
  fr::IdentityFact fact;
  fact.kind = fr::IdentityFactKind::SerialNumber;
  fact.scope = "vendor:0x15b3/product:0x1017";
  fact.value = "bench-serial-" + std::to_string(index);
  return fact;
}

/// Builds the registration a workload performs at \`index\`.
fr::RegisterEntityRequest registration_for(fr::Registry& registry, std::size_t index, bool with_alias) {
  fr::RegisterEntityRequest request;
  request.attempt = attempt_for(index);
  request.authority = registry.local_authority();
  request.entity_class = fr::EntityClass::Switch;
  request.derivation_namespace = "benchmark/namespace";
  request.friendly_name = "bench-switch-" + std::to_string(index);
  request.facts.push_back(serial_fact_for(index));
  request.provenance = benchmark_provenance();
  request.evidence_class = fr::EvidenceClass::DurableAuthority;
  request.admission = fr::AdmissionMode::RequireCurrent;
  if (with_alias) {
    fr::AliasInput alias;
    alias.alias_namespace = fr::AliasNamespace::ExternalCmdbId;
    alias.value = "bench-cmdb-" + std::to_string(index);
    request.aliases.push_back(alias);
  }
  return request;
}

/// Registers one entity, returning true when it committed.
bool register_at(fr::Registry& registry, std::size_t index, bool with_alias) {
  return registry.register_entity(registration_for(registry, index, with_alias)).committed();
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct Fixture {
  std::unique_ptr<fr::Registry> registry;
  std::vector<fr::CanonicalId> ids;
  std::vector<std::string> serials;
  std::size_t rejected{0};
};

/// Builds a registry holding exactly \`size\` current records, each with one
/// unique alias. Building is deliberately outside every measurement.
Fixture build_fixture(std::size_t size) {
  Fixture fixture;
  fixture.registry = std::make_unique<fr::Registry>();
  fixture.ids.reserve(size);
  fixture.serials.reserve(size);
  for (std::size_t index = 0; index < size; ++index) {
    const fr::Outcome outcome = fixture.registry->register_entity(registration_for(*fixture.registry, index, true));
    if (!outcome.committed() || !outcome.record.has_value()) {
      ++fixture.rejected;
      continue;
    }
    fixture.ids.push_back(*outcome.record);
    fixture.serials.push_back("bench-serial-" + std::to_string(index));
  }
  return fixture;
}

// ---------------------------------------------------------------------------
// Workloads
// ---------------------------------------------------------------------------

/// Bulk registration of \`size\` entities into an empty registry. The registry
/// that results is handed back so the incremental workload can continue on it.
Measurement benchmark_bulk_registration(std::size_t size, std::unique_ptr<fr::Registry>& incremental_base) {
  std::unique_ptr<fr::Registry> registry = std::make_unique<fr::Registry>();
  Measurement measurement = measure(
      "register_bulk_" + size_tag(size),
      size,
      [] {
        // Warmup on a throwaway registry: the allocator, the identity derivation
        // path and the codecs are all exercised before the clock starts.
        fr::Registry warmup;
        for (std::size_t index = 0; index < kWarmupRegistrations; ++index) {
          (void)register_at(warmup, index, false);
        }
      },
      [&registry, size] {
        std::size_t completed = 0;
        for (std::size_t index = 0; index < size; ++index) {
          if (register_at(*registry, index, false)) {
            ++completed;
          }
        }
        return completed;
      });
  incremental_base = std::move(registry);
  return measurement;
}

/// One-at-a-time registration on a registry that already holds \`base\` records.
Measurement benchmark_incremental_registration(fr::Registry& registry) {
  const std::string workload = "register_incremental_base_" + size_tag(registry.stats().entities);
  const std::size_t base = registry.stats().entities;
  return measure(
      workload,
      kIncrementalRegistrations,
      [] {
        fr::Registry warmup;
        for (std::size_t index = 0; index < kWarmupRegistrations; ++index) {
          (void)register_at(warmup, index, false);
        }
      },
      [&registry, base] {
        std::size_t completed = 0;
        for (std::size_t step = 0; step < kIncrementalRegistrations; ++step) {
          if (register_at(registry, base + step, false)) {
            ++completed;
          }
        }
        return completed;
      });
}

/// Canonical and alias lookups over the fixture records.
std::vector<Measurement> benchmark_lookups(const Fixture& fixture) {
  std::vector<Measurement> results;
  const std::string tag = size_tag(fixture.ids.size());
  fr::AliasKey key;
  key.alias_namespace = fr::AliasNamespace::ExternalCmdbId;

  results.push_back(measure(
      "lookup_canonical_" + tag,
      kLookupOperations,
      [&fixture] {
        std::shared_ptr<const fr::EntityRecord> record;
        for (std::size_t index = 0; index < 1000; ++index) {
          (void)fixture.registry->lookup(fixture.ids[index % fixture.ids.size()], record);
        }
      },
      [&fixture] {
        std::size_t completed = 0;
        std::shared_ptr<const fr::EntityRecord> record;
        for (std::size_t index = 0; index < kLookupOperations; ++index) {
          const fr::CanonicalId& target = fixture.ids[index % fixture.ids.size()];
          if (fixture.registry->lookup(target, record).committed() && record != nullptr) {
            ++completed;
          }
        }
        return completed;
      }));

  results.push_back(measure(
      "lookup_alias_" + tag,
      kLookupOperations,
      [&fixture, &key] {
        std::shared_ptr<const fr::EntityRecord> record;
        for (std::size_t index = 0; index < 1000; ++index) {
          fr::AliasKey warmup_key = key;
          warmup_key.value = "bench-cmdb-" + std::to_string(index % fixture.serials.size());
          (void)fixture.registry->lookup_by_alias(warmup_key, record);
        }
      },
      [&fixture, &key] {
        std::size_t completed = 0;
        std::shared_ptr<const fr::EntityRecord> record;
        for (std::size_t index = 0; index < kLookupOperations; ++index) {
          fr::AliasKey probe = key;
          probe.value = "bench-cmdb-" + std::to_string(index % fixture.serials.size());
          if (fixture.registry->lookup_by_alias(probe, record).committed() && record != nullptr) {
            ++completed;
          }
        }
        return completed;
      }));
  return results;
}

/// Reconciliation lookups: a full observation is matched against the registry.
Measurement benchmark_reconciliation(const Fixture& fixture) {
  return measure(
      "reconcile_lookup_" + size_tag(fixture.ids.size()),
      kReconcileOperations,
      [&fixture] {
        fr::ReconcileObservationRequest warmup;
        warmup.attempt = attempt_for(1);
        warmup.entity_class = fr::EntityClass::Switch;
        warmup.facts.push_back(serial_fact_for(0));
        warmup.provenance = benchmark_provenance();
        (void)fixture.registry->reconcile_observation(warmup);
      },
      [&fixture] {
        std::size_t completed = 0;
        for (std::size_t index = 0; index < kReconcileOperations; ++index) {
          const std::size_t position = index % fixture.serials.size();
          fr::ReconcileObservationRequest request;
          request.attempt = attempt_for(1u + position);
          request.entity_class = fr::EntityClass::Switch;
          request.facts.push_back(serial_fact_for(position));
          request.provenance = benchmark_provenance();
          const fr::ReconcileResult result = fixture.registry->reconcile_observation(request);
          if (result.outcome.committed() && result.detail.matched.has_value()) {
            ++completed;
          }
        }
        return completed;
      });
}

/// Snapshot construction, including the canonical state digest it computes.
Measurement benchmark_snapshot(const Fixture& fixture) {
  const std::size_t count = fixture.ids.size() >= 100000 ? 2u : (fixture.ids.size() >= 10000 ? 20u : 200u);
  return measure(
      "snapshot_" + size_tag(fixture.ids.size()),
      count,
      [&fixture] {
        const fr::Snapshot warmup = fixture.registry->snapshot();
        (void)warmup.size();
      },
      [&fixture, count] {
        std::size_t completed = 0;
        for (std::size_t index = 0; index < count; ++index) {
          const fr::Snapshot snapshot = fixture.registry->snapshot();
          if (snapshot.size() == fixture.ids.size()) {
            ++completed;
          }
        }
        return completed;
      });
}

/// The transactional save and the recovering load, both measured to completion.
std::vector<Measurement> benchmark_persistence(const Fixture& fixture, const std::filesystem::path& state_path) {
  std::vector<Measurement> results;
  const std::string tag = size_tag(fixture.ids.size());
  results.push_back(measure(
      "persistence_save_" + tag,
      kPersistenceOperations,
      [&fixture, &state_path] { (void)fixture.registry->save(state_path, false); },
      [&fixture, &state_path] {
        std::size_t completed = 0;
        for (std::size_t index = 0; index < kPersistenceOperations; ++index) {
          if (fixture.registry->save(state_path, false).committed()) {
            ++completed;
          }
        }
        return completed;
      }));

  results.push_back(measure(
      "persistence_load_" + tag,
      kPersistenceOperations,
      [&state_path] {
        fr::Registry warmup;
        fr::RecoveryReport report;
        (void)warmup.load(state_path, report);
      },
      [&state_path] {
        std::size_t completed = 0;
        for (std::size_t index = 0; index < kPersistenceOperations; ++index) {
          fr::Registry loaded;
          fr::RecoveryReport report;
          if (loaded.load(state_path, report).committed()) {
            ++completed;
          }
        }
        return completed;
      }));
  return results;
}

} // namespace

int main(int argc, char** argv) {
  bool quick = false;
  bool json_output = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument = argv[index] != nullptr ? std::string_view(argv[index]) : std::string_view();
    if (argument == "--quick") {
      quick = true;
    } else if (argument == "--json") {
      json_output = true;
    } else if (!argument.empty()) {
      std::fprintf(stderr, "benchmark: ignoring unknown argument '%s'\n", std::string(argument).c_str());
    }
  }

  std::vector<std::size_t> sizes;
  sizes.push_back(1000);
  if (!quick) {
    sizes.push_back(10000);
    if (kReleaseBuild) {
      sizes.push_back(100000);
    }
  }

  if (!json_output) {
    std::printf("fabric-registry benchmarks: %s build, sizes", kReleaseBuild ? "release" : "debug");
    for (const std::size_t size : sizes) {
      std::printf(" %s", size_tag(size).c_str());
    }
    std::printf(", every rate counts completed operations\n");
  } else {
    std::fprintf(stderr,
                 "fabric-registry benchmarks: %s build, %zu size(s), json output\n",
                 kReleaseBuild ? "release" : "debug",
                 sizes.size());
  }
  if (!kReleaseBuild) {
    std::fprintf(stderr, "benchmark note: the 100k sizes are skipped because NDEBUG is not defined\n");
  }

  const std::filesystem::path state_path =
      std::filesystem::temp_directory_path() / "fabric-registry-benchmark-state.bin";

  for (const std::size_t size : sizes) {
    std::unique_ptr<fr::Registry> incremental_base;
    report(benchmark_bulk_registration(size, incremental_base), json_output);
    if (incremental_base != nullptr) {
      report(benchmark_incremental_registration(*incremental_base), json_output);
    }
  }

  for (const std::size_t size : sizes) {
    Fixture fixture = build_fixture(size);
    if (fixture.rejected != 0) {
      std::fprintf(stderr, "benchmark warning: %zu fixture registrations were rejected\n", fixture.rejected);
    }
    if (fixture.ids.empty()) {
      continue;
    }
    for (const Measurement& measurement : benchmark_lookups(fixture)) {
      report(measurement, json_output);
    }
    report(benchmark_reconciliation(fixture), json_output);
    report(benchmark_snapshot(fixture), json_output);
    if (size <= 10000) {
      for (const Measurement& measurement : benchmark_persistence(fixture, state_path)) {
        report(measurement, json_output);
      }
    }
  }

  std::error_code error;
  std::filesystem::remove(state_path, error);
  std::filesystem::remove(fr::persistence::temporary_path_for(state_path), error);
  return 0;
}
