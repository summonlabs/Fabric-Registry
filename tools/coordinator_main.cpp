// Fabric Registry — coordinator executable.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

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

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "fabric_registry/coordinator.hpp"
#include "fabric_registry/version.hpp"

namespace {

struct Options {
  std::string listen{"127.0.0.1:0"};
  std::string state_path;
  std::string ready_file;
  std::string server_name{"fabric-registry-coordinator"};
  std::string pid_file;
  long long run_ms{0};
  bool persist{true};
  bool quiet{false};
  bool help{false};
};

void print_usage() {
  std::cout << "fabric-registry-coordinator " << fabric_registry::version_string() << "\n"
            << "usage: fabric-registry-coordinator [options]\n"
            << "  --listen HOST:PORT   address to serve on (default 127.0.0.1:0, an ephemeral port)\n"
            << "  --state PATH         durable state file; the registry is recovered from it at start\n"
            << "  --ready-file PATH    write the bound port to PATH once the socket is listening\n"
            << "  --pid-file PATH      write the process id to PATH once the socket is listening\n"
            << "  --run-ms N           stop gracefully after N milliseconds (0 runs until killed)\n"
            << "  --no-persist         keep state in memory only; --state is then only read at start\n"
            << "  --quiet              suppress the startup banner\n"
            << "  --help               print this message\n";
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
    if (argument == "--help" || argument == "-h") {
      options.help = true;
    } else if (argument == "--listen") {
      if (!next(options.listen)) {
        return false;
      }
    } else if (argument == "--state") {
      if (!next(options.state_path)) {
        return false;
      }
    } else if (argument == "--ready-file") {
      if (!next(options.ready_file)) {
        return false;
      }
    } else if (argument == "--pid-file") {
      if (!next(options.pid_file)) {
        return false;
      }
    } else if (argument == "--server-name") {
      if (!next(options.server_name)) {
        return false;
      }
    } else if (argument == "--run-ms") {
      std::string value;
      if (!next(value)) {
        return false;
      }
      options.run_ms = std::strtoll(value.c_str(), nullptr, 10);
      if (options.run_ms < 0) {
        error = "--run-ms must not be negative";
        return false;
      }
    } else if (argument == "--no-persist") {
      options.persist = false;
    } else if (argument == "--quiet") {
      options.quiet = true;
    } else {
      error = std::string("unknown argument: ") + std::string(argument);
      return false;
    }
  }
  return true;
}

long long current_process_id() {
#if defined(_WIN32)
  return static_cast<long long>(::_getpid());
#else
  return static_cast<long long>(::getpid());
#endif
}

bool write_text_file(const std::string& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream << text;
  stream.flush();
  return static_cast<bool>(stream);
}

} // namespace

int main(int argc, char** argv) {
  Options options;
  std::string error;
  if (!parse_options(argc, argv, options, error)) {
    std::cerr << "fabric-registry-coordinator: " << error << "\n";
    print_usage();
    return 2;
  }
  if (options.help) {
    print_usage();
    return 0;
  }

  const std::optional<fabric_registry::Endpoint> endpoint = fabric_registry::Endpoint::parse(options.listen);
  if (!endpoint.has_value()) {
    std::cerr << "fabric-registry-coordinator: --listen is not a valid HOST:PORT endpoint\n";
    return 2;
  }

  fabric_registry::CoordinatorOptions coordinator_options;
  coordinator_options.listen = *endpoint;
  coordinator_options.state_path = options.state_path;
  coordinator_options.persist_on_commit = options.persist && !options.state_path.empty();
  coordinator_options.server_name = options.server_name;

  const fabric_registry::ValidationResult validation = coordinator_options.validate();
  if (!validation) {
    std::cerr << "fabric-registry-coordinator: " << validation.message << "\n";
    return 2;
  }

  std::unique_ptr<fabric_registry::Coordinator> coordinator =
      fabric_registry::Coordinator::start(coordinator_options, error);
  if (!coordinator) {
    std::cerr << "fabric-registry-coordinator: " << error << "\n";
    return 1;
  }

  const std::string port_text = std::to_string(coordinator->port());
  if (!options.ready_file.empty() && !write_text_file(options.ready_file, port_text + "\n")) {
    std::cerr << "fabric-registry-coordinator: the ready file could not be written\n";
    coordinator->stop();
    return 1;
  }
  if (!options.pid_file.empty() && !write_text_file(options.pid_file, std::to_string(current_process_id()) + "\n")) {
    std::cerr << "fabric-registry-coordinator: the pid file could not be written\n";
    coordinator->stop();
    return 1;
  }

  if (!options.quiet) {
    std::cout << "fabric-registry-coordinator " << fabric_registry::version_string() << "\n";
    std::cout << "listening " << coordinator->endpoint().to_string() << "\n";
    std::cout << "coordinator-epoch " << coordinator->epoch().to_string() << "\n";
    std::cout << "state " << (options.state_path.empty() ? std::string("(memory only)") : options.state_path) << "\n";
    const fabric_registry::RecoveryReport& recovery = coordinator->recovery_report();
    if (recovery.records_loaded != 0 || recovery.publishers_fenced != 0) {
      std::cout << "recovered records " << recovery.records_loaded << " demoted " << recovery.records_demoted
                << " publishers-fenced " << recovery.publishers_fenced << "\n";
    }
    std::cout.flush();
  }

  if (options.run_ms > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(options.run_ms));
  } else {
    // Run until the controlling process closes standard input or terminates this
    // process. This keeps a foreground invocation alive without any timeout.
    char buffer[256];
    while (std::fgets(buffer, sizeof(buffer), stdin) != nullptr) {
    }
  }

  coordinator->stop();
  if (!options.quiet) {
    const fabric_registry::RegistryStats stats = coordinator->stats();
    std::cout << "stopped entities " << stats.entities << " generation " << stats.generation.to_string()
              << " epoch " << stats.epoch.to_string() << "\n";
    std::cout.flush();
  }
  return 0;
}
