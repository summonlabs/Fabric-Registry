// Fabric Registry — downstream package consumer.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Built as a standalone project against an installed Fabric Registry package:
// it includes the public header by its installed name, links the exported
// target and proves that the library actually linked and ran.

#include <exception>
#include <iostream>

#include <fabric_registry/registry.hpp>
#include <fabric_registry/version.hpp>

int main() {
  std::cout << "fabric_registry " << fabric_registry::version_string() << "\n";

  try {
    fabric_registry::Registry registry{};
    std::cout << "registry epoch: " << registry.epoch().to_string() << "\n";
  } catch (const std::exception& error) {
    std::cerr << "registry construction failed: " << error.what() << "\n";
    return 1;
  }

  return 0;
}
