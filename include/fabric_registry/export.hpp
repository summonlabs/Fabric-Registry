// Fabric Registry — canonical identity and registration runtime for the
// Distributed Fabric Infrastructure stack.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef FABRIC_REGISTRY_EXPORT_HPP
#define FABRIC_REGISTRY_EXPORT_HPP

// FABRIC_REGISTRY_API decorates every symbol that crosses the library
// boundary. The library builds and installs as a static library by default;
// shared builds are supported and use the same decoration.
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(FABRIC_REGISTRY_BUILD_SHARED)
#define FABRIC_REGISTRY_API __declspec(dllexport)
#elif defined(FABRIC_REGISTRY_USE_SHARED)
#define FABRIC_REGISTRY_API __declspec(dllimport)
#else
#define FABRIC_REGISTRY_API
#endif
#else
#if defined(FABRIC_REGISTRY_BUILD_SHARED) || defined(FABRIC_REGISTRY_USE_SHARED)
#define FABRIC_REGISTRY_API __attribute__((visibility("default")))
#else
#define FABRIC_REGISTRY_API
#endif
#endif

// Marks APIs that are part of the supported 1.x surface. Nothing in this
// library is marked experimental: every declaration documented in the README
// is implemented and exercised by the test suite.
#define FABRIC_REGISTRY_PUBLIC FABRIC_REGISTRY_API

#endif // FABRIC_REGISTRY_EXPORT_HPP
