# Fabric Registry — build, test, install and packaging rules.
#
# Copyright 2026 Summon Software Labs.
# Licensed under the Apache License, Version 2.0.
#
# Everything here is target based: no directory-global flags are set, so the
# library, the tools, the benchmarks and the tests each carry exactly the
# options they need, and nothing this project uses for itself can leak into
# the installed package.

cmake_minimum_required(VERSION 3.20)

project(FabricRegistry
        VERSION 1.0.0
        DESCRIPTION "Canonical identity and registration runtime for the Distributed Fabric Infrastructure stack"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(BUILD_SHARED_LIBS "Build fabric_registry as a shared library instead of a static one" OFF)

option(FABRIC_REGISTRY_BUILD_TESTS "Build the Fabric Registry test suite" ON)
option(FABRIC_REGISTRY_BUILD_TOOLS "Build the Fabric Registry command line tools" ON)
option(FABRIC_REGISTRY_BUILD_EXAMPLES "Build the Fabric Registry example programs" ON)
option(FABRIC_REGISTRY_BUILD_BENCHMARKS "Build the Fabric Registry benchmarks" ON)
option(FABRIC_REGISTRY_WARNINGS_AS_ERRORS "Treat every compiler warning as an error" ON)
option(FABRIC_REGISTRY_SANITIZERS "Build with AddressSanitizer, and UndefinedBehaviorSanitizer on GCC and Clang" OFF)
option(FABRIC_REGISTRY_ANALYZE "Build with the MSVC static analyzer" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CheckCXXCompilerFlag)
include(CTest)

set(FABRIC_REGISTRY_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/FabricRegistry"
    CACHE STRING "Install destination of the Fabric Registry CMake package files")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Resolves a declared source list against the source tree.
#
# CMake refuses to generate a build system for a target whose source file does
# not exist, and the implementation is written incrementally, so a declared
# translation unit may not be on disk yet. Those entries are marked GENERATED
# (which tells CMake not to look for them now) and resolved to their final
# absolute source-tree path, so that the same build tree compiles the file as
# soon as it lands without being reconfigured. Declared files that are present
# are used exactly as written, and every missing file is reported.
function(fabric_registry_sources out_var)
  set(resolved "")
  set(pending "")
  foreach(source IN LISTS ARGN)
    if(IS_ABSOLUTE "${source}")
      set(path "${source}")
    else()
      set(path "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    endif()
    if(EXISTS "${path}")
      list(APPEND resolved "${source}")
    else()
      set_source_files_properties("${path}" PROPERTIES GENERATED TRUE)
      list(APPEND resolved "${path}")
      list(APPEND pending "${source}")
    endif()
  endforeach()
  if(pending)
    list(JOIN pending ", " pending_text)
    message(STATUS "FabricRegistry: declared but not on disk yet (compiled once present): ${pending_text}")
  endif()
  set(${out_var} "${resolved}" PARENT_SCOPE)
endfunction()

# Applies the project build policy to one target. Every entry is PRIVATE, so
# none of it is part of the installed package.
function(fabric_registry_configure_target target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    if(FABRIC_REGISTRY_WARNINGS_AS_ERRORS AND NOT FABRIC_REGISTRY_ANALYZE)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    target_compile_definitions(${target} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:/RTC1>)
    target_compile_definitions(${target} PRIVATE $<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=2>)
    target_compile_options(${target} PRIVATE
      $<$<CONFIG:Release>:/O2>
      $<$<CONFIG:Release>:/Gy>
      $<$<CONFIG:Release>:/Gw>)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    if(FABRIC_REGISTRY_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  # A static-analysis run reports through /analyze:WX-; /WX is deliberately not
  # layered on top of it (see the guard above).
  if(MSVC AND FABRIC_REGISTRY_ANALYZE)
    target_compile_options(${target} PRIVATE /analyze /analyze:WX-)
  endif()
  if(FABRIC_REGISTRY_SANITIZERS)
    target_compile_options(${target} PRIVATE ${FABRIC_REGISTRY_SANITIZER_COMPILE_OPTIONS})
    target_link_options(${target} PRIVATE ${FABRIC_REGISTRY_SANITIZER_LINK_OPTIONS})
  endif()
endfunction()

# Adds one project executable: source resolution, linkage against the library
# and the project build policy.
function(fabric_registry_add_executable target)
  fabric_registry_sources(sources ${ARGN})
  add_executable(${target} ${sources})
  target_link_libraries(${target} PRIVATE fabric_registry)
  fabric_registry_configure_target(${target})
endfunction()

# ---------------------------------------------------------------------------
# Sanitizers and static analysis
# ---------------------------------------------------------------------------

if(FABRIC_REGISTRY_SANITIZERS)
  if(MSVC)
    check_cxx_compiler_flag("/fsanitize=address" FABRIC_REGISTRY_COMPILER_HAS_ASAN)
    if(NOT FABRIC_REGISTRY_COMPILER_HAS_ASAN)
      message(FATAL_ERROR
        "FABRIC_REGISTRY_SANITIZERS=ON cannot be used with ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION}: a program built with /fsanitize=address does not "
        "compile and link here. Either the toolset predates AddressSanitizer support "
        "(Visual Studio 2019 16.9) or the optional C++ AddressSanitizer component is not "
        "installed in this Visual Studio installation, in which case the link fails with "
        "LNK1104 for clang_rt.asan_dynamic_runtime_thunk-x86_64.lib. Reconfigure with "
        "-DFABRIC_REGISTRY_SANITIZERS=OFF, install that component, or use a newer toolset.")
    endif()
    set(FABRIC_REGISTRY_SANITIZER_COMPILE_OPTIONS /fsanitize=address /Zi)
    set(FABRIC_REGISTRY_SANITIZER_LINK_OPTIONS /fsanitize=address)
    message(STATUS "FabricRegistry: AddressSanitizer enabled (MSVC)")
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    check_cxx_compiler_flag("-fsanitize=address,undefined" FABRIC_REGISTRY_COMPILER_HAS_ASAN_UBSAN)
    if(NOT FABRIC_REGISTRY_COMPILER_HAS_ASAN_UBSAN)
      message(FATAL_ERROR
        "FABRIC_REGISTRY_SANITIZERS=ON cannot be used with ${CMAKE_CXX_COMPILER_ID} "
        "${CMAKE_CXX_COMPILER_VERSION}: a program built with -fsanitize=address,undefined "
        "does not compile and link here. Either the compiler predates these sanitizers or "
        "the sanitizer runtime (libasan/libubsan) is missing. Reconfigure with "
        "-DFABRIC_REGISTRY_SANITIZERS=OFF or install the sanitizer runtime.")
    endif()
    set(FABRIC_REGISTRY_SANITIZER_COMPILE_OPTIONS -fsanitize=address,undefined -fno-omit-frame-pointer)
    set(FABRIC_REGISTRY_SANITIZER_LINK_OPTIONS -fsanitize=address,undefined)
    message(STATUS "FabricRegistry: AddressSanitizer and UndefinedBehaviorSanitizer enabled")
  else()
    message(FATAL_ERROR
      "FABRIC_REGISTRY_SANITIZERS=ON is supported with MSVC (/fsanitize=address) and with "
      "GCC or Clang (-fsanitize=address,undefined); the configured compiler is "
      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}. "
      "Reconfigure with -DFABRIC_REGISTRY_SANITIZERS=OFF.")
  endif()
endif()

# ---------------------------------------------------------------------------
# fabric_registry
# ---------------------------------------------------------------------------

set(FABRIC_REGISTRY_SOURCES
  src/version.cpp
  src/entity_class.cpp
  src/ids.cpp
  src/limits.cpp
  src/codec.cpp
  src/digest.cpp
  src/identity.cpp
  src/errors.cpp
  src/entity.cpp
  src/serialization.cpp
  src/record_codec.cpp
  src/registry.cpp
  src/registry_mutations.cpp
  src/persistence.cpp
  src/frame.cpp
  src/transport.cpp
  src/coordinator.cpp
  src/publisher.cpp
  # Always compiled: defines DiscoveryReport::render() exactly once on every
  # platform.
  src/discovery_common.cpp)

# Exactly one discovery translation unit is compiled: the Windows platform
# implementation, or the portable stub everywhere else.
if(WIN32)
  list(APPEND FABRIC_REGISTRY_SOURCES src/discovery_windows.cpp)
else()
  list(APPEND FABRIC_REGISTRY_SOURCES src/discovery_stub.cpp)
endif()

fabric_registry_sources(FABRIC_REGISTRY_RESOLVED_SOURCES ${FABRIC_REGISTRY_SOURCES})

add_library(fabric_registry ${FABRIC_REGISTRY_RESOLVED_SOURCES})
add_library(SummonSoftwareLabs::FabricRegistry ALIAS fabric_registry)

set_target_properties(fabric_registry PROPERTIES
  # Consumers link SummonSoftwareLabs::FabricRegistry: the exported name is the
  # project name, the artifact keeps the library name.
  EXPORT_NAME FabricRegistry
  OUTPUT_NAME fabric_registry
  VERSION ${PROJECT_VERSION}
  SOVERSION 1
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON)

if(BUILD_SHARED_LIBS)
  # Symbols are hidden unless they carry FABRIC_REGISTRY_API, so the shared
  # library exports exactly its public surface.
  set_target_properties(fabric_registry PROPERTIES CXX_VISIBILITY_PRESET hidden)
  target_compile_definitions(fabric_registry PRIVATE FABRIC_REGISTRY_BUILD_SHARED)
  target_compile_definitions(fabric_registry INTERFACE FABRIC_REGISTRY_USE_SHARED)
endif()

target_include_directories(fabric_registry
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_features(fabric_registry PUBLIC cxx_std_20)

if(WIN32)
  # Winsock plus the system APIs the Windows discovery translation unit uses.
  # PRIVATE: none of this belongs to the public interface. A static consumer
  # still receives the entries through $<LINK_ONLY:...> in the exported target.
  target_link_libraries(fabric_registry PRIVATE ws2_32 iphlpapi setupapi ole32 bcrypt)
endif()

fabric_registry_configure_target(fabric_registry)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

if(FABRIC_REGISTRY_BUILD_TOOLS)
  fabric_registry_add_executable(fabric-registry-cli tools/registry_cli.cpp)
  fabric_registry_add_executable(fabric-registry-coordinator tools/coordinator_main.cpp)
  fabric_registry_add_executable(fabric-registry-publisher tools/publisher_main.cpp)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(FABRIC_REGISTRY_BUILD_EXAMPLES)
  # One self-contained program per file in examples/.
  file(GLOB FABRIC_REGISTRY_EXAMPLE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp")
  foreach(example_source IN LISTS FABRIC_REGISTRY_EXAMPLE_SOURCES)
    get_filename_component(example_stem "${example_source}" NAME_WE)
    fabric_registry_add_executable(fabric-registry-example-${example_stem} "${example_source}")
  endforeach()
  if(NOT FABRIC_REGISTRY_EXAMPLE_SOURCES)
    message(STATUS "FabricRegistry: FABRIC_REGISTRY_BUILD_EXAMPLES is ON but examples/ has no program yet")
  endif()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

if(FABRIC_REGISTRY_BUILD_BENCHMARKS)
  fabric_registry_add_executable(fabric-registry-benchmarks benchmarks/benchmark_registry.cpp)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(BUILD_TESTING AND FABRIC_REGISTRY_BUILD_TESTS)
  # One executable per translation unit in tests/. tests/support and
  # tests/package_consumer are not test programs: the first is the shared
  # harness, the second is a standalone downstream project that is configured
  # separately against the installed package.
  file(GLOB FABRIC_REGISTRY_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
  file(GLOB FABRIC_REGISTRY_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/support/*.cpp")

  if(FABRIC_REGISTRY_TEST_SUPPORT_SOURCES)
    add_library(fabric_registry_test_support STATIC ${FABRIC_REGISTRY_TEST_SUPPORT_SOURCES})
    set_target_properties(fabric_registry_test_support PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(fabric_registry_test_support PUBLIC fabric_registry)
    # Test translation units include the harness either as
    # "support/test_harness.hpp" or as "test_harness.hpp".
    target_include_directories(fabric_registry_test_support PUBLIC
      "${CMAKE_CURRENT_SOURCE_DIR}/tests"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/support")
    fabric_registry_configure_target(fabric_registry_test_support)
  else()
    message(STATUS "FabricRegistry: tests/support has no translation unit yet; test executables link fabric_registry only")
  endif()

  foreach(test_source IN LISTS FABRIC_REGISTRY_TEST_SOURCES)
    # tests/test_ids.cpp -> fabric-registry-test-ids
    get_filename_component(test_stem "${test_source}" NAME_WE)
    string(REGEX REPLACE "^test_" "" test_suffix "${test_stem}")
    set(test_target "fabric-registry-test-${test_suffix}")

    fabric_registry_add_executable(${test_target} "${test_source}")
    if(TARGET fabric_registry_test_support)
      target_link_libraries(${test_target} PRIVATE fabric_registry_test_support)
    endif()

    # The multi-process test drives the real tools, so the tools must exist
    # before any test runs.
    if(TARGET fabric-registry-coordinator AND TARGET fabric-registry-publisher)
      add_dependencies(${test_target} fabric-registry-coordinator fabric-registry-publisher)
    endif()

    if(test_stem STREQUAL "test_multiprocess" AND TARGET fabric-registry-coordinator AND TARGET fabric-registry-publisher)
      add_test(NAME ${test_target}
               COMMAND ${test_target} multiprocess
                       --coordinator $<TARGET_FILE:fabric-registry-coordinator>
                       --publisher $<TARGET_FILE:fabric-registry-publisher>)
    else()
      add_test(NAME ${test_target} COMMAND ${test_target})
    endif()
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Installation and packaging
# ---------------------------------------------------------------------------

install(TARGETS fabric_registry
        EXPORT FabricRegistryTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT FabricRegistryTargets
        NAMESPACE SummonSoftwareLabs::
        DESTINATION ${FABRIC_REGISTRY_INSTALL_CMAKEDIR})

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FabricRegistryConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/FabricRegistryConfig.cmake"
  INSTALL_DESTINATION "${FABRIC_REGISTRY_INSTALL_CMAKEDIR}"
  PATH_VARS CMAKE_INSTALL_INCLUDEDIR)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/FabricRegistryConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/FabricRegistryConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/FabricRegistryConfigVersion.cmake"
        DESTINATION ${FABRIC_REGISTRY_INSTALL_CMAKEDIR})

# The build tree is usable by a sibling project without installing first.
export(EXPORT FabricRegistryTargets
       NAMESPACE SummonSoftwareLabs::
       FILE "${CMAKE_CURRENT_BINARY_DIR}/FabricRegistryTargets.cmake")

