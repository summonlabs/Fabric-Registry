# Standalone downstream project.
#
# This is deliberately NOT part of the Fabric Registry build: it stands in for
# a real consumer and is configured on its own against an installed package
# (or against the build tree) to prove that the exported package works.
#
#   cmake -S tests/package_consumer -B <dir> -DFabricRegistry_DIR=<prefix>/lib/cmake/FabricRegistry

cmake_minimum_required(VERSION 3.20)

project(FabricRegistryPackageConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(FabricRegistry CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE SummonSoftwareLabs::FabricRegistry)
