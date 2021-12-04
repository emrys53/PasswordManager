cmake_minimum_required(VERSION 3.14)
project(PassKif)

# require C++20
set(CMAKE_CXX_STANDARD 20)

# add our cmake modules under cmake/
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Include CPM dependency manager
include(CPM)

# enable testing
enable_testing()

# Pull doctest using CPM
cpmaddpackage("gh:onqtam/doctest#2.4.5")

# add the CMake modules for automatic test discovery so we can use
# doctest_discover_tests() CMake
set(CMAKE_MODULE_PATH "${doctest_SOURCE_DIR}/scripts/cmake"
        ${CMAKE_MODULE_PATH})

add_subdirectory(test EXCLUDE_FROM_ALL)

add_subdirectory(src)
