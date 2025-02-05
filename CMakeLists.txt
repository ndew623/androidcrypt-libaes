cmake_minimum_required(VERSION 3.21)

# Define the AES Library project
project(libaes
        VERSION 1.0.2.0
        DESCRIPTION "AES Cryptography Library"
        LANGUAGES CXX)

# Tests are built by default when this is a top-level project
if(PROJECT_IS_TOP_LEVEL)
    option(libaes_BUILD_TESTS "Build Tests for the AES Library" ON)
else()
    option(libaes_BUILD_TESTS "Build Tests for the AES Library" OFF)
endif()

# Option to control ability to install the library
option(libaes_INSTALL "Install the AES Library" ON)

# Determine whether clang-tidy should be used during build
option(libaes_CLANG_TIDY "Use clang-tidy to perform linting during build" OFF)

# Option to control use of Intel intrinsics (available only on x86/x64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86|X86|amd64|AMD64")
    message(STATUS "Enabling Intel Intrinsics with processor ${CMAKE_SYSTEM_PROCESSOR}")
    option(TERRA_ENABLE_INTEL_INTRINSICS "Enable Intel AES Intrinsics" ON)
else()
    message(STATUS "Intel Intrinsics are DISABLED for ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Option to enable speed test in the AES engine tests
option(TERRA_ENABLE_AES_SPEED_TESTS "Enable AES Engine Speed Tests" OFF)

add_subdirectory(dependencies)
add_subdirectory(src)

include(CTest)

if(BUILD_TESTING AND libaes_BUILD_TESTS)
    add_subdirectory(test)
endif()
