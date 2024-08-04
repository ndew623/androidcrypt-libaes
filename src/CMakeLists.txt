# Create the library
add_library(aes STATIC
    aes.cpp
    aes_intel.cpp
    aes_universal.cpp
    aes_key_wrap.cpp
    cpu_check.cpp)
add_library(Terra::libaes ALIAS aes)

# Specify the internal and public include directories
target_include_directories(aes
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

# Specify the C++ standard to observe
set_target_properties(aes
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

# If requesting clang-tidy, try to look for it
if(libaes_CLANG_TIDY)
    find_program(CLANG_TIDY_COMMAND NAMES "clang-tidy")
    if(CLANG_TIDY_COMMAND)
        set_target_properties(aes PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")
    else()
        message(WARNING "Could not find clang-tidy")
    endif()
endif()

# Use the following compile options
target_compile_options(aes
    PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>: -Wpedantic -Wextra -Wall>
        $<$<CXX_COMPILER_ID:MSVC>: >)

# Ensure compiler knows if requested to build with Intel intrinsics
if(TERRA_ENABLE_INTEL_AES_INTRINSICS)
    # Set the compiler definition
    target_compile_definitions(aes PRIVATE TERRA_ENABLE_INTEL_AES_INTRINSICS)

    # Set the compiler flags for some platforms
    target_compile_options(aes
        PRIVATE
            $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>: -maes>)
endif()

# Link against library dependencies
target_link_libraries(aes PRIVATE Terra::secutil Terra::bitutil)

# Install target and associated include files
if(libaes_INSTALL)
    include(GNUInstallDirs)
    install(TARGETS aes EXPORT libaesTargets ARCHIVE)
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ TYPE INCLUDE)
    install(EXPORT libaesTargets
            FILE libaesConfig.cmake
            NAMESPACE Terra::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libaes)
endif()
