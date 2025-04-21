# Change Log

v1.1.0

- Performance improvement in AESUniversal object
- Removed inclusion of cpuid.h file for Windows (inadvertently added in 1.0.5
  while working on FreeBSD support)
- Modified utility functions to use templates to allow re-used by specific
  integer types
- Replaced use of legacy C arrays with std::array and replaced use of legacy C
  functions with newer C++ algorithms

v1.0.6

- Disable Intel intrinsics if not targeting an Intel processor
- Updated dependencies

v1.0.5

- Changes required to build on FreeBSD
- Updated library dependencies

v1.0.4

- Changes for Intel-based Mac to support Intel intrinsics

v1.0.3

- Updated library dependencies

v1.0.2

- Changes to CMake related to use of Intel Intrinsics
- Changes to #ifdef statements to check for AES-NI support
- Updated library dependencies

v1.0.1

- Updated secutil to 1.0.1 for better Linux compatibility

v1.0.0

- Initial Release
