#
# Handle checks to see if the system has the __cpuid() function
#

# Windows systems have their own CPUID function, so skip this check
if(NOT WIN32)

    include(CheckCXXSourceCompiles)

    check_cxx_source_compiles("
        #include <cpuid.h>
        #include <cstdint>
        int main() {
            uint32_t a, b, c, d;
            __cpuid(0, a, b, c, d);
            return 0;
        }" HAVE_CPUID)

endif()
