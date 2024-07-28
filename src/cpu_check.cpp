/*
 *  cpu_check.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This module defines a function that will verify that the Intel
 *      processor supports the AES-NI instructions.  When calling the cpuid()
 *      function with function_id 1, bit 25 of the ecx register will contain
 *      a 1 if the AES-NI instructions are supported.  Source:
 *      https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
 *
 *  Portability Issues:
 *      None.
 */

#include <array>
#include <cstdint>
#ifdef __linux__
#include <cpuid.h>
#endif
#ifdef _WIN32
#include <intrin.h>
#endif
#include "intel_intrinsics.h"

// Set the feature bit representing AES (25th bit) (0x02000000)
#define INTEL_AES_BIT (std::uint32_t(1) << 25)

namespace Terra::Crypto::Cipher
{

#ifdef TERRA_USE_INTEL_AES_INTRINSICS

#ifdef _WIN32

bool CPUSupportsAES_NI()
{
    // Ensure we can query via cpuid
    {
        std::array<int, 4> cpu_info{};
        __cpuid(cpu_info.data(), 0);
        if (cpu_info[0] < 1) return false;
    }

    std::array<int, 4> cpu_info{};
    __cpuid(cpu_info.data(), 1);
    return (cpu_info[2] & INTEL_AES_BIT) != 0;
}

#else

#ifdef __linux__

bool CPUSupportsAES_NI()
{
    // Ensure we can query via cpuid
    {
        std::uint32_t eax{}, ebx{}, ecx{}, edx{};
        __cpuid(0, eax, ebx, ecx, edx);
        if (eax < 1) return false;
    }

    std::uint32_t eax{}, ebx{}, ecx{}, edx{};
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx & INTEL_AES_BIT) != 0;
}

#else // __linux__

#define cpuid(function_id, eax, ebx, ecx, edx) \
    __asm__ __volatile__ ("cpuid": "=a" (eax), "=b" (ebx), "=c" (ecx), \
                                   "=d" (edx) : "a" (function_id));

bool CPUSupportsAES_NI()
{
    // Ensure we can query via cpuid
    {
        std::uint32_t eax{}, ebx{}, ecx{}, edx{};
        cpuid(0, eax, ebx, ecx, edx);
        if (eax < 1) return false;
    }

    std::uint32_t eax{}, ebx{}, ecx{}, edx{};
    cpuid(1, eax, ebx, ecx, edx);
    return (ecx & INTEL_AES_BIT) != 0;
}

#endif // __linux__

#endif // _WIN32

#else // TERRA_USE_INTEL_AES_INTRINSICS

bool CPUSupportsAES_NI()
{
    return false;
}

#endif // TERRA_USE_INTEL_AES_INTRINSICS

} // namespace Terra::Crypto::Cipher
