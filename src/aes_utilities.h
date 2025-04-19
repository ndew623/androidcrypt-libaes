/*
 *  aes_utilities.h
 *
 *  Copyright (C) 2024-2025
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This header file defines some constexpr functions that are defined
 *      in the AES specification or facilitate AES-related operations.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <type_traits>
#include <limits.h>
#include <cstdint>
#include <terra/bitutil/bit_rotation.h>
#include "aes_tables.h"

namespace
{

// Define the concept defining an unsigned integer that is 32-bits or larger
template<typename T>
concept Unsigned32OrLarger =
    std::is_unsigned_v<T> && (sizeof(T) * CHAR_BIT >= 32);

/*
 *  GetWordFromBuffer
 *
 *  Description:
 *      This function will read a 32-bit word from the given buffer at the
 *      specified offset.  It is used in several places in AES, including
 *      the  key expansion logic and filling a column in the state
 *      array as shown in Figure 3 of FIPS 197.
 *
 *  Parameters:
 *      buffer [in]
 *          A pointer to the buffer from which octets will be read to form a
 *          32-bit value.
 *
 *      offset [in]
 *          The offset from which to read from the buffer.
 *
 *  Returns:
 *      A 32-bit word extract from the given buffer at the specified offset.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr T GetWordFromBuffer(const std::uint8_t buffer[4],
                              const std::size_t offset)
{
    return static_cast<T>(buffer[(offset << 2)    ]) << 24 |
           static_cast<T>(buffer[(offset << 2) + 1]) << 16 |
           static_cast<T>(buffer[(offset << 2) + 2]) <<  8 |
           static_cast<T>(buffer[(offset << 2) + 3]);
}

/*
 *  PutStateColumn
 *
 *  Description:
 *      This function takes the given value from the state array as input
 *      and puts that column into the given buffer linearly.  This is the
 *      output transformation shown in Figure 3 of FIP 197.
 *
 *  Parameters:
 *      value [in]
 *          The state array value for specified column.
 *
 *      column [in]
 *          The column in the state array from which values are to be extracted.
 *          This must be constrained to values between 0 and 3, but no error
 *          checking is performed here for performance reasons.
 *
 *      ciphertext [out]
 *          A pointer into the ciphertext output buffer to write the 32-bit
 *          word extract from the state array.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr void PutStateColumn(const T value,
                              const std::size_t column,
                              std::uint8_t ciphertext[16])
{
    ciphertext[(column << 2)    ] = (value >> 24) & 0xff;
    ciphertext[(column << 2) + 1] = (value >> 16) & 0xff;
    ciphertext[(column << 2) + 2] = (value >>  8) & 0xff;
    ciphertext[(column << 2) + 3] = (value      ) & 0xff;
}

/*
 *  RotWord
 *
 *  Description:
 *      This function will left rotate a 32-bit word by 8 bits.
 *
 *  Parameters:
 *      word [in]
 *          The 32-bit word to be rotated left by 8 bits.
 *
 *  Returns:
 *      The 32-bit word after the bits are rotated left.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr T RotWord(const T word)
{
    return Terra::BitUtil::RotateLeft(word,
                                      8,
                                      32,
                                      T(0xffff'ffff));
}

/*
 *  SubBytes
 *
 *  Description:
 *      This function will perform byte substitution using the S-box table.
 *
 *  Parameters:
 *      value [in]
 *          The value to be substituted using the S-box table.
 *
 *  Returns:
 *      The substituted octet.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr T SubBytes(const T value)
{
    return static_cast<T>(Sbox[(value >> 24) & 0xff]) << 24 |
           static_cast<T>(Sbox[(value >> 16) & 0xff]) << 16 |
           static_cast<T>(Sbox[(value >>  8) & 0xff]) <<  8 |
           static_cast<T>(Sbox[(value      ) & 0xff]);
}

/*
 *  SubBytesShiftRows
 *
 *  Description:
 *      This function perform byte substitution while also shifting rows.
 *      This is part of the final encryption round.
 *
 *  Parameters:
 *      column
 *          The column shift value.
 *
 *      state [in]
 *          The state table from which to extract values while doing byte
 *          substitution using the S-box table.
 *
 *  Returns:
 *      The 32-bit value resulting from the byte substitution following the
 *      column mixing scheme.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr T SubBytesShiftRows(std::size_t column, const T state[4])
{
    return static_cast<T>(Sbox[(state[(0 + column) % 4] >> 24) & 0xff]) << 24 |
           static_cast<T>(Sbox[(state[(1 + column) % 4] >> 16) & 0xff]) << 16 |
           static_cast<T>(Sbox[(state[(2 + column) % 4] >>  8) & 0xff]) <<  8 |
           static_cast<T>(Sbox[(state[(3 + column) % 4]      ) & 0xff]);
}

/*
 *  InvSubBytesShiftRows
 *
 *  Description:
 *      This function perform byte inverse substitution while also shifting
 *      rows.  This is part of the final decryption round.
 *
 *  Parameters:
 *      column
 *          The column shift value.
 *
 *      state [in]
 *          The state table from which to extract values while doing byte
 *          substitution using the S-box table.
 *
 *  Returns:
 *      The 32-bit value resulting from the byte substitution following the
 *      column mixing scheme.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr T InvSubBytesShiftRows(std::size_t column, const T state[4])
{
    return static_cast<T>(
                InverseSbox[(state[(0 + column) % 4] >> 24) & 0xff]) << 24 |
           static_cast<T>(
                InverseSbox[(state[(3 + column) % 4] >> 16) & 0xff]) << 16 |
           static_cast<T>(
                InverseSbox[(state[(2 + column) % 4] >>  8) & 0xff]) <<  8 |
           static_cast<T>(
                InverseSbox[(state[(1 + column) % 4]      ) & 0xff]);
}

/*
 *  AddRoundKey
 *
 *  Description:
 *      The AddRoundKey function merely XORs two values.  It is defined
 *      as a constexpr function just to make it easier to understand the
 *      code as it compares to the AES specification.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
template<Unsigned32OrLarger T>
constexpr T AddRoundKey(const T x, const T y)
{
    return x ^ y;
}

/*
 *  MixColShiftRow
 *
 *  Description:
 *      This function, by using the encrypting constants tables Enc0..Enc3,
 *      is able to perform SubBytes(), ShiftRows(), and MixColumns() for a
 *      column in the state array efficiently.
 *
 *  Parameters:
 *      column [in]
 *          The column number in the state array to operate upon.
 *
 *      state [in]
 *          The state array on which to operate.
 *
 *  Returns:
 *      The resulting output of the combined SubBytes(), ShiftRows(), and
 *      MixColumns() operations.
 *
 *  Comments:
 *      The constants added to column performs the row shifts.
 */
template<Unsigned32OrLarger T>
constexpr T MixColShiftRow(const std::size_t column, const T state[4])
{
    return static_cast<T>(Enc0[(state[(0 + column) % 4] >> 24) & 0xff] ^
                          Enc1[(state[(1 + column) % 4] >> 16) & 0xff] ^
                          Enc2[(state[(2 + column) % 4] >>  8) & 0xff] ^
                          Enc3[(state[(3 + column) % 4]      ) & 0xff]);
}

/*
 *  FastInvMixColumn
 *
 *  Description:
 *      This function will perform the InverseMixColumns operation for
 *      the given 32-bit word.
 *
 *  Parameters:
 *      word [in]
 *          The 32-bit word value on which to operate.
 *
 *  Returns:
 *      The resulting value for InvMixColumns() given the 32-bit input value.
 *
 *  Comments:
 *      Throughout most of the decryption process the decrypting constants
 *      tables (Dec0..Dec3) are used as-is, since they contain the result of
 *      the InverseMixColumns(InvSubBytes()).  As a part of the process to
 *      expand the decryption key, however, it is necessary to perform this
 *      step without byte substitution.  (Refer to the bottom of Figure 15
 *      of FIP 197 for the algorithm.)
 *
 *      This function exists to "reverse" the byte substitution already
 *      existing in the decrypting constants table before indexing into those
 *      tables.  This requires an additional lookup to get the proper entry
 *      in the table, but it is still fast and avoids the need to maintain
 *      additional tables.
 *
 *      This is used by the decryption round key generation as explained in
 *      section 5.3.5 of FIPS 197.  Refer to the README.md for more detail.
 */
template<Unsigned32OrLarger T>
constexpr T FastInvMixColumn(const T value)
{
    return static_cast<T>(Dec0[static_cast<T>(Sbox[(value >> 24) & 0xff])] ^
                          Dec1[static_cast<T>(Sbox[(value >> 16) & 0xff])] ^
                          Dec2[static_cast<T>(Sbox[(value >>  8) & 0xff])] ^
                          Dec3[static_cast<T>(Sbox[(value      ) & 0xff])]);
}

/*
 *  InvMixColShiftRow
 *
 *  Description:
 *      This function, by using the decrypting constants tables Dec0..Dec3,
 *      is able to perform InvSubBytes(), InvShiftRows(), and InvMixColumns()
 *      for a column in the state array efficiently.
 *
 *  Parameters:
 *      column [in]
 *          The column number in the state array to operate upon.
 *
 *      state [in]
 *          The state array on which to operate.
 *
 *  Returns:
 *      The resulting output of the combined InvSubBytes(), InvShiftRows(), and
 *      InvMixColumns() operations.
 *
 *  Comments:
 *      The constants added to column performs the row shifts.
 */
template<Unsigned32OrLarger T>
constexpr T InvMixColShiftRow(const std::size_t column, const T state[4])
{
    return static_cast<T>(Dec0[(state[(0 + column) % 4] >> 24) & 0xff] ^
                          Dec1[(state[(3 + column) % 4] >> 16) & 0xff] ^
                          Dec2[(state[(2 + column) % 4] >>  8) & 0xff] ^
                          Dec3[(state[(1 + column) % 4]      ) & 0xff]);
}

} // namespace
