#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <Windows.h>


#define LOAD(x)			(_mm512_loadu_si512((__m512*)(x))))
#define STORE(x, y)		(_mm512_storeu_si512((__m512*)(x), y))
#define XOR32(x, y)		(_mm512_xor_si512(x, y))
#define ADD8(x, y)		(_mm512_add_epi8(x, y))
#define ADD16(x, y)		(_mm512_add_epi16((x), (y)))
#define ADD_32(x, y)	(_mm512_add_epi32(x, y))
#define SET8(x)			(_mm512_set1_epi8(x))
#define SET16(x)		(_mm512_set1_epi16(x))
#define SET32(x)		(_mm512_set1_epi32(x))
#define LSHIFT(x, n)	(_mm512_slli_epi64(x, n))
#define RSHIFT(x, n)	(_mm512_srli_epi64(x, n))

//! Rotate n-bit using T1, T2
#define ROL_8(T1, T2, state, n)	_mm512_or_si512(_mm512_slli_epi16(_mm512_and_si512(T1, state), n), _mm512_srli_epi16(_mm512_and_si512(T2, state), 8-n))
#define ROL_16(x ,n)				(((x)<<(n))^((x)>>(16-n)))
#define ROLN(x, n)					(_mm512_or_si512(_mm512_slli_epi16(x, n), _mm512_srli_epi16(x, 16-n)))
#define ROR(x, tmp)		(_mm512_ror_epi32(x, tmp))

#define XAR3(cur, pre, tmp, rk1, rk2)											\
	tmp = ADD_32(XOR32(pre, SET32(rk1)), XOR32(cur, SET32(rk2)));				\
	cur = ROR(tmp, 3);
#define XAR5(cur, pre, tmp, rk1, rk2)											\
	tmp = ADD_32(XOR32(pre, SET32(rk1)), XOR32(cur, SET32(rk2)));				\
	cur = ROR(tmp, 5);
#define XAR9(cur, pre, tmp, rk1, rk2)											\
	tmp = ADD_32(XOR32(pre, SET32(rk1)), XOR32(cur, SET32(rk2)));				\
	cur = ROR(tmp, 23);

#define AVX512_BLOCKSIZE	512
#define HIGHT_ROUNDNUM		32
#define CHAM64_128ROUNDNUM  80

__int64 cpucycles();
void HIGHT_genT(__m512i* T);

/***************************************************************************
 *
 * File : KISA_HIGHT_ECB.h
 *
 * Description : header file for KISA_HIGHT_ECB.c
 *
 **************************************************************************/

#ifndef _HIGHT_H_
#define _HIGHT_H_

 /*************** Header files *********************************************/


 /*************** Definitions **********************************************/

#define CT_LITTLE_ENDIAN

/*************** Constants ************************************************/

/*************** Macros ***************************************************/
////
#define ROTL_BYTE(x, n) ( (BYTE)((x) << (n)) | (DWORD)((x) >> (8-(n))) )
#define ROTR_BYTE(x, n) ( (BYTE)((x) >> (n)) | (DWORD)((x) << (8-(n))) )

#if defined(_MSC_VER)
#define ROTL_DWORD(x, n) _lrotl((x), (n))
#define ROTR_DWORD(x, n) _lrotr((x), (n))
#else
#define ROTL_DWORD(x, n) ( (DWORD)((x) << (n)) | (DWORD)((x) >> (32-(n))) )
#define ROTR_DWORD(x, n) ( (DWORD)((x) >> (n)) | (DWORD)((x) << (32-(n))) )
#endif

////    reverse the byte order of DWORD(DWORD:4-bytes integer).
#define ENDIAN_REVERSE_DWORD(dwS)   ( (ROTL_DWORD((dwS),  8) & 0x00ff00ff)  \
                                    | (ROTL_DWORD((dwS), 24) & 0xff00ff00) )

////
#if defined(CT_BIG_ENDIAN)      ////    Big-Endian machine
#define BIG_B2D(B, D)       D = *(DWORD *)(B)
#define BIG_D2B(D, B)       *(DWORD *)(B) = (DWORD)(D)
#define LITTLE_B2D(B, D)    D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
#define LITTLE_D2B(D, B)    *(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
#elif defined(CT_LITTLE_ENDIAN) ////    Little-Endian machine
#define BIG_B2D(B, D)       D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
#define BIG_D2B(D, B)       *(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
#define LITTLE_B2D(B, D)    D = *(DWORD *)(B)
#define LITTLE_D2B(D, B)    *(DWORD *)(B) = (DWORD)(D)
#else
#error ERROR : Invalid DataChangeType
#endif

#if defined(_MSC_VER)
#define INLINE  _inline
#else
#define INLINE  inline
#endif

/*************** New Data Types *******************************************/
#define BYTE    unsigned char       //  1-byte data type
#define WORD    unsigned short int  //  2-byte data type
#define DWORD   unsigned int        //  4-byte data type
/*************** Prototypes ***********************************************/
void    HIGHT_KeySched(
    BYTE* UserKey,
    DWORD   UserKeyLen,
    BYTE* RoundKey);
void    HIGHT_Encrypt(
    BYTE* RoundKey,
    BYTE* Data);

void    HIGHT_Decrypt(
    BYTE* RoundKey,
    BYTE* Data);



#endif  /* _HIGHT_H_ */