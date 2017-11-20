/* -----------------------------------------------------------------------
 * 
 * umac.c -- C Implementation UMAC Message Authentication
 *
 * Version 0.05 of draft-krovetz-umac-01.txt -- 2000 October
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2000 Ted Krovetz (tdk@acm.org)
 *                                                                 
 * Permission to use, copy, modify, and distribute this software and  
 * its documentation for any purpose and without fee, is hereby granted,
 * provided that the above copyright notice appears in all copies and  
 * that both that copyright notice and this permission notice appear   
 * in supporting documentation, and that the names of the University of
 * California and Ted Krovetz not be used in advertising or publicity  
 * pertaining to distribution of the software without specific,        
 * written prior permission.                                          
 *                                                                   
 * The Regents of the University of California and Ted Krovetz disclaim 
 * all warranties with regard to this software, including all implied
 * warranties of merchantability and fitness.  In no event shall the  
 * University of California or Ted Krovetz be liable for any special,  
 * indirect or consequential damages or any damages whatsoever resulting
 * from loss of use, data or profits, whether in an action of contract,
 * negligence or other tortious action, arising out of or in connection
 * with the use or performance of this software.
 * 
 * ---------------------------------------------------------------------- */
 
/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#include "umac.h"
#include <string.h>
#include <stdlib.h>

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

#if 0
#ifdef _MSC_VER
typedef unsigned char      UINT8;   /* 1 byte   */
typedef __int16            INT16;  /* 2 byte   */
typedef unsigned __int16   UINT16; /* 2 byte   */
typedef __int32            INT32;  /* 4 byte   */
typedef unsigned __int32   UINT32; /* 4 byte   */
typedef unsigned __int64   UINT64; /* 8 bytes  */
#else
typedef unsigned char      UINT8;  /* 1 byte   */
typedef short              INT16;  /* 2 byte   */
typedef unsigned short     UINT16; /* 2 byte   */
typedef int                INT32;  /* 4 byte   */
typedef unsigned int       UINT32; /* 4 byte   */
typedef unsigned long long UINT64; /* 8 bytes  */
#endif
typedef unsigned long      UWORD;  /* Register */
#endif

/* ---------------------------------------------------------------------- */
/* --- Derived Constants ------------------------------------------------ */
/* ---------------------------------------------------------------------- */

#if (WORD_LEN == 4)

typedef UINT32  SMALL_UWORD;  
typedef UINT64  LARGE_UWORD;

#elif (WORD_LEN == 2)
 
typedef UINT16  SMALL_UWORD;  
typedef UINT32  LARGE_UWORD;

#endif

/* How many iterations, or streams, are needed to produce UMAC_OUTPUT_LEN
 * and UMAC_PREFIX_LEN bytes of output
 */
#define PREFIX_STREAMS    (UMAC_PREFIX_LEN / WORD_LEN)
#define OUTPUT_STREAMS    (UMAC_OUTPUT_LEN / WORD_LEN)

/* Three compiler environments are supported for accellerated
 * implementations: GNU gcc and Microsoft Visual C++ (and copycats) on x86,
 * and Metrowerks on PowerPC.
 */
#define GCC_X86         (__GNUC__ && __i386__)      /* GCC on IA-32       */
#define MSC_X86         (_MSC_VER && _M_IX86)       /* Microsoft on IA-32 */
#define MW_PPC          ((__MWERKS__ || __MRC__) && __POWERPC__)
                                                    /* Metrowerks on PPC  */
/* ---------------------------------------------------------------------- */
/* --- Host Computer Endian Definition ---------------------------------- */
/* ---------------------------------------------------------------------- */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#ifndef __LITTLE_ENDIAN__
#if __i386__ || __alpha__ || _M_IX86 || __LITTLE_ENDIAN
#define __LITTLE_ENDIAN__ 1
#else
#define __LITTLE_ENDIAN__ 0
#endif
#endif

/* ---------------------------------------------------------------------- */
/* ----- AES Function Family Constants ---------------------------------- */
/* ---------------------------------------------------------------------- */

/*#define AES_BLOCK_LEN  16                */
/*#define ROUNDS	       ((UMAC_KEY_LEN / 4) + 6)*/
/*typedef UINT8          aes_int_key[ROUNDS+1][4][4];*/

/* ---------------------------------------------------------------------- */
/* ----- Poly hash and Inner-Product hash Constants --------------------- */
/* ---------------------------------------------------------------------- */

/* Primes and masks */
#define p19    ((UINT32)0x0007FFFFu)              /* 2^19 -  1 */
#define p32    ((UINT32)0xFFFFFFFBu)              /* 2^32 -  5 */
#define m19    ((UINT32)0x0007FFFFu)  /* The low 19 of 32 bits */

#if _MSC_VER  /* no support for ull suffix in Visual C++ */
const UINT64 p36 = (((UINT64)1 << 36) - (UINT64)5);         /* 2^36 -  5 */
const UINT64 p64 = ((UINT64)0 - (UINT64)59);                /* 2^64 - 59 */
const UINT64 m36 = (((UINT64)1 << 36) - 1);  /* The low 36 of 64 bits */
#else
#define p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#define p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#define m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Architecture Specific Routines --------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* These are the optional, architecture-specific accelleration files      */

#if (GCC_X86 && ! USE_C_ONLY)
#include "umac_gcc_x86_incl.c"
#elif (MSC_X86 && ! USE_C_ONLY)
#include "umac_msc_x86_incl.c"
#elif (MW_PPC && ! USE_C_ONLY)
#include "umac_mw_ppc_incl.c"
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Primitive Routines --------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* --- 32-Bit Rotation operators                                          */
/* ---------------------------------------------------------------------- */

/* Good compilers can detect when a rotate
 * is being constructed from bitshifting and bitwise OR and output the
 * assembly rotates. Other compilers require assembly or C intrinsics.
 * There are two versions because some intrinsics differentiate between
 * constant rotation and variable rotation. "n" must be on 0..31.
 */

#if (USE_C_ONLY || ! ARCH_ROTL)

#define ROTL32_VAR(r,n)   (((r) <<  (n))       | \
                          ((UINT32)(r) >> (32 -  (n))))
#define ROTL32_CONST(r,n) (((r) <<  (n))       | \
                          ((UINT32)(r) >> (32 -  (n))))

#endif

/* ---------------------------------------------------------------------- */
/* --- 32-bit by 32-bit to 64-bit Multiplication ------------------------ */
/* ---------------------------------------------------------------------- */

#if (USE_C_ONLY || ! ARCH_MUL64)

#define MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))
               
#endif

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

/* Lots of endian reversals happen in UMAC. PowerPC and Intel Architechture
 * both support efficient endian conversion, but compilers seem unable to
 * automatically utilize the efficient assembly opcodes. The architechture-
 * specific versions utilize them.
 */

#if (USE_C_ONLY || ! ARCH_ENDIAN_LS)

static UINT32 LOAD_UINT32_REVERSED(void *ptr)
{
    UINT32 temp = *(UINT32 *)ptr;
    temp = (temp >> 24) | ((temp & 0x00FF0000) >> 8 )
         | ((temp & 0x0000FF00) << 8 ) | (temp << 24);
    return (UINT32)temp;
}
               
static void STORE_UINT32_REVERSED(void *ptr, UINT32 x)
{
    UINT32 i = (UINT32)x;
    *(UINT32 *)ptr = (i >> 24) | ((i & 0x00FF0000) >> 8 )
                   | ((i & 0x0000FF00) << 8 ) | (i << 24);
}

static UINT16 LOAD_UINT16_REVERSED(void *ptr)
{
    UINT16 temp = *(UINT16 *)ptr;
    temp = (temp >> 8) | (temp << 8);
    return (UINT16)temp;
}
               
static void STORE_UINT16_REVERSED(void *ptr, UINT16 x)
{
    UINT16 temp = (UINT16)x;
    *(UINT16 *)ptr = (temp >> 8) | (temp << 8);
}
               
#endif

/* The following definitions use the above reversal-primitives to do the right
 * thing on endian specific load and stores.
 */

#if (__LITTLE_ENDIAN__)
#define LOAD_UINT16_LITTLE(ptr)     (*(UINT16 *)(ptr))
#define LOAD_UINT32_LITTLE(ptr)     (*(UINT32 *)(ptr))
#define STORE_UINT16_LITTLE(ptr,x)  (*(UINT16 *)(ptr) = (UINT16)(x))
#define STORE_UINT32_LITTLE(ptr,x)  (*(UINT32 *)(ptr) = (UINT32)(x))
#define LOAD_UINT16_BIG(ptr)        LOAD_UINT16_REVERSED(ptr)
#define LOAD_UINT32_BIG(ptr)        LOAD_UINT32_REVERSED(ptr)
#define STORE_UINT16_BIG(ptr,x)     STORE_UINT16_REVERSED(ptr,x)
#define STORE_UINT32_BIG(ptr,x)     STORE_UINT32_REVERSED(ptr,x)
#else
#define LOAD_UINT16_LITTLE(ptr)     LOAD_UINT16_REVERSED(ptr)
#define LOAD_UINT32_LITTLE(ptr)     LOAD_UINT32_REVERSED(ptr)
#define STORE_UINT16_LITTLE(ptr,x)  STORE_UINT16_REVERSED(ptr,x)
#define STORE_UINT32_LITTLE(ptr,x)  STORE_UINT32_REVERSED(ptr,x)
#define LOAD_UINT16_BIG(ptr)        (*(UINT16 *)(ptr))
#define LOAD_UINT32_BIG(ptr)        (*(UINT32 *)(ptr))
#define STORE_UINT16_BIG(ptr,x)     (*(UINT16 *)(ptr) = (UINT16)(x))
#define STORE_UINT32_BIG(ptr,x)     (*(UINT32 *)(ptr) = (UINT32)(x))
#endif


/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin Cryptographic Primitive Section -------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The UMAC specification requires the use of AES for it's cryptographic
 * component.
 */

/* ---------------------------------------------------------------------- */
#if (USE_C_ONLY || ! ARCH_AES)
/* ---------------------------------------------------------------------- */

 

/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */


/*
 * Based on rijndael-alg-fst.c   v2.4   April '2000
 */

static const UINT8 S[256] = {
 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118, 
202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21, 
  4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117, 
  9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132, 
 83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207, 
208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168, 
 81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210, 
205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115, 
 96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219, 
224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 
231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 
186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138, 
112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158, 
225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223, 
140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22
};


static const UINT8 T1[256][4] = {
0xc6,0x63,0x63,0xa5, 0xf8,0x7c,0x7c,0x84, 0xee,0x77,0x77,0x99, 0xf6,0x7b,0x7b,0x8d, 
0xff,0xf2,0xf2,0x0d, 0xd6,0x6b,0x6b,0xbd, 0xde,0x6f,0x6f,0xb1, 0x91,0xc5,0xc5,0x54, 
0x60,0x30,0x30,0x50, 0x02,0x01,0x01,0x03, 0xce,0x67,0x67,0xa9, 0x56,0x2b,0x2b,0x7d, 
0xe7,0xfe,0xfe,0x19, 0xb5,0xd7,0xd7,0x62, 0x4d,0xab,0xab,0xe6, 0xec,0x76,0x76,0x9a, 
0x8f,0xca,0xca,0x45, 0x1f,0x82,0x82,0x9d, 0x89,0xc9,0xc9,0x40, 0xfa,0x7d,0x7d,0x87, 
0xef,0xfa,0xfa,0x15, 0xb2,0x59,0x59,0xeb, 0x8e,0x47,0x47,0xc9, 0xfb,0xf0,0xf0,0x0b, 
0x41,0xad,0xad,0xec, 0xb3,0xd4,0xd4,0x67, 0x5f,0xa2,0xa2,0xfd, 0x45,0xaf,0xaf,0xea, 
0x23,0x9c,0x9c,0xbf, 0x53,0xa4,0xa4,0xf7, 0xe4,0x72,0x72,0x96, 0x9b,0xc0,0xc0,0x5b, 
0x75,0xb7,0xb7,0xc2, 0xe1,0xfd,0xfd,0x1c, 0x3d,0x93,0x93,0xae, 0x4c,0x26,0x26,0x6a, 
0x6c,0x36,0x36,0x5a, 0x7e,0x3f,0x3f,0x41, 0xf5,0xf7,0xf7,0x02, 0x83,0xcc,0xcc,0x4f, 
0x68,0x34,0x34,0x5c, 0x51,0xa5,0xa5,0xf4, 0xd1,0xe5,0xe5,0x34, 0xf9,0xf1,0xf1,0x08, 
0xe2,0x71,0x71,0x93, 0xab,0xd8,0xd8,0x73, 0x62,0x31,0x31,0x53, 0x2a,0x15,0x15,0x3f, 
0x08,0x04,0x04,0x0c, 0x95,0xc7,0xc7,0x52, 0x46,0x23,0x23,0x65, 0x9d,0xc3,0xc3,0x5e, 
0x30,0x18,0x18,0x28, 0x37,0x96,0x96,0xa1, 0x0a,0x05,0x05,0x0f, 0x2f,0x9a,0x9a,0xb5, 
0x0e,0x07,0x07,0x09, 0x24,0x12,0x12,0x36, 0x1b,0x80,0x80,0x9b, 0xdf,0xe2,0xe2,0x3d, 
0xcd,0xeb,0xeb,0x26, 0x4e,0x27,0x27,0x69, 0x7f,0xb2,0xb2,0xcd, 0xea,0x75,0x75,0x9f, 
0x12,0x09,0x09,0x1b, 0x1d,0x83,0x83,0x9e, 0x58,0x2c,0x2c,0x74, 0x34,0x1a,0x1a,0x2e, 
0x36,0x1b,0x1b,0x2d, 0xdc,0x6e,0x6e,0xb2, 0xb4,0x5a,0x5a,0xee, 0x5b,0xa0,0xa0,0xfb, 
0xa4,0x52,0x52,0xf6, 0x76,0x3b,0x3b,0x4d, 0xb7,0xd6,0xd6,0x61, 0x7d,0xb3,0xb3,0xce, 
0x52,0x29,0x29,0x7b, 0xdd,0xe3,0xe3,0x3e, 0x5e,0x2f,0x2f,0x71, 0x13,0x84,0x84,0x97, 
0xa6,0x53,0x53,0xf5, 0xb9,0xd1,0xd1,0x68, 0x00,0x00,0x00,0x00, 0xc1,0xed,0xed,0x2c, 
0x40,0x20,0x20,0x60, 0xe3,0xfc,0xfc,0x1f, 0x79,0xb1,0xb1,0xc8, 0xb6,0x5b,0x5b,0xed, 
0xd4,0x6a,0x6a,0xbe, 0x8d,0xcb,0xcb,0x46, 0x67,0xbe,0xbe,0xd9, 0x72,0x39,0x39,0x4b, 
0x94,0x4a,0x4a,0xde, 0x98,0x4c,0x4c,0xd4, 0xb0,0x58,0x58,0xe8, 0x85,0xcf,0xcf,0x4a, 
0xbb,0xd0,0xd0,0x6b, 0xc5,0xef,0xef,0x2a, 0x4f,0xaa,0xaa,0xe5, 0xed,0xfb,0xfb,0x16, 
0x86,0x43,0x43,0xc5, 0x9a,0x4d,0x4d,0xd7, 0x66,0x33,0x33,0x55, 0x11,0x85,0x85,0x94, 
0x8a,0x45,0x45,0xcf, 0xe9,0xf9,0xf9,0x10, 0x04,0x02,0x02,0x06, 0xfe,0x7f,0x7f,0x81, 
0xa0,0x50,0x50,0xf0, 0x78,0x3c,0x3c,0x44, 0x25,0x9f,0x9f,0xba, 0x4b,0xa8,0xa8,0xe3, 
0xa2,0x51,0x51,0xf3, 0x5d,0xa3,0xa3,0xfe, 0x80,0x40,0x40,0xc0, 0x05,0x8f,0x8f,0x8a, 
0x3f,0x92,0x92,0xad, 0x21,0x9d,0x9d,0xbc, 0x70,0x38,0x38,0x48, 0xf1,0xf5,0xf5,0x04, 
0x63,0xbc,0xbc,0xdf, 0x77,0xb6,0xb6,0xc1, 0xaf,0xda,0xda,0x75, 0x42,0x21,0x21,0x63, 
0x20,0x10,0x10,0x30, 0xe5,0xff,0xff,0x1a, 0xfd,0xf3,0xf3,0x0e, 0xbf,0xd2,0xd2,0x6d, 
0x81,0xcd,0xcd,0x4c, 0x18,0x0c,0x0c,0x14, 0x26,0x13,0x13,0x35, 0xc3,0xec,0xec,0x2f, 
0xbe,0x5f,0x5f,0xe1, 0x35,0x97,0x97,0xa2, 0x88,0x44,0x44,0xcc, 0x2e,0x17,0x17,0x39, 
0x93,0xc4,0xc4,0x57, 0x55,0xa7,0xa7,0xf2, 0xfc,0x7e,0x7e,0x82, 0x7a,0x3d,0x3d,0x47, 
0xc8,0x64,0x64,0xac, 0xba,0x5d,0x5d,0xe7, 0x32,0x19,0x19,0x2b, 0xe6,0x73,0x73,0x95, 
0xc0,0x60,0x60,0xa0, 0x19,0x81,0x81,0x98, 0x9e,0x4f,0x4f,0xd1, 0xa3,0xdc,0xdc,0x7f, 
0x44,0x22,0x22,0x66, 0x54,0x2a,0x2a,0x7e, 0x3b,0x90,0x90,0xab, 0x0b,0x88,0x88,0x83, 
0x8c,0x46,0x46,0xca, 0xc7,0xee,0xee,0x29, 0x6b,0xb8,0xb8,0xd3, 0x28,0x14,0x14,0x3c, 
0xa7,0xde,0xde,0x79, 0xbc,0x5e,0x5e,0xe2, 0x16,0x0b,0x0b,0x1d, 0xad,0xdb,0xdb,0x76, 
0xdb,0xe0,0xe0,0x3b, 0x64,0x32,0x32,0x56, 0x74,0x3a,0x3a,0x4e, 0x14,0x0a,0x0a,0x1e, 
0x92,0x49,0x49,0xdb, 0x0c,0x06,0x06,0x0a, 0x48,0x24,0x24,0x6c, 0xb8,0x5c,0x5c,0xe4, 
0x9f,0xc2,0xc2,0x5d, 0xbd,0xd3,0xd3,0x6e, 0x43,0xac,0xac,0xef, 0xc4,0x62,0x62,0xa6, 
0x39,0x91,0x91,0xa8, 0x31,0x95,0x95,0xa4, 0xd3,0xe4,0xe4,0x37, 0xf2,0x79,0x79,0x8b, 
0xd5,0xe7,0xe7,0x32, 0x8b,0xc8,0xc8,0x43, 0x6e,0x37,0x37,0x59, 0xda,0x6d,0x6d,0xb7, 
0x01,0x8d,0x8d,0x8c, 0xb1,0xd5,0xd5,0x64, 0x9c,0x4e,0x4e,0xd2, 0x49,0xa9,0xa9,0xe0, 
0xd8,0x6c,0x6c,0xb4, 0xac,0x56,0x56,0xfa, 0xf3,0xf4,0xf4,0x07, 0xcf,0xea,0xea,0x25, 
0xca,0x65,0x65,0xaf, 0xf4,0x7a,0x7a,0x8e, 0x47,0xae,0xae,0xe9, 0x10,0x08,0x08,0x18, 
0x6f,0xba,0xba,0xd5, 0xf0,0x78,0x78,0x88, 0x4a,0x25,0x25,0x6f, 0x5c,0x2e,0x2e,0x72, 
0x38,0x1c,0x1c,0x24, 0x57,0xa6,0xa6,0xf1, 0x73,0xb4,0xb4,0xc7, 0x97,0xc6,0xc6,0x51, 
0xcb,0xe8,0xe8,0x23, 0xa1,0xdd,0xdd,0x7c, 0xe8,0x74,0x74,0x9c, 0x3e,0x1f,0x1f,0x21, 
0x96,0x4b,0x4b,0xdd, 0x61,0xbd,0xbd,0xdc, 0x0d,0x8b,0x8b,0x86, 0x0f,0x8a,0x8a,0x85, 
0xe0,0x70,0x70,0x90, 0x7c,0x3e,0x3e,0x42, 0x71,0xb5,0xb5,0xc4, 0xcc,0x66,0x66,0xaa, 
0x90,0x48,0x48,0xd8, 0x06,0x03,0x03,0x05, 0xf7,0xf6,0xf6,0x01, 0x1c,0x0e,0x0e,0x12, 
0xc2,0x61,0x61,0xa3, 0x6a,0x35,0x35,0x5f, 0xae,0x57,0x57,0xf9, 0x69,0xb9,0xb9,0xd0, 
0x17,0x86,0x86,0x91, 0x99,0xc1,0xc1,0x58, 0x3a,0x1d,0x1d,0x27, 0x27,0x9e,0x9e,0xb9, 
0xd9,0xe1,0xe1,0x38, 0xeb,0xf8,0xf8,0x13, 0x2b,0x98,0x98,0xb3, 0x22,0x11,0x11,0x33, 
0xd2,0x69,0x69,0xbb, 0xa9,0xd9,0xd9,0x70, 0x07,0x8e,0x8e,0x89, 0x33,0x94,0x94,0xa7, 
0x2d,0x9b,0x9b,0xb6, 0x3c,0x1e,0x1e,0x22, 0x15,0x87,0x87,0x92, 0xc9,0xe9,0xe9,0x20, 
0x87,0xce,0xce,0x49, 0xaa,0x55,0x55,0xff, 0x50,0x28,0x28,0x78, 0xa5,0xdf,0xdf,0x7a, 
0x03,0x8c,0x8c,0x8f, 0x59,0xa1,0xa1,0xf8, 0x09,0x89,0x89,0x80, 0x1a,0x0d,0x0d,0x17, 
0x65,0xbf,0xbf,0xda, 0xd7,0xe6,0xe6,0x31, 0x84,0x42,0x42,0xc6, 0xd0,0x68,0x68,0xb8, 
0x82,0x41,0x41,0xc3, 0x29,0x99,0x99,0xb0, 0x5a,0x2d,0x2d,0x77, 0x1e,0x0f,0x0f,0x11, 
0x7b,0xb0,0xb0,0xcb, 0xa8,0x54,0x54,0xfc, 0x6d,0xbb,0xbb,0xd6, 0x2c,0x16,0x16,0x3a
};

static const UINT8 T2[256][4] = {
0xa5,0xc6,0x63,0x63, 0x84,0xf8,0x7c,0x7c, 0x99,0xee,0x77,0x77, 0x8d,0xf6,0x7b,0x7b, 
0x0d,0xff,0xf2,0xf2, 0xbd,0xd6,0x6b,0x6b, 0xb1,0xde,0x6f,0x6f, 0x54,0x91,0xc5,0xc5, 
0x50,0x60,0x30,0x30, 0x03,0x02,0x01,0x01, 0xa9,0xce,0x67,0x67, 0x7d,0x56,0x2b,0x2b, 
0x19,0xe7,0xfe,0xfe, 0x62,0xb5,0xd7,0xd7, 0xe6,0x4d,0xab,0xab, 0x9a,0xec,0x76,0x76, 
0x45,0x8f,0xca,0xca, 0x9d,0x1f,0x82,0x82, 0x40,0x89,0xc9,0xc9, 0x87,0xfa,0x7d,0x7d, 
0x15,0xef,0xfa,0xfa, 0xeb,0xb2,0x59,0x59, 0xc9,0x8e,0x47,0x47, 0x0b,0xfb,0xf0,0xf0, 
0xec,0x41,0xad,0xad, 0x67,0xb3,0xd4,0xd4, 0xfd,0x5f,0xa2,0xa2, 0xea,0x45,0xaf,0xaf, 
0xbf,0x23,0x9c,0x9c, 0xf7,0x53,0xa4,0xa4, 0x96,0xe4,0x72,0x72, 0x5b,0x9b,0xc0,0xc0, 
0xc2,0x75,0xb7,0xb7, 0x1c,0xe1,0xfd,0xfd, 0xae,0x3d,0x93,0x93, 0x6a,0x4c,0x26,0x26, 
0x5a,0x6c,0x36,0x36, 0x41,0x7e,0x3f,0x3f, 0x02,0xf5,0xf7,0xf7, 0x4f,0x83,0xcc,0xcc, 
0x5c,0x68,0x34,0x34, 0xf4,0x51,0xa5,0xa5, 0x34,0xd1,0xe5,0xe5, 0x08,0xf9,0xf1,0xf1, 
0x93,0xe2,0x71,0x71, 0x73,0xab,0xd8,0xd8, 0x53,0x62,0x31,0x31, 0x3f,0x2a,0x15,0x15, 
0x0c,0x08,0x04,0x04, 0x52,0x95,0xc7,0xc7, 0x65,0x46,0x23,0x23, 0x5e,0x9d,0xc3,0xc3, 
0x28,0x30,0x18,0x18, 0xa1,0x37,0x96,0x96, 0x0f,0x0a,0x05,0x05, 0xb5,0x2f,0x9a,0x9a, 
0x09,0x0e,0x07,0x07, 0x36,0x24,0x12,0x12, 0x9b,0x1b,0x80,0x80, 0x3d,0xdf,0xe2,0xe2, 
0x26,0xcd,0xeb,0xeb, 0x69,0x4e,0x27,0x27, 0xcd,0x7f,0xb2,0xb2, 0x9f,0xea,0x75,0x75, 
0x1b,0x12,0x09,0x09, 0x9e,0x1d,0x83,0x83, 0x74,0x58,0x2c,0x2c, 0x2e,0x34,0x1a,0x1a, 
0x2d,0x36,0x1b,0x1b, 0xb2,0xdc,0x6e,0x6e, 0xee,0xb4,0x5a,0x5a, 0xfb,0x5b,0xa0,0xa0, 
0xf6,0xa4,0x52,0x52, 0x4d,0x76,0x3b,0x3b, 0x61,0xb7,0xd6,0xd6, 0xce,0x7d,0xb3,0xb3, 
0x7b,0x52,0x29,0x29, 0x3e,0xdd,0xe3,0xe3, 0x71,0x5e,0x2f,0x2f, 0x97,0x13,0x84,0x84, 
0xf5,0xa6,0x53,0x53, 0x68,0xb9,0xd1,0xd1, 0x00,0x00,0x00,0x00, 0x2c,0xc1,0xed,0xed, 
0x60,0x40,0x20,0x20, 0x1f,0xe3,0xfc,0xfc, 0xc8,0x79,0xb1,0xb1, 0xed,0xb6,0x5b,0x5b, 
0xbe,0xd4,0x6a,0x6a, 0x46,0x8d,0xcb,0xcb, 0xd9,0x67,0xbe,0xbe, 0x4b,0x72,0x39,0x39, 
0xde,0x94,0x4a,0x4a, 0xd4,0x98,0x4c,0x4c, 0xe8,0xb0,0x58,0x58, 0x4a,0x85,0xcf,0xcf, 
0x6b,0xbb,0xd0,0xd0, 0x2a,0xc5,0xef,0xef, 0xe5,0x4f,0xaa,0xaa, 0x16,0xed,0xfb,0xfb, 
0xc5,0x86,0x43,0x43, 0xd7,0x9a,0x4d,0x4d, 0x55,0x66,0x33,0x33, 0x94,0x11,0x85,0x85, 
0xcf,0x8a,0x45,0x45, 0x10,0xe9,0xf9,0xf9, 0x06,0x04,0x02,0x02, 0x81,0xfe,0x7f,0x7f, 
0xf0,0xa0,0x50,0x50, 0x44,0x78,0x3c,0x3c, 0xba,0x25,0x9f,0x9f, 0xe3,0x4b,0xa8,0xa8, 
0xf3,0xa2,0x51,0x51, 0xfe,0x5d,0xa3,0xa3, 0xc0,0x80,0x40,0x40, 0x8a,0x05,0x8f,0x8f, 
0xad,0x3f,0x92,0x92, 0xbc,0x21,0x9d,0x9d, 0x48,0x70,0x38,0x38, 0x04,0xf1,0xf5,0xf5, 
0xdf,0x63,0xbc,0xbc, 0xc1,0x77,0xb6,0xb6, 0x75,0xaf,0xda,0xda, 0x63,0x42,0x21,0x21, 
0x30,0x20,0x10,0x10, 0x1a,0xe5,0xff,0xff, 0x0e,0xfd,0xf3,0xf3, 0x6d,0xbf,0xd2,0xd2, 
0x4c,0x81,0xcd,0xcd, 0x14,0x18,0x0c,0x0c, 0x35,0x26,0x13,0x13, 0x2f,0xc3,0xec,0xec, 
0xe1,0xbe,0x5f,0x5f, 0xa2,0x35,0x97,0x97, 0xcc,0x88,0x44,0x44, 0x39,0x2e,0x17,0x17, 
0x57,0x93,0xc4,0xc4, 0xf2,0x55,0xa7,0xa7, 0x82,0xfc,0x7e,0x7e, 0x47,0x7a,0x3d,0x3d, 
0xac,0xc8,0x64,0x64, 0xe7,0xba,0x5d,0x5d, 0x2b,0x32,0x19,0x19, 0x95,0xe6,0x73,0x73, 
0xa0,0xc0,0x60,0x60, 0x98,0x19,0x81,0x81, 0xd1,0x9e,0x4f,0x4f, 0x7f,0xa3,0xdc,0xdc, 
0x66,0x44,0x22,0x22, 0x7e,0x54,0x2a,0x2a, 0xab,0x3b,0x90,0x90, 0x83,0x0b,0x88,0x88, 
0xca,0x8c,0x46,0x46, 0x29,0xc7,0xee,0xee, 0xd3,0x6b,0xb8,0xb8, 0x3c,0x28,0x14,0x14, 
0x79,0xa7,0xde,0xde, 0xe2,0xbc,0x5e,0x5e, 0x1d,0x16,0x0b,0x0b, 0x76,0xad,0xdb,0xdb, 
0x3b,0xdb,0xe0,0xe0, 0x56,0x64,0x32,0x32, 0x4e,0x74,0x3a,0x3a, 0x1e,0x14,0x0a,0x0a, 
0xdb,0x92,0x49,0x49, 0x0a,0x0c,0x06,0x06, 0x6c,0x48,0x24,0x24, 0xe4,0xb8,0x5c,0x5c, 
0x5d,0x9f,0xc2,0xc2, 0x6e,0xbd,0xd3,0xd3, 0xef,0x43,0xac,0xac, 0xa6,0xc4,0x62,0x62, 
0xa8,0x39,0x91,0x91, 0xa4,0x31,0x95,0x95, 0x37,0xd3,0xe4,0xe4, 0x8b,0xf2,0x79,0x79, 
0x32,0xd5,0xe7,0xe7, 0x43,0x8b,0xc8,0xc8, 0x59,0x6e,0x37,0x37, 0xb7,0xda,0x6d,0x6d, 
0x8c,0x01,0x8d,0x8d, 0x64,0xb1,0xd5,0xd5, 0xd2,0x9c,0x4e,0x4e, 0xe0,0x49,0xa9,0xa9, 
0xb4,0xd8,0x6c,0x6c, 0xfa,0xac,0x56,0x56, 0x07,0xf3,0xf4,0xf4, 0x25,0xcf,0xea,0xea, 
0xaf,0xca,0x65,0x65, 0x8e,0xf4,0x7a,0x7a, 0xe9,0x47,0xae,0xae, 0x18,0x10,0x08,0x08, 
0xd5,0x6f,0xba,0xba, 0x88,0xf0,0x78,0x78, 0x6f,0x4a,0x25,0x25, 0x72,0x5c,0x2e,0x2e, 
0x24,0x38,0x1c,0x1c, 0xf1,0x57,0xa6,0xa6, 0xc7,0x73,0xb4,0xb4, 0x51,0x97,0xc6,0xc6, 
0x23,0xcb,0xe8,0xe8, 0x7c,0xa1,0xdd,0xdd, 0x9c,0xe8,0x74,0x74, 0x21,0x3e,0x1f,0x1f, 
0xdd,0x96,0x4b,0x4b, 0xdc,0x61,0xbd,0xbd, 0x86,0x0d,0x8b,0x8b, 0x85,0x0f,0x8a,0x8a, 
0x90,0xe0,0x70,0x70, 0x42,0x7c,0x3e,0x3e, 0xc4,0x71,0xb5,0xb5, 0xaa,0xcc,0x66,0x66, 
0xd8,0x90,0x48,0x48, 0x05,0x06,0x03,0x03, 0x01,0xf7,0xf6,0xf6, 0x12,0x1c,0x0e,0x0e, 
0xa3,0xc2,0x61,0x61, 0x5f,0x6a,0x35,0x35, 0xf9,0xae,0x57,0x57, 0xd0,0x69,0xb9,0xb9, 
0x91,0x17,0x86,0x86, 0x58,0x99,0xc1,0xc1, 0x27,0x3a,0x1d,0x1d, 0xb9,0x27,0x9e,0x9e, 
0x38,0xd9,0xe1,0xe1, 0x13,0xeb,0xf8,0xf8, 0xb3,0x2b,0x98,0x98, 0x33,0x22,0x11,0x11, 
0xbb,0xd2,0x69,0x69, 0x70,0xa9,0xd9,0xd9, 0x89,0x07,0x8e,0x8e, 0xa7,0x33,0x94,0x94, 
0xb6,0x2d,0x9b,0x9b, 0x22,0x3c,0x1e,0x1e, 0x92,0x15,0x87,0x87, 0x20,0xc9,0xe9,0xe9, 
0x49,0x87,0xce,0xce, 0xff,0xaa,0x55,0x55, 0x78,0x50,0x28,0x28, 0x7a,0xa5,0xdf,0xdf, 
0x8f,0x03,0x8c,0x8c, 0xf8,0x59,0xa1,0xa1, 0x80,0x09,0x89,0x89, 0x17,0x1a,0x0d,0x0d, 
0xda,0x65,0xbf,0xbf, 0x31,0xd7,0xe6,0xe6, 0xc6,0x84,0x42,0x42, 0xb8,0xd0,0x68,0x68, 
0xc3,0x82,0x41,0x41, 0xb0,0x29,0x99,0x99, 0x77,0x5a,0x2d,0x2d, 0x11,0x1e,0x0f,0x0f, 
0xcb,0x7b,0xb0,0xb0, 0xfc,0xa8,0x54,0x54, 0xd6,0x6d,0xbb,0xbb, 0x3a,0x2c,0x16,0x16
};

static const UINT8 T3[256][4] = {
0x63,0xa5,0xc6,0x63, 0x7c,0x84,0xf8,0x7c, 0x77,0x99,0xee,0x77, 0x7b,0x8d,0xf6,0x7b, 
0xf2,0x0d,0xff,0xf2, 0x6b,0xbd,0xd6,0x6b, 0x6f,0xb1,0xde,0x6f, 0xc5,0x54,0x91,0xc5, 
0x30,0x50,0x60,0x30, 0x01,0x03,0x02,0x01, 0x67,0xa9,0xce,0x67, 0x2b,0x7d,0x56,0x2b, 
0xfe,0x19,0xe7,0xfe, 0xd7,0x62,0xb5,0xd7, 0xab,0xe6,0x4d,0xab, 0x76,0x9a,0xec,0x76, 
0xca,0x45,0x8f,0xca, 0x82,0x9d,0x1f,0x82, 0xc9,0x40,0x89,0xc9, 0x7d,0x87,0xfa,0x7d, 
0xfa,0x15,0xef,0xfa, 0x59,0xeb,0xb2,0x59, 0x47,0xc9,0x8e,0x47, 0xf0,0x0b,0xfb,0xf0, 
0xad,0xec,0x41,0xad, 0xd4,0x67,0xb3,0xd4, 0xa2,0xfd,0x5f,0xa2, 0xaf,0xea,0x45,0xaf, 
0x9c,0xbf,0x23,0x9c, 0xa4,0xf7,0x53,0xa4, 0x72,0x96,0xe4,0x72, 0xc0,0x5b,0x9b,0xc0, 
0xb7,0xc2,0x75,0xb7, 0xfd,0x1c,0xe1,0xfd, 0x93,0xae,0x3d,0x93, 0x26,0x6a,0x4c,0x26, 
0x36,0x5a,0x6c,0x36, 0x3f,0x41,0x7e,0x3f, 0xf7,0x02,0xf5,0xf7, 0xcc,0x4f,0x83,0xcc, 
0x34,0x5c,0x68,0x34, 0xa5,0xf4,0x51,0xa5, 0xe5,0x34,0xd1,0xe5, 0xf1,0x08,0xf9,0xf1, 
0x71,0x93,0xe2,0x71, 0xd8,0x73,0xab,0xd8, 0x31,0x53,0x62,0x31, 0x15,0x3f,0x2a,0x15, 
0x04,0x0c,0x08,0x04, 0xc7,0x52,0x95,0xc7, 0x23,0x65,0x46,0x23, 0xc3,0x5e,0x9d,0xc3, 
0x18,0x28,0x30,0x18, 0x96,0xa1,0x37,0x96, 0x05,0x0f,0x0a,0x05, 0x9a,0xb5,0x2f,0x9a, 
0x07,0x09,0x0e,0x07, 0x12,0x36,0x24,0x12, 0x80,0x9b,0x1b,0x80, 0xe2,0x3d,0xdf,0xe2, 
0xeb,0x26,0xcd,0xeb, 0x27,0x69,0x4e,0x27, 0xb2,0xcd,0x7f,0xb2, 0x75,0x9f,0xea,0x75, 
0x09,0x1b,0x12,0x09, 0x83,0x9e,0x1d,0x83, 0x2c,0x74,0x58,0x2c, 0x1a,0x2e,0x34,0x1a, 
0x1b,0x2d,0x36,0x1b, 0x6e,0xb2,0xdc,0x6e, 0x5a,0xee,0xb4,0x5a, 0xa0,0xfb,0x5b,0xa0, 
0x52,0xf6,0xa4,0x52, 0x3b,0x4d,0x76,0x3b, 0xd6,0x61,0xb7,0xd6, 0xb3,0xce,0x7d,0xb3, 
0x29,0x7b,0x52,0x29, 0xe3,0x3e,0xdd,0xe3, 0x2f,0x71,0x5e,0x2f, 0x84,0x97,0x13,0x84, 
0x53,0xf5,0xa6,0x53, 0xd1,0x68,0xb9,0xd1, 0x00,0x00,0x00,0x00, 0xed,0x2c,0xc1,0xed, 
0x20,0x60,0x40,0x20, 0xfc,0x1f,0xe3,0xfc, 0xb1,0xc8,0x79,0xb1, 0x5b,0xed,0xb6,0x5b, 
0x6a,0xbe,0xd4,0x6a, 0xcb,0x46,0x8d,0xcb, 0xbe,0xd9,0x67,0xbe, 0x39,0x4b,0x72,0x39, 
0x4a,0xde,0x94,0x4a, 0x4c,0xd4,0x98,0x4c, 0x58,0xe8,0xb0,0x58, 0xcf,0x4a,0x85,0xcf, 
0xd0,0x6b,0xbb,0xd0, 0xef,0x2a,0xc5,0xef, 0xaa,0xe5,0x4f,0xaa, 0xfb,0x16,0xed,0xfb, 
0x43,0xc5,0x86,0x43, 0x4d,0xd7,0x9a,0x4d, 0x33,0x55,0x66,0x33, 0x85,0x94,0x11,0x85, 
0x45,0xcf,0x8a,0x45, 0xf9,0x10,0xe9,0xf9, 0x02,0x06,0x04,0x02, 0x7f,0x81,0xfe,0x7f, 
0x50,0xf0,0xa0,0x50, 0x3c,0x44,0x78,0x3c, 0x9f,0xba,0x25,0x9f, 0xa8,0xe3,0x4b,0xa8, 
0x51,0xf3,0xa2,0x51, 0xa3,0xfe,0x5d,0xa3, 0x40,0xc0,0x80,0x40, 0x8f,0x8a,0x05,0x8f, 
0x92,0xad,0x3f,0x92, 0x9d,0xbc,0x21,0x9d, 0x38,0x48,0x70,0x38, 0xf5,0x04,0xf1,0xf5, 
0xbc,0xdf,0x63,0xbc, 0xb6,0xc1,0x77,0xb6, 0xda,0x75,0xaf,0xda, 0x21,0x63,0x42,0x21, 
0x10,0x30,0x20,0x10, 0xff,0x1a,0xe5,0xff, 0xf3,0x0e,0xfd,0xf3, 0xd2,0x6d,0xbf,0xd2, 
0xcd,0x4c,0x81,0xcd, 0x0c,0x14,0x18,0x0c, 0x13,0x35,0x26,0x13, 0xec,0x2f,0xc3,0xec, 
0x5f,0xe1,0xbe,0x5f, 0x97,0xa2,0x35,0x97, 0x44,0xcc,0x88,0x44, 0x17,0x39,0x2e,0x17, 
0xc4,0x57,0x93,0xc4, 0xa7,0xf2,0x55,0xa7, 0x7e,0x82,0xfc,0x7e, 0x3d,0x47,0x7a,0x3d, 
0x64,0xac,0xc8,0x64, 0x5d,0xe7,0xba,0x5d, 0x19,0x2b,0x32,0x19, 0x73,0x95,0xe6,0x73, 
0x60,0xa0,0xc0,0x60, 0x81,0x98,0x19,0x81, 0x4f,0xd1,0x9e,0x4f, 0xdc,0x7f,0xa3,0xdc, 
0x22,0x66,0x44,0x22, 0x2a,0x7e,0x54,0x2a, 0x90,0xab,0x3b,0x90, 0x88,0x83,0x0b,0x88, 
0x46,0xca,0x8c,0x46, 0xee,0x29,0xc7,0xee, 0xb8,0xd3,0x6b,0xb8, 0x14,0x3c,0x28,0x14, 
0xde,0x79,0xa7,0xde, 0x5e,0xe2,0xbc,0x5e, 0x0b,0x1d,0x16,0x0b, 0xdb,0x76,0xad,0xdb, 
0xe0,0x3b,0xdb,0xe0, 0x32,0x56,0x64,0x32, 0x3a,0x4e,0x74,0x3a, 0x0a,0x1e,0x14,0x0a, 
0x49,0xdb,0x92,0x49, 0x06,0x0a,0x0c,0x06, 0x24,0x6c,0x48,0x24, 0x5c,0xe4,0xb8,0x5c, 
0xc2,0x5d,0x9f,0xc2, 0xd3,0x6e,0xbd,0xd3, 0xac,0xef,0x43,0xac, 0x62,0xa6,0xc4,0x62, 
0x91,0xa8,0x39,0x91, 0x95,0xa4,0x31,0x95, 0xe4,0x37,0xd3,0xe4, 0x79,0x8b,0xf2,0x79, 
0xe7,0x32,0xd5,0xe7, 0xc8,0x43,0x8b,0xc8, 0x37,0x59,0x6e,0x37, 0x6d,0xb7,0xda,0x6d, 
0x8d,0x8c,0x01,0x8d, 0xd5,0x64,0xb1,0xd5, 0x4e,0xd2,0x9c,0x4e, 0xa9,0xe0,0x49,0xa9, 
0x6c,0xb4,0xd8,0x6c, 0x56,0xfa,0xac,0x56, 0xf4,0x07,0xf3,0xf4, 0xea,0x25,0xcf,0xea, 
0x65,0xaf,0xca,0x65, 0x7a,0x8e,0xf4,0x7a, 0xae,0xe9,0x47,0xae, 0x08,0x18,0x10,0x08, 
0xba,0xd5,0x6f,0xba, 0x78,0x88,0xf0,0x78, 0x25,0x6f,0x4a,0x25, 0x2e,0x72,0x5c,0x2e, 
0x1c,0x24,0x38,0x1c, 0xa6,0xf1,0x57,0xa6, 0xb4,0xc7,0x73,0xb4, 0xc6,0x51,0x97,0xc6, 
0xe8,0x23,0xcb,0xe8, 0xdd,0x7c,0xa1,0xdd, 0x74,0x9c,0xe8,0x74, 0x1f,0x21,0x3e,0x1f, 
0x4b,0xdd,0x96,0x4b, 0xbd,0xdc,0x61,0xbd, 0x8b,0x86,0x0d,0x8b, 0x8a,0x85,0x0f,0x8a, 
0x70,0x90,0xe0,0x70, 0x3e,0x42,0x7c,0x3e, 0xb5,0xc4,0x71,0xb5, 0x66,0xaa,0xcc,0x66, 
0x48,0xd8,0x90,0x48, 0x03,0x05,0x06,0x03, 0xf6,0x01,0xf7,0xf6, 0x0e,0x12,0x1c,0x0e, 
0x61,0xa3,0xc2,0x61, 0x35,0x5f,0x6a,0x35, 0x57,0xf9,0xae,0x57, 0xb9,0xd0,0x69,0xb9, 
0x86,0x91,0x17,0x86, 0xc1,0x58,0x99,0xc1, 0x1d,0x27,0x3a,0x1d, 0x9e,0xb9,0x27,0x9e, 
0xe1,0x38,0xd9,0xe1, 0xf8,0x13,0xeb,0xf8, 0x98,0xb3,0x2b,0x98, 0x11,0x33,0x22,0x11, 
0x69,0xbb,0xd2,0x69, 0xd9,0x70,0xa9,0xd9, 0x8e,0x89,0x07,0x8e, 0x94,0xa7,0x33,0x94, 
0x9b,0xb6,0x2d,0x9b, 0x1e,0x22,0x3c,0x1e, 0x87,0x92,0x15,0x87, 0xe9,0x20,0xc9,0xe9, 
0xce,0x49,0x87,0xce, 0x55,0xff,0xaa,0x55, 0x28,0x78,0x50,0x28, 0xdf,0x7a,0xa5,0xdf, 
0x8c,0x8f,0x03,0x8c, 0xa1,0xf8,0x59,0xa1, 0x89,0x80,0x09,0x89, 0x0d,0x17,0x1a,0x0d, 
0xbf,0xda,0x65,0xbf, 0xe6,0x31,0xd7,0xe6, 0x42,0xc6,0x84,0x42, 0x68,0xb8,0xd0,0x68, 
0x41,0xc3,0x82,0x41, 0x99,0xb0,0x29,0x99, 0x2d,0x77,0x5a,0x2d, 0x0f,0x11,0x1e,0x0f, 
0xb0,0xcb,0x7b,0xb0, 0x54,0xfc,0xa8,0x54, 0xbb,0xd6,0x6d,0xbb, 0x16,0x3a,0x2c,0x16
};

static const UINT8 T4[256][4] = {
0x63,0x63,0xa5,0xc6, 0x7c,0x7c,0x84,0xf8, 0x77,0x77,0x99,0xee, 0x7b,0x7b,0x8d,0xf6, 
0xf2,0xf2,0x0d,0xff, 0x6b,0x6b,0xbd,0xd6, 0x6f,0x6f,0xb1,0xde, 0xc5,0xc5,0x54,0x91, 
0x30,0x30,0x50,0x60, 0x01,0x01,0x03,0x02, 0x67,0x67,0xa9,0xce, 0x2b,0x2b,0x7d,0x56, 
0xfe,0xfe,0x19,0xe7, 0xd7,0xd7,0x62,0xb5, 0xab,0xab,0xe6,0x4d, 0x76,0x76,0x9a,0xec, 
0xca,0xca,0x45,0x8f, 0x82,0x82,0x9d,0x1f, 0xc9,0xc9,0x40,0x89, 0x7d,0x7d,0x87,0xfa, 
0xfa,0xfa,0x15,0xef, 0x59,0x59,0xeb,0xb2, 0x47,0x47,0xc9,0x8e, 0xf0,0xf0,0x0b,0xfb, 
0xad,0xad,0xec,0x41, 0xd4,0xd4,0x67,0xb3, 0xa2,0xa2,0xfd,0x5f, 0xaf,0xaf,0xea,0x45, 
0x9c,0x9c,0xbf,0x23, 0xa4,0xa4,0xf7,0x53, 0x72,0x72,0x96,0xe4, 0xc0,0xc0,0x5b,0x9b, 
0xb7,0xb7,0xc2,0x75, 0xfd,0xfd,0x1c,0xe1, 0x93,0x93,0xae,0x3d, 0x26,0x26,0x6a,0x4c, 
0x36,0x36,0x5a,0x6c, 0x3f,0x3f,0x41,0x7e, 0xf7,0xf7,0x02,0xf5, 0xcc,0xcc,0x4f,0x83, 
0x34,0x34,0x5c,0x68, 0xa5,0xa5,0xf4,0x51, 0xe5,0xe5,0x34,0xd1, 0xf1,0xf1,0x08,0xf9, 
0x71,0x71,0x93,0xe2, 0xd8,0xd8,0x73,0xab, 0x31,0x31,0x53,0x62, 0x15,0x15,0x3f,0x2a, 
0x04,0x04,0x0c,0x08, 0xc7,0xc7,0x52,0x95, 0x23,0x23,0x65,0x46, 0xc3,0xc3,0x5e,0x9d, 
0x18,0x18,0x28,0x30, 0x96,0x96,0xa1,0x37, 0x05,0x05,0x0f,0x0a, 0x9a,0x9a,0xb5,0x2f, 
0x07,0x07,0x09,0x0e, 0x12,0x12,0x36,0x24, 0x80,0x80,0x9b,0x1b, 0xe2,0xe2,0x3d,0xdf, 
0xeb,0xeb,0x26,0xcd, 0x27,0x27,0x69,0x4e, 0xb2,0xb2,0xcd,0x7f, 0x75,0x75,0x9f,0xea, 
0x09,0x09,0x1b,0x12, 0x83,0x83,0x9e,0x1d, 0x2c,0x2c,0x74,0x58, 0x1a,0x1a,0x2e,0x34, 
0x1b,0x1b,0x2d,0x36, 0x6e,0x6e,0xb2,0xdc, 0x5a,0x5a,0xee,0xb4, 0xa0,0xa0,0xfb,0x5b, 
0x52,0x52,0xf6,0xa4, 0x3b,0x3b,0x4d,0x76, 0xd6,0xd6,0x61,0xb7, 0xb3,0xb3,0xce,0x7d, 
0x29,0x29,0x7b,0x52, 0xe3,0xe3,0x3e,0xdd, 0x2f,0x2f,0x71,0x5e, 0x84,0x84,0x97,0x13, 
0x53,0x53,0xf5,0xa6, 0xd1,0xd1,0x68,0xb9, 0x00,0x00,0x00,0x00, 0xed,0xed,0x2c,0xc1, 
0x20,0x20,0x60,0x40, 0xfc,0xfc,0x1f,0xe3, 0xb1,0xb1,0xc8,0x79, 0x5b,0x5b,0xed,0xb6, 
0x6a,0x6a,0xbe,0xd4, 0xcb,0xcb,0x46,0x8d, 0xbe,0xbe,0xd9,0x67, 0x39,0x39,0x4b,0x72, 
0x4a,0x4a,0xde,0x94, 0x4c,0x4c,0xd4,0x98, 0x58,0x58,0xe8,0xb0, 0xcf,0xcf,0x4a,0x85, 
0xd0,0xd0,0x6b,0xbb, 0xef,0xef,0x2a,0xc5, 0xaa,0xaa,0xe5,0x4f, 0xfb,0xfb,0x16,0xed, 
0x43,0x43,0xc5,0x86, 0x4d,0x4d,0xd7,0x9a, 0x33,0x33,0x55,0x66, 0x85,0x85,0x94,0x11, 
0x45,0x45,0xcf,0x8a, 0xf9,0xf9,0x10,0xe9, 0x02,0x02,0x06,0x04, 0x7f,0x7f,0x81,0xfe, 
0x50,0x50,0xf0,0xa0, 0x3c,0x3c,0x44,0x78, 0x9f,0x9f,0xba,0x25, 0xa8,0xa8,0xe3,0x4b, 
0x51,0x51,0xf3,0xa2, 0xa3,0xa3,0xfe,0x5d, 0x40,0x40,0xc0,0x80, 0x8f,0x8f,0x8a,0x05, 
0x92,0x92,0xad,0x3f, 0x9d,0x9d,0xbc,0x21, 0x38,0x38,0x48,0x70, 0xf5,0xf5,0x04,0xf1, 
0xbc,0xbc,0xdf,0x63, 0xb6,0xb6,0xc1,0x77, 0xda,0xda,0x75,0xaf, 0x21,0x21,0x63,0x42, 
0x10,0x10,0x30,0x20, 0xff,0xff,0x1a,0xe5, 0xf3,0xf3,0x0e,0xfd, 0xd2,0xd2,0x6d,0xbf, 
0xcd,0xcd,0x4c,0x81, 0x0c,0x0c,0x14,0x18, 0x13,0x13,0x35,0x26, 0xec,0xec,0x2f,0xc3, 
0x5f,0x5f,0xe1,0xbe, 0x97,0x97,0xa2,0x35, 0x44,0x44,0xcc,0x88, 0x17,0x17,0x39,0x2e, 
0xc4,0xc4,0x57,0x93, 0xa7,0xa7,0xf2,0x55, 0x7e,0x7e,0x82,0xfc, 0x3d,0x3d,0x47,0x7a, 
0x64,0x64,0xac,0xc8, 0x5d,0x5d,0xe7,0xba, 0x19,0x19,0x2b,0x32, 0x73,0x73,0x95,0xe6, 
0x60,0x60,0xa0,0xc0, 0x81,0x81,0x98,0x19, 0x4f,0x4f,0xd1,0x9e, 0xdc,0xdc,0x7f,0xa3, 
0x22,0x22,0x66,0x44, 0x2a,0x2a,0x7e,0x54, 0x90,0x90,0xab,0x3b, 0x88,0x88,0x83,0x0b, 
0x46,0x46,0xca,0x8c, 0xee,0xee,0x29,0xc7, 0xb8,0xb8,0xd3,0x6b, 0x14,0x14,0x3c,0x28, 
0xde,0xde,0x79,0xa7, 0x5e,0x5e,0xe2,0xbc, 0x0b,0x0b,0x1d,0x16, 0xdb,0xdb,0x76,0xad, 
0xe0,0xe0,0x3b,0xdb, 0x32,0x32,0x56,0x64, 0x3a,0x3a,0x4e,0x74, 0x0a,0x0a,0x1e,0x14, 
0x49,0x49,0xdb,0x92, 0x06,0x06,0x0a,0x0c, 0x24,0x24,0x6c,0x48, 0x5c,0x5c,0xe4,0xb8, 
0xc2,0xc2,0x5d,0x9f, 0xd3,0xd3,0x6e,0xbd, 0xac,0xac,0xef,0x43, 0x62,0x62,0xa6,0xc4, 
0x91,0x91,0xa8,0x39, 0x95,0x95,0xa4,0x31, 0xe4,0xe4,0x37,0xd3, 0x79,0x79,0x8b,0xf2, 
0xe7,0xe7,0x32,0xd5, 0xc8,0xc8,0x43,0x8b, 0x37,0x37,0x59,0x6e, 0x6d,0x6d,0xb7,0xda, 
0x8d,0x8d,0x8c,0x01, 0xd5,0xd5,0x64,0xb1, 0x4e,0x4e,0xd2,0x9c, 0xa9,0xa9,0xe0,0x49, 
0x6c,0x6c,0xb4,0xd8, 0x56,0x56,0xfa,0xac, 0xf4,0xf4,0x07,0xf3, 0xea,0xea,0x25,0xcf, 
0x65,0x65,0xaf,0xca, 0x7a,0x7a,0x8e,0xf4, 0xae,0xae,0xe9,0x47, 0x08,0x08,0x18,0x10, 
0xba,0xba,0xd5,0x6f, 0x78,0x78,0x88,0xf0, 0x25,0x25,0x6f,0x4a, 0x2e,0x2e,0x72,0x5c, 
0x1c,0x1c,0x24,0x38, 0xa6,0xa6,0xf1,0x57, 0xb4,0xb4,0xc7,0x73, 0xc6,0xc6,0x51,0x97, 
0xe8,0xe8,0x23,0xcb, 0xdd,0xdd,0x7c,0xa1, 0x74,0x74,0x9c,0xe8, 0x1f,0x1f,0x21,0x3e, 
0x4b,0x4b,0xdd,0x96, 0xbd,0xbd,0xdc,0x61, 0x8b,0x8b,0x86,0x0d, 0x8a,0x8a,0x85,0x0f, 
0x70,0x70,0x90,0xe0, 0x3e,0x3e,0x42,0x7c, 0xb5,0xb5,0xc4,0x71, 0x66,0x66,0xaa,0xcc, 
0x48,0x48,0xd8,0x90, 0x03,0x03,0x05,0x06, 0xf6,0xf6,0x01,0xf7, 0x0e,0x0e,0x12,0x1c, 
0x61,0x61,0xa3,0xc2, 0x35,0x35,0x5f,0x6a, 0x57,0x57,0xf9,0xae, 0xb9,0xb9,0xd0,0x69, 
0x86,0x86,0x91,0x17, 0xc1,0xc1,0x58,0x99, 0x1d,0x1d,0x27,0x3a, 0x9e,0x9e,0xb9,0x27, 
0xe1,0xe1,0x38,0xd9, 0xf8,0xf8,0x13,0xeb, 0x98,0x98,0xb3,0x2b, 0x11,0x11,0x33,0x22, 
0x69,0x69,0xbb,0xd2, 0xd9,0xd9,0x70,0xa9, 0x8e,0x8e,0x89,0x07, 0x94,0x94,0xa7,0x33, 
0x9b,0x9b,0xb6,0x2d, 0x1e,0x1e,0x22,0x3c, 0x87,0x87,0x92,0x15, 0xe9,0xe9,0x20,0xc9, 
0xce,0xce,0x49,0x87, 0x55,0x55,0xff,0xaa, 0x28,0x28,0x78,0x50, 0xdf,0xdf,0x7a,0xa5, 
0x8c,0x8c,0x8f,0x03, 0xa1,0xa1,0xf8,0x59, 0x89,0x89,0x80,0x09, 0x0d,0x0d,0x17,0x1a, 
0xbf,0xbf,0xda,0x65, 0xe6,0xe6,0x31,0xd7, 0x42,0x42,0xc6,0x84, 0x68,0x68,0xb8,0xd0, 
0x41,0x41,0xc3,0x82, 0x99,0x99,0xb0,0x29, 0x2d,0x2d,0x77,0x5a, 0x0f,0x0f,0x11,0x1e, 
0xb0,0xb0,0xcb,0x7b, 0x54,0x54,0xfc,0xa8, 0xbb,0xbb,0xd6,0x6d, 0x16,0x16,0x3a,0x2c
};

UINT32 rcon[30] = { 
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
  0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
  0xc5, 0x91
};

#define KC				(UMAC_KEY_LEN / 4)

int aes_setup(UINT8 key[UMAC_KEY_LEN], aes_int_key W) {
	/* Calculate the necessary round keys
	 * The number of calculations depends on keyBits and blockBits
	 */ 
	int i,j, r, t, rconpointer = 0;
	UINT8 tk[KC][4];

	for (i = 0; i < UMAC_KEY_LEN; i++) {
		tk[i >> 2][i & 3] = (UINT8)key[i]; 
	}

	r = 0;
	t = 0;
	/* copy values into round key array */
	for (j = 0; (j < KC) && (r < ROUNDS + 1); ) {
		for (; (j < KC) && (t < 4); j++, t++) {
			*((UINT32*)W[r][t]) = *((UINT32*)tk[j]);
		}
		if (t == 4) {
			r++;
			t = 0;
		}
	}
		
	while (r < ROUNDS + 1) { /* while not enough round key material calculated */
		/* calculate new values */
		tk[0][0] ^= S[tk[KC-1][1]];
		tk[0][1] ^= S[tk[KC-1][2]];
		tk[0][2] ^= S[tk[KC-1][3]];
		tk[0][3] ^= S[tk[KC-1][0]];
		tk[0][0] ^= rcon[rconpointer++];

		if (KC != 8) {
			for (j = 1; j < KC; j++) {
				*((UINT32*)tk[j]) ^= *((UINT32*)tk[j-1]);
			}
		} else {
			for (j = 1; j < KC/2; j++) {
				*((UINT32*)tk[j]) ^= *((UINT32*)tk[j-1]);
			}
			tk[KC/2][0] ^= S[tk[KC/2 - 1][0]];
			tk[KC/2][1] ^= S[tk[KC/2 - 1][1]];
			tk[KC/2][2] ^= S[tk[KC/2 - 1][2]];
			tk[KC/2][3] ^= S[tk[KC/2 - 1][3]];
			for (j = KC/2 + 1; j < KC; j++) {
				*((UINT32*)tk[j]) ^= *((UINT32*)tk[j-1]);
			}
		}
		/* copy values into round key array */
		for (j = 0; (j < KC) && (r < ROUNDS + 1); ) {
			for (; (j < KC) && (t < 4); j++, t++) {
				*((UINT32*)W[r][t]) = *((UINT32*)tk[j]);
			}
			if (t == 4) {
				r++;
				t = 0;
			}
		}
	}		
	return 0;
}

/**
 * Encrypt a single block. 
 */
int aes(UINT8 a[16], UINT8 b[16], aes_int_key rk) {
	int r;
	UINT8 temp[4][4];

    *((UINT32*)temp[0]) = *((UINT32*)(a   )) ^ *((UINT32*)rk[0][0]);
    *((UINT32*)temp[1]) = *((UINT32*)(a+ 4)) ^ *((UINT32*)rk[0][1]);
    *((UINT32*)temp[2]) = *((UINT32*)(a+ 8)) ^ *((UINT32*)rk[0][2]);
    *((UINT32*)temp[3]) = *((UINT32*)(a+12)) ^ *((UINT32*)rk[0][3]);
    *((UINT32*)(b    )) = *((UINT32*)T1[temp[0][0]])
						^ *((UINT32*)T2[temp[1][1]])
						^ *((UINT32*)T3[temp[2][2]]) 
						^ *((UINT32*)T4[temp[3][3]]);
    *((UINT32*)(b + 4)) = *((UINT32*)T1[temp[1][0]])
						^ *((UINT32*)T2[temp[2][1]])
						^ *((UINT32*)T3[temp[3][2]]) 
						^ *((UINT32*)T4[temp[0][3]]);
    *((UINT32*)(b + 8)) = *((UINT32*)T1[temp[2][0]])
						^ *((UINT32*)T2[temp[3][1]])
						^ *((UINT32*)T3[temp[0][2]]) 
						^ *((UINT32*)T4[temp[1][3]]);
    *((UINT32*)(b +12)) = *((UINT32*)T1[temp[3][0]])
						^ *((UINT32*)T2[temp[0][1]])
						^ *((UINT32*)T3[temp[1][2]]) 
						^ *((UINT32*)T4[temp[2][3]]);
	for (r = 1; r < ROUNDS-1; r++) {
		*((UINT32*)temp[0]) = *((UINT32*)(b   )) ^ *((UINT32*)rk[r][0]);
		*((UINT32*)temp[1]) = *((UINT32*)(b+ 4)) ^ *((UINT32*)rk[r][1]);
		*((UINT32*)temp[2]) = *((UINT32*)(b+ 8)) ^ *((UINT32*)rk[r][2]);
		*((UINT32*)temp[3]) = *((UINT32*)(b+12)) ^ *((UINT32*)rk[r][3]);

		*((UINT32*)(b    )) = *((UINT32*)T1[temp[0][0]])
							^ *((UINT32*)T2[temp[1][1]])
							^ *((UINT32*)T3[temp[2][2]]) 
							^ *((UINT32*)T4[temp[3][3]]);
		*((UINT32*)(b + 4)) = *((UINT32*)T1[temp[1][0]])
							^ *((UINT32*)T2[temp[2][1]])
							^ *((UINT32*)T3[temp[3][2]]) 
							^ *((UINT32*)T4[temp[0][3]]);
		*((UINT32*)(b + 8)) = *((UINT32*)T1[temp[2][0]])
							^ *((UINT32*)T2[temp[3][1]])
							^ *((UINT32*)T3[temp[0][2]]) 
							^ *((UINT32*)T4[temp[1][3]]);
		*((UINT32*)(b +12)) = *((UINT32*)T1[temp[3][0]])
							^ *((UINT32*)T2[temp[0][1]])
							^ *((UINT32*)T3[temp[1][2]]) 
							^ *((UINT32*)T4[temp[2][3]]);
	}
	/* last round is special */   
	*((UINT32*)temp[0]) = *((UINT32*)(b   )) ^ *((UINT32*)rk[ROUNDS-1][0]);
	*((UINT32*)temp[1]) = *((UINT32*)(b+ 4)) ^ *((UINT32*)rk[ROUNDS-1][1]);
	*((UINT32*)temp[2]) = *((UINT32*)(b+ 8)) ^ *((UINT32*)rk[ROUNDS-1][2]);
	*((UINT32*)temp[3]) = *((UINT32*)(b+12)) ^ *((UINT32*)rk[ROUNDS-1][3]);
	b[ 0] = T1[temp[0][0]][1];
	b[ 1] = T1[temp[1][1]][1];
	b[ 2] = T1[temp[2][2]][1];
	b[ 3] = T1[temp[3][3]][1];
	b[ 4] = T1[temp[1][0]][1];
	b[ 5] = T1[temp[2][1]][1];
	b[ 6] = T1[temp[3][2]][1];
	b[ 7] = T1[temp[0][3]][1];
	b[ 8] = T1[temp[2][0]][1];
	b[ 9] = T1[temp[3][1]][1];
	b[10] = T1[temp[0][2]][1];
	b[11] = T1[temp[1][3]][1];
	b[12] = T1[temp[3][0]][1];
	b[13] = T1[temp[0][1]][1];
	b[14] = T1[temp[1][2]][1];
	b[15] = T1[temp[2][3]][1];
	*((UINT32*)(b   )) ^= *((UINT32*)rk[ROUNDS][0]);
	*((UINT32*)(b+ 4)) ^= *((UINT32*)rk[ROUNDS][1]);
	*((UINT32*)(b+ 8)) ^= *((UINT32*)rk[ROUNDS][2]);
	*((UINT32*)(b+12)) ^= *((UINT32*)rk[ROUNDS][3]);

	return 0;
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The user-supplied UMAC key is stretched using AES in an output feedback
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * and AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'buffer_ptr'. Each distinct
 * 'index' causes a distinct byte stream.
 */
static void kdf(void *buffer_ptr, aes_int_key key, UINT8 index, int nbytes)
{
    UINT8 chain[AES_BLOCK_LEN] = {0};
    UINT8 *dst_buf = (UINT8 *)buffer_ptr;
    
    chain[AES_BLOCK_LEN-1] = index;
    
    while (nbytes >= AES_BLOCK_LEN) {
        aes(chain,chain,key);
        memcpy(dst_buf,chain,AES_BLOCK_LEN);
        nbytes -= AES_BLOCK_LEN;
        dst_buf += AES_BLOCK_LEN;
    }
    if (nbytes) {
        aes(chain,chain,key);
        memcpy(dst_buf,chain,nbytes);
    }
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and 
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

typedef struct {
    UINT8 cache[AES_BLOCK_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_BLOCK_LEN];  /* The AES input for the above cache */
    aes_int_key prf_key;         /* Expanded AES key for PDF  */
} pdf_ctx;

static void pdf_init(pdf_ctx *pc, aes_int_key prf_key)
{
    UINT8 buf[UMAC_KEY_LEN];
    
    kdf(buf, prf_key, 128, UMAC_KEY_LEN);
    aes_setup(buf, pc->prf_key);
    
    /* Initialize pdf and cache */
    memset(pc->nonce, 0, sizeof(pc->nonce));
    aes(pc->nonce, pc->cache, pc->prf_key);
}

static void pdf_gen_xor(pdf_ctx *pc, UINT8 nonce[8], UINT8 buf[8])
{
    /* This implementation requires UMAC_OUTPUT_LEN to divide AES_BLOCK_LEN
     * or be at least 1/2 its length. 'index' indicates that we'll be using
     * the index-th UMAC_OUTPUT_LEN-length element of the AES output. If
     * last time around we returned the index-1 element, then we may have
     * the result in the cache already.
     */
    UINT8 tmp_nonce_lo[4];
    int index = nonce[7] % (AES_BLOCK_LEN / UMAC_OUTPUT_LEN);
    
    *(UINT32 *)tmp_nonce_lo = ((UINT32 *)nonce)[1];
    tmp_nonce_lo[3] ^= index; /* zero some bits */
    
    if ( (((UINT32 *)tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)tmp_nonce_lo)[0];
        aes(pc->nonce, pc->cache, pc->prf_key);
    }
    
    #if (UMAC_OUTPUT_LEN == 2)
        *((UINT16 *)buf) ^= ((UINT16 *)pc->cache)[index];
    #elif (UMAC_OUTPUT_LEN == 4)
        *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[index];
    #elif (UMAC_OUTPUT_LEN == 8)
        *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[index];
    #elif (UMAC_OUTPUT_LEN == 12) 
        ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
        ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
    #elif (UMAC_OUTPUT_LEN == 16) 
        ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
        ((UINT64 *)buf)[1] ^= ((UINT64 *)pc->cache)[1];
    #else
        #error only 2,4,8,12,16 byte output supported.
    #endif
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin NH Hash Section ------------------------------------------ */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The NH-based hash functions used in UMAC are described in the UMAC paper
 * and specification, both of which can be found at the UMAC website.     
 * The interface to this implementation has two         
 * versions, one expects the entire message being hashed to be passed
 * in a single buffer and returns the hash result immediately. The second
 * allows the message to be passed in a sequence of buffers. In the          
 * muliple-buffer interface, the client calls the routine nh_update() as     
 * many times as necessary. When there is no more data to be fed to the   
 * hash, the client calls nh_final() which calculates the hash output.    
 * Before beginning another hash calculation the nh_reset() routine       
 * must be called. The single-buffer routine, nh(), is equivalent to  
 * the sequence of calls nh_update() and nh_final(); however it is        
 * optimized and should be prefered whenever the multiple-buffer interface
 * is not necessary. When using either interface, it is the client's         
 * responsability to pass no more than L1_KEY_LEN bytes per hash result.            
 *                                                                        
 * The routine nh_init() initializes the nh_ctx data structure and        
 * must be called once, before any other PDF routine.                     
 */
 
 /* The "nh_aux_*" routines do the actual NH hashing work. They
  * expect buffers to be multiples of L1_PAD_BOUNDARY. These routines
  * produce output for all PREFIX_STREAMS NH iterations in one call, 
  * allowing the parallel implementation of the streams.
  */
#if   (UMAC_PREFIX_LEN == 2)
#define nh_aux   nh_aux_4
#elif (UMAC_PREFIX_LEN == 4)
#define nh_aux   nh_aux_8
#elif (UMAC_PREFIX_LEN == 8)
#define nh_aux   nh_aux_16
#elif (UMAC_PREFIX_LEN == 12)
#define nh_aux   nh_aux_24
#elif (UMAC_PREFIX_LEN == 16)
#define nh_aux   nh_aux_32
#endif

#define L1_KEY_SHIFT         16     /* Toeplitz key shift between streams */
#define L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#define ALLOC_BOUNDARY       32     /* Keep buffers aligned to this       */
#define HASH_BUF_BYTES      128     /* nh_aux_hb buffer multiple          */

/* How many extra bytes are needed for Toeplitz shift? */
#define TOEPLITZ_EXTRA       ((PREFIX_STREAMS - 1) * L1_KEY_SHIFT)

typedef struct {
    UINT8  nh_key [L1_KEY_LEN + TOEPLITZ_EXTRA]; /* NH Key */
    UINT8  data   [HASH_BUF_BYTES];    /* Incomming data buffer           */
    int next_data_empty;    /* Bookeeping variable for data buffer.       */
    int bytes_hashed;        /* Bytes (out of L1_KEY_LEN) incorperated.   */
    LARGE_UWORD state[PREFIX_STREAMS];               /* on-line state     */
} nh_ctx;


/* ---------------------------------------------------------------------- */
#if (WORD_LEN == 4)
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
#if (USE_C_ONLY || ! ARCH_NH32)
/* ---------------------------------------------------------------------- */

static void nh_aux_8(void *kp, void *dp, void *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     
 * then stored via hp pointer. The length of the data pointed at by "dp",
 * "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
 * is expected to be endian compensated in memory at key setup.    
 */
{
  UINT64 h;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  UINT32 *d = (UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

  h = *((UINT64 *)hp);
  do {
    d0 = LOAD_UINT32_LITTLE(d+0); d1 = LOAD_UINT32_LITTLE(d+1);
    d2 = LOAD_UINT32_LITTLE(d+2); d3 = LOAD_UINT32_LITTLE(d+3);
    d4 = LOAD_UINT32_LITTLE(d+4); d5 = LOAD_UINT32_LITTLE(d+5);
    d6 = LOAD_UINT32_LITTLE(d+6); d7 = LOAD_UINT32_LITTLE(d+7);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    h += MUL64((k0 + d0), (k4 + d4));
    h += MUL64((k1 + d1), (k5 + d5));
    h += MUL64((k2 + d2), (k6 + d6));
    h += MUL64((k3 + d3), (k7 + d7));

    d += 8;
    k += 8;
  } while (--c);
  *((UINT64 *)hp) = h;
}

/* ---------------------------------------------------------------------- */

static void nh_aux_16(void *kp, void *dp, void *hp, UINT32 dlen)
/* Same as nh_aux_8, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  UINT32 *d = (UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  do {
    d0 = LOAD_UINT32_LITTLE(d+0); d1 = LOAD_UINT32_LITTLE(d+1);
    d2 = LOAD_UINT32_LITTLE(d+2); d3 = LOAD_UINT32_LITTLE(d+3);
    d4 = LOAD_UINT32_LITTLE(d+4); d5 = LOAD_UINT32_LITTLE(d+5);
    d6 = LOAD_UINT32_LITTLE(d+6); d7 = LOAD_UINT32_LITTLE(d+7);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    k8 = *(k+8); k9 = *(k+9); k10 = *(k+10); k11 = *(k+11);

    h1 += MUL64((k0 + d0), (k4 + d4));
    h2 += MUL64((k4 + d0), (k8 + d4));

    h1 += MUL64((k1 + d1), (k5 + d5));
    h2 += MUL64((k5 + d1), (k9 + d5));

    h1 += MUL64((k2 + d2), (k6 + d6));
    h2 += MUL64((k6 + d2), (k10 + d6));

    h1 += MUL64((k3 + d3), (k7 + d7));
    h2 += MUL64((k7 + d3), (k11 + d7));

    k0 = k8; k1 = k9; k2 = k10; k3 = k11;

    d += 8;
    k += 8;
  } while (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
#endif /* (USE_C_ONLY || ! ARCH_NH32) */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* ----- NH16 Universal Hash -------------------------------------------- */
/* ---------------------------------------------------------------------- */

#else /* WORD_LEN == 2 */


/* ---------------------------------------------------------------------- */
#if (USE_C_ONLY || ! ARCH_NH16)
/* ---------------------------------------------------------------------- */

static void nh_aux_4(void *kp, void *dp, void *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     
 * then stored via hp pointer. The length of the data pointed at by "dp",
 * "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
 * is expected to be endian compensated in memory at key setup.    
 */
{
    UINT32 h;
    UINT32 c = dlen / 32;
    UINT16 *k = (UINT16 *)kp;
    UINT16 *d = (UINT16 *)dp;

    h = *(UINT32 *)hp;
    do {
    	/* Cast to signed integers to forced signed multiplication */
        h += (INT32)(INT16)(*(k+0)  + LOAD_UINT16_LITTLE(d+0)) * 
             (INT32)(INT16)(*(k+8)  + LOAD_UINT16_LITTLE(d+8));
        h += (INT32)(INT16)(*(k+1)  + LOAD_UINT16_LITTLE(d+1)) * 
             (INT32)(INT16)(*(k+9)  + LOAD_UINT16_LITTLE(d+9));
        h += (INT32)(INT16)(*(k+2)  + LOAD_UINT16_LITTLE(d+2)) * 
             (INT32)(INT16)(*(k+10) + LOAD_UINT16_LITTLE(d+10));
        h += (INT32)(INT16)(*(k+3)  + LOAD_UINT16_LITTLE(d+3)) * 
             (INT32)(INT16)(*(k+11) + LOAD_UINT16_LITTLE(d+11));
        h += (INT32)(INT16)(*(k+4)  + LOAD_UINT16_LITTLE(d+4)) * 
             (INT32)(INT16)(*(k+12) + LOAD_UINT16_LITTLE(d+12));
        h += (INT32)(INT16)(*(k+5)  + LOAD_UINT16_LITTLE(d+5)) * 
             (INT32)(INT16)(*(k+13) + LOAD_UINT16_LITTLE(d+13));
        h += (INT32)(INT16)(*(k+6)  + LOAD_UINT16_LITTLE(d+6)) * 
             (INT32)(INT16)(*(k+14) + LOAD_UINT16_LITTLE(d+14));
        h += (INT32)(INT16)(*(k+7)  + LOAD_UINT16_LITTLE(d+7)) * 
             (INT32)(INT16)(*(k+15) + LOAD_UINT16_LITTLE(d+15));
        d += 16;
        k += 16;
    } while (--c);
    *(UINT32 *)hp = h;
}

/* ---------------------------------------------------------------------- */

static void nh_aux_8(void *kp, void *dp, void *hp, UINT32 dlen)
/* Same as nh_aux_4, but two streams are handled in one pass,
 * reading and writing 8 bytes of hash-state per call.
 */
{
    nh_aux_4(kp,dp,hp,dlen);
    nh_aux_4((UINT8 *)kp+16,dp,(UINT8 *)hp+4,dlen);
}

/* ---------------------------------------------------------------------- */

static void nh_aux_16(void *kp, void *dp, void *hp, UINT32 dlen)
/* Same as nh_aux_8, but four streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
    nh_aux_4(kp,dp,hp,dlen);
    nh_aux_4((UINT8 *)kp+16,dp,(UINT8 *)hp+4,dlen);
    nh_aux_4((UINT8 *)kp+32,dp,(UINT8 *)hp+8,dlen);
    nh_aux_4((UINT8 *)kp+48,dp,(UINT8 *)hp+12,dlen);
}

/* ---------------------------------------------------------------------- */



/* ---------------------------------------------------------------------- */
#endif  /* (USE_C_ONLY || ! ARCH_NH16)        */
/* ---------------------------------------------------------------------- */
#endif  /* WORD_LEN                           */
/* ---------------------------------------------------------------------- */

/* The following two routines use previously defined ones to build up longer
 * outputs of 24 or 32 bytes.
 */
 

/* ---------------------------------------------------------------------- */

static void nh_aux_24(void *kp, void *dp, void *hp, UINT32 dlen)
{
    nh_aux_16(kp,dp,hp,dlen);
    nh_aux_8((UINT8 *)kp+((8/WORD_LEN)*L1_KEY_SHIFT),dp,
                                           (UINT8 *)hp+16,dlen);
}

/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

static void nh_aux_32(void *kp, void *dp, void *hp, UINT32 dlen)
{
    nh_aux_16(kp,dp,hp,dlen);
    nh_aux_16((UINT8 *)kp+((8/WORD_LEN)*L1_KEY_SHIFT),
                                      dp,(UINT8 *)hp+16,dlen);
}

/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

static void nh_transform(nh_ctx *hc, UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *key;
  
    key = hc->nh_key + hc->bytes_hashed;
    nh_aux(key, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

static void endian_convert(void *buf, UWORD bpw, UINT32 num_bytes)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = num_bytes / bpw;
    if (bpw == 2) {
        UINT16 *p = (UINT16 *)buf;
        do {
            *p = ((UINT16)*p >> 8) | (*p << 8);
            p++;
        } while (--iters);
    } else if (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        do {
            *p = LOAD_UINT32_REVERSED(p);
            p++;
        } while (--iters);
    } else if (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        do {
            t = LOAD_UINT32_REVERSED(p+1);
            p[1] = LOAD_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } while (--iters);
    }
}
#if (__LITTLE_ENDIAN__)
#define endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#else
#define endian_convert_if_le(x,y,z) do{}while(0)  /* Do nothing */
#endif

/* ---------------------------------------------------------------------- */

static void nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->bytes_hashed = 0;
    hc->next_data_empty = 0;
    hc->state[0] = 0;
    #if (PREFIX_STREAMS > 1)
    hc->state[1] = 0;
    #if (PREFIX_STREAMS > 2)
    hc->state[2] = 0;
    #if (PREFIX_STREAMS > 3)
    hc->state[3] = 0;
    #if (PREFIX_STREAMS > 4)
    hc->state[4] = 0;
    hc->state[5] = 0;
    #if (PREFIX_STREAMS > 6)
    hc->state[6] = 0;
    hc->state[7] = 0;
    #endif
    #endif
    #endif
    #endif
    #endif
}

/* ---------------------------------------------------------------------- */

static void nh_init(nh_ctx *hc, aes_int_key prf_key)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    
    kdf(hc->nh_key, prf_key, 0, sizeof(hc->nh_key));
    endian_convert_if_le(hc->nh_key, WORD_LEN, sizeof(hc->nh_key));
    #if (ARCH_KEY_MODIFICATION)
    /* Some specialized code may need the key in an altered format.
     * They will define ARCH_KEY_MODIFICATION == 1 and provide a
     * arch_key_modification(UINT8 *buf, int buflen) function
     */
    arch_key_modification(hc->nh_key, sizeof(hc->nh_key));
    #endif
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

static void nh_update(nh_ctx *hc, UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;
    
    j = hc->next_data_empty;
    if ((j + nbytes) >= HASH_BUF_BYTES) {
        if (j) {
            i = HASH_BUF_BYTES - j;
            memcpy(hc->data+j, buf, i);
            nh_transform(hc,hc->data,HASH_BUF_BYTES);
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += HASH_BUF_BYTES;
        }
        if (nbytes >= HASH_BUF_BYTES) {
            /* i = nbytes - (nbytes % HASH_BUF_BYTES); */
            i = nbytes & ~(HASH_BUF_BYTES - 1);
            nh_transform(hc, buf, i); /* buf could be poorly aligned */
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += i;
        }
        j = 0;
    }
    memcpy(hc->data + j, buf, nbytes);
    hc->next_data_empty = j + nbytes;
}

/* ---------------------------------------------------------------------- */

static void zero_pad(UINT8 *p, int nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    if (nbytes >= (int)sizeof(UWORD)) {
        while ((int)p % sizeof(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        while (nbytes >= (int)sizeof(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= sizeof(UWORD);
            p += sizeof(UWORD);
        }
    }
    while (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

static void nh_final(nh_ctx *hc, UINT8 *result)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 */
{
    int nh_len, nbits;

    if (hc->next_data_empty) {
        nh_len = ((hc->next_data_empty + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->data + hc->next_data_empty, 
                                          nh_len - hc->next_data_empty);
        nh_transform(hc, hc->data, nh_len);
        hc->bytes_hashed += hc->next_data_empty;
    }
    nbits = (hc->bytes_hashed << 3);
    ((LARGE_UWORD *)result)[0] = ((LARGE_UWORD *)hc->state)[0] + nbits;
    #if (PREFIX_STREAMS > 1)
    ((LARGE_UWORD *)result)[1] = ((LARGE_UWORD *)hc->state)[1] + nbits;
    #if (PREFIX_STREAMS > 2)
    ((LARGE_UWORD *)result)[2] = ((LARGE_UWORD *)hc->state)[2] + nbits;
    #if (PREFIX_STREAMS > 3)
    ((LARGE_UWORD *)result)[3] = ((LARGE_UWORD *)hc->state)[3] + nbits;
    #if (PREFIX_STREAMS > 4)
    ((LARGE_UWORD *)result)[4] = ((LARGE_UWORD *)hc->state)[4] + nbits;
    ((LARGE_UWORD *)result)[5] = ((LARGE_UWORD *)hc->state)[5] + nbits;
    #if (PREFIX_STREAMS > 6)
    ((LARGE_UWORD *)result)[6] = ((LARGE_UWORD *)hc->state)[6] + nbits;
    ((LARGE_UWORD *)result)[7] = ((LARGE_UWORD *)hc->state)[7] + nbits;
    #endif
    #endif
    #endif
    #endif
    #endif
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

static void nh(nh_ctx *hc, UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *result)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;
    
    /* Initialize the hash state */
    nbits = (unpadded_len << 3);
    
    ((LARGE_UWORD *)result)[0] = nbits;
    #if (PREFIX_STREAMS > 1)
    ((LARGE_UWORD *)result)[1] = nbits;
    #if (PREFIX_STREAMS > 2)
    ((LARGE_UWORD *)result)[2] = nbits;
    #if (PREFIX_STREAMS > 3)
    ((LARGE_UWORD *)result)[3] = nbits;
    #if (PREFIX_STREAMS > 4)
    ((LARGE_UWORD *)result)[4] = nbits;
    ((LARGE_UWORD *)result)[5] = nbits;
    #if (PREFIX_STREAMS > 6)
    ((LARGE_UWORD *)result)[6] = nbits;
    ((LARGE_UWORD *)result)[7] = nbits;
    #endif
    #endif
    #endif
    #endif
    #endif
    
    nh_aux(hc->nh_key, buf, result, padded_len);
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin UHASH Section -------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UHASH is a multi-layered algorithm. Data presented to UHASH is first
 * hashed by NH. The NH output is then hashed by a polynomial-hash layer
 * unless the initial data to be hashed is short. After the polynomial-
 * layer, an inner-product hash is used to produce the final UHASH output.
 *
 * UHASH provides two interfaces, one all-at-once and another where data
 * buffers are presented sequentially. In the sequential interface, the
 * UHASH client calls the routine uhash_update() as many times as necessary.
 * When there is no more data to be fed to UHASH, the client calls
 * uhash_final() which          
 * calculates the UHASH output. Before beginning another UHASH calculation    
 * the uhash_reset() routine must be called. The all-at-once UHASH routine,   
 * uhash(), is equivalent to the sequence of calls uhash_update() and         
 * uhash_final(); however it is optimized and should be                     
 * used whenever the sequential interface is not necessary.              
 *                                                                        
 * The routine uhash_init() initializes the uhash_ctx data structure and    
 * must be called once, before any other UHASH routine.
 */                                                        

/* ---------------------------------------------------------------------- */
/* ----- PDF Constants and uhash_ctx ------------------------------------ */
/* ---------------------------------------------------------------------- */



/* ---------------------------------------------------------------------- */

typedef struct uhash_ctx {
    nh_ctx hash;                        /* Hash context for L1 NH hash    */
    /* Extra stuff for the WORD_LEN == 2 case, where a polyhash tansition
     * may occur between p32 and p64
     */
    #if (WORD_LEN == 2)
    UINT32 poly_key_4[PREFIX_STREAMS]; /* p32 Poly keys                   */
    UINT64 poly_store[PREFIX_STREAMS]; /* To buffer NH-16 output for p64  */
    int poly_store_full;               /* Flag for poly_store             */
    UINT32 poly_invocations;           /* Number of p32 words hashed      */
    #endif
    UINT64 poly_key_8[PREFIX_STREAMS];    /* p64 poly keys                */
    UINT64 poly_accum[PREFIX_STREAMS];    /* poly hash result             */
    LARGE_UWORD ip_keys[PREFIX_STREAMS*4];/* Inner-product keys           */
    SMALL_UWORD ip_trans[PREFIX_STREAMS]; /* Inner-product translation    */
    UINT32 msg_len;               /* Total length of data passed to uhash */
} uhash_ctx;

/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */
#if (USE_C_ONLY || ! ARCH_POLY)
/* ---------------------------------------------------------------------- */

/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following impelementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */
static UINT32 poly32(UINT32 cur, UINT32 key, UINT32 data)
/* requires 29 bit keys */
{
    UINT64 t;
    UINT32 hi, lo;
    
    t = cur * (UINT64)key;
    hi = (UINT32)(t >> 32);
    lo = (UINT32)t;
    hi *= 5;
    lo += hi;
    if (lo < hi)
        lo += 5;
    lo += data;
    if (lo < data)
        lo += 5;
    return lo;
}

static UINT64 poly64(UINT64 cur, UINT64 key, UINT64 data)
{
    UINT32 key_hi = (UINT32)(key >> 32),
           key_lo = (UINT32)key,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;
    
    X =  MUL64(key_hi, cur_lo) + MUL64(cur_hi, key_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);
    
    res = (MUL64(key_hi, cur_hi) + x_hi) * 59 + MUL64(key_lo, cur_lo);
     
    T = ((UINT64)x_lo << 32);
    res += T;
    if (res < T)
        res += 59;

    res += data;
    if (res < data)
        res += 59;

    return res;
}

#endif



#if (WORD_LEN == 2)

/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * impelemtation does not handle all ramp levels. When WORD_LEN is 2, we only
 * handle the p32 and p64 modulus polynomial calculations. Because we don't
 * handle the ramp up to p128 modulus in this implementation, we are limited
 * to 2^31 poly_hash() invocations per stream (for a total capacity of 2^41
 * bytes per tag input to UMAC).
 */
const UINT32 poly_crossover = (1ul << 9);

static void poly_hash(uhash_ctx_t hc, UINT32 data[])
{
    int i;

    if (hc->poly_invocations < poly_crossover) { /* Use poly32 */
        for (i = 0; i < PREFIX_STREAMS; i++) {
            /* If the data passed in is out of range, we hash a marker
             * and then hash the data offset to be in range.
             */
            if (data[i] >= (p32-1)) {
                hc->poly_accum[i] = poly32((UINT32)hc->poly_accum[i],
                                           hc->poly_key_4[i], p32-1);
                hc->poly_accum[i] = poly32((UINT32)hc->poly_accum[i],
                                           hc->poly_key_4[i], (data[i] - 5));
            } else
                hc->poly_accum[i] = poly32((UINT32)hc->poly_accum[i], 
                                           hc->poly_key_4[i], data[i]);
        }
    } else if (hc->poly_invocations > poly_crossover) {      /* Use poly64 */
        /* We must buffer every other 32-bit word to build up a 64-bit one */
        if ( ! hc->poly_store_full) {
            for (i = 0; i < PREFIX_STREAMS; i++) {
                hc->poly_store[i] = ((UINT64)data[i]) << 32;
            }
            hc->poly_store_full = 1;
        } else {
            for (i = 0; i < PREFIX_STREAMS; i++) {
                /* If the data passed in is out of range, we hash a marker
                 * and then hash the data offset to be in range.
                 */
                if ((UINT32)(hc->poly_store[i] >> 32) == 0xfffffffful) {
                    hc->poly_accum[i] = poly64(hc->poly_accum[i], 
                                               hc->poly_key_8[i], p64 - 1);
                    hc->poly_accum[i] = poly64(hc->poly_accum[i], 
                                        hc->poly_key_8[i],
                                        (hc->poly_store[i] + data[i] - 59));
                } else {
                    hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                        hc->poly_key_8[i],
                                        hc->poly_store[i] + data[i]);
                }
                hc->poly_store_full = 0;
            }
        }
    } else { /* (hc->poly_invocations == poly_crossover) */
        /* Implement the ramp from p32 to p64 hashing    */
        for (i = 0; i < PREFIX_STREAMS; i++) {
            hc->poly_accum[i] = poly64(1, hc->poly_key_8[i],
                                       hc->poly_accum[i]);
            hc->poly_store[i] = ((UINT64)data[i]) << 32;
        }
        hc->poly_store_full = 1;
    }
    hc->poly_invocations += 1;
}

#else /* WORD_LEN == 4 */

/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * impelemtation does not handle all ramp levels. When WORD_LEN is 4, we only
 * handle the p64 modulus polynomial calculations. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes per tag input to UMAC).
 */
static void poly_hash(uhash_ctx_t hc, UINT32 data_in[])
{
/* This routine is simpler than that above because there is no ramping. */ 
    int i;
    UINT64 *data=(UINT64*)data_in;
    
    for (i = 0; i < PREFIX_STREAMS; i++) {
        if ((UINT32)(data[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i], 
                                       hc->poly_key_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_key_8[i], (data[i] - 59));
        } else {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_key_8[i], data[i]);
        }
    }
}

#endif

/* ---------------------------------------------------------------------- */

#if (WORD_LEN == 4)

/* ---------------------------------------------------------------------- */
#if (USE_C_ONLY || ! ARCH_IP)
/* ---------------------------------------------------------------------- */

/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not neccesarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */
static UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 data)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(data >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(data >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(data >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(data);
    
    return t;
}

static UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;
    
    ret = (t & m36) + 5 * (t >> 36);
    if (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    return (UINT32)(ret);
}

#endif

/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
static void ip_short(uhash_ctx_t ahc, UINT8 *nh_res, char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;
    
    t  = ip_aux(0,ahc->ip_keys, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
    #if (PREFIX_STREAMS > 1)
    t  = ip_aux(0,ahc->ip_keys+1, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
    #if (PREFIX_STREAMS > 2)
    t  = ip_aux(0,ahc->ip_keys+2, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
    #if (PREFIX_STREAMS > 3)
    t  = ip_aux(0,ahc->ip_keys+3, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
    #if (PREFIX_STREAMS > 4)
    t  = ip_aux(0,ahc->ip_keys+4, nhp[4]);
    STORE_UINT32_BIG((UINT32 *)res+4, ip_reduce_p36(t) ^ ahc->ip_trans[4]);
    t  = ip_aux(0,ahc->ip_keys+5, nhp[5]);
    STORE_UINT32_BIG((UINT32 *)res+5, ip_reduce_p36(t) ^ ahc->ip_trans[5]);
    #if (PREFIX_STREAMS > 6)
    t  = ip_aux(0,ahc->ip_keys+6, nhp[6]);
    STORE_UINT32_BIG((UINT32 *)res+6, ip_reduce_p36(t) ^ ahc->ip_trans[6]);
    t  = ip_aux(0,ahc->ip_keys+7, nhp[7]);
    STORE_UINT32_BIG((UINT32 *)res+7, ip_reduce_p36(t) ^ ahc->ip_trans[7]);
    #endif
    #endif
    #endif
    #endif
    #endif
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
static void ip_long(uhash_ctx_t ahc, char *res)
{
    int i;
    UINT64 t;

    for (i = 0; i < PREFIX_STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        if (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_keys+i, ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i, 
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */
#elif (WORD_LEN == 2)
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
#if (USE_C_ONLY || ! ARCH_IP)
/* ---------------------------------------------------------------------- */

/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not neccesarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 19 bit key.
 */
static UINT64 ip_aux(UINT64 t, UINT32 *ipkp, UINT32 data)
{
    t = t + MUL64(ipkp[0], (data >> 16));
    t = t + MUL64(ipkp[1], (UINT16)(data));
    
    return t;
}

static UINT16 ip_reduce_p19(UINT64 t)
{
/* Divisionless modular reduction */
    UINT32 ret;
    
    ret = ((UINT32)t & m19) + (UINT32)(t >> 19);
    if (ret >= p19)
        ret -= p19;

    /* return least significant 16 bits */
    return (UINT16)(ret);
}


#endif


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
static void ip_short(uhash_ctx_t ahc, UINT8 *nh_res, char *res)
{
    UINT64 t;
    UINT32 *nhp = (UINT32 *)nh_res;
    
    t  = ip_aux(0,ahc->ip_keys+2, nhp[0]);
    STORE_UINT16_BIG((UINT16 *)res+0, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[0]));
    #if (PREFIX_STREAMS > 1)
    t  = ip_aux(0,ahc->ip_keys+6, nhp[1]);
    STORE_UINT16_BIG((UINT16 *)res+1, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[1]));
    #if (PREFIX_STREAMS > 2)
    t  = ip_aux(0,ahc->ip_keys+10, nhp[2]);
    STORE_UINT16_BIG((UINT16 *)res+2, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[2]));
    #if (PREFIX_STREAMS > 3)
    t  = ip_aux(0,ahc->ip_keys+14, nhp[3]);
    STORE_UINT16_BIG((UINT16 *)res+3, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[3]));
    #if (PREFIX_STREAMS > 4)
    t  = ip_aux(0,ahc->ip_keys+18, nhp[4]);
    STORE_UINT16_BIG((UINT16 *)res+4, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[4]));
    t  = ip_aux(0,ahc->ip_keys+22, nhp[5]);
    STORE_UINT16_BIG((UINT16 *)res+5, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[5]));
    #if (PREFIX_STREAMS > 6)
    t  = ip_aux(0,ahc->ip_keys+26, nhp[6]);
    STORE_UINT16_BIG((UINT16 *)res+6, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[6]));
    t  = ip_aux(0,ahc->ip_keys+30, nhp[7]);
    STORE_UINT16_BIG((UINT16 *)res+7, 
            (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[7]));
    #endif
    #endif
    #endif
    #endif
    #endif
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
static void ip_long(uhash_ctx_t ahc, char *res)
{
    int i;
    UINT64 t;

    if (ahc->poly_invocations > poly_crossover) { /* hash 64 bits */
        for (i = 0; i < PREFIX_STREAMS; i++) {
            if (ahc->poly_accum[i] >= p64)
                ahc->poly_accum[i] -= p64;
            t = ip_aux(0,ahc->ip_keys+i*4,(UINT32)(ahc->poly_accum[i] >> 32));
            t = ip_aux(t,ahc->ip_keys+i*4+2,(UINT32)ahc->poly_accum[i]);
            /* Store result big endian for sonsistancy across architectures */
            STORE_UINT16_BIG((UINT16 *)res+i, 
                             (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[i]));
        }
    } else {                                      /* hash 32 bits */
        for (i = 0; i < PREFIX_STREAMS; i++) {
            if (ahc->poly_accum[i] >= p32)
                ahc->poly_accum[i] -= p32;
            t  = ip_aux(0,ahc->ip_keys+i*4+2,(UINT32)ahc->poly_accum[i]);
            STORE_UINT16_BIG((UINT16 *)res+i, 
                             (UINT16)(ip_reduce_p19(t) ^ ahc->ip_trans[i]));
        }
    }
}

#endif

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
int uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->msg_len = 0;
    #if (WORD_LEN == 2)
    pc->poly_invocations = 0;
    pc->poly_store_full = 0;
    #endif
    pc->poly_accum[0] = 1;
    #if (PREFIX_STREAMS > 1)
    pc->poly_accum[1] = 1;
    #if (PREFIX_STREAMS > 2)
    pc->poly_accum[2] = 1;
    #if (PREFIX_STREAMS > 3)
    pc->poly_accum[3] = 1;
    #if (PREFIX_STREAMS > 4)
    pc->poly_accum[4] = 1;
    pc->poly_accum[5] = 1;
    #if (PREFIX_STREAMS > 6)
    pc->poly_accum[6] = 1;
    pc->poly_accum[7] = 1;
    #endif
    #endif
    #endif
    #endif
    #endif
    return 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
static void uhash_init(uhash_ctx_t ahc, aes_int_key prf_key)
{
    int i;
    UINT8 buf[(8*PREFIX_STREAMS+4)*sizeof(LARGE_UWORD)];
    
    /* Zero the entire uhash context */
    memset(ahc, 0, sizeof(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_key);
    
    /* Setup L2 hash variables */
    kdf(buf, prf_key, 1, sizeof(buf));    /* Fill buffer with index 1 key */
    for (i = 0; i < PREFIX_STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        #if (WORD_LEN == 2)
        memcpy(ahc->poly_key_4+i, buf+28*i, 4);
        memcpy(ahc->poly_key_8+i, buf+28*i+4, 8);
        endian_convert_if_le(ahc->poly_key_4+i, 4, 4);
        ahc->poly_key_4[i] &= 0x1fffffff;  /* Mask to special domain */
        #elif (WORD_LEN == 4)
        memcpy(ahc->poly_key_8+i, buf+24*i, 8);
        #endif
        endian_convert_if_le(ahc->poly_key_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_key_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }
    
    /* Setup L3-1 hash variables */
    kdf(buf, prf_key, 2, sizeof(buf)); /* Fill buffer with index 2 key */
    for (i = 0; i < PREFIX_STREAMS; i++)
          memcpy(ahc->ip_keys+4*i, buf+(8*i+4)*sizeof(LARGE_UWORD),
                                                 4*sizeof(LARGE_UWORD));
    endian_convert_if_le(ahc->ip_keys, sizeof(LARGE_UWORD), 
                                                  sizeof(ahc->ip_keys));
    for (i = 0; i < PREFIX_STREAMS*4; i++)
        #if (WORD_LEN == 2)
        ahc->ip_keys[i] %= p19;  /* Bring into Z_p19 */
        #elif (WORD_LEN == 4)
        ahc->ip_keys[i] %= p36;  /* Bring into Z_p36 */
        #endif
    
    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 3 key */
    kdf(ahc->ip_trans, prf_key, 3, PREFIX_STREAMS * sizeof(SMALL_UWORD));
    endian_convert_if_le(ahc->ip_trans, sizeof(SMALL_UWORD),
                         PREFIX_STREAMS * sizeof(SMALL_UWORD));
}

/* ---------------------------------------------------------------------- */

uhash_ctx_t uhash_alloc(char key[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    char bytes_to_add;
    aes_int_key prf_key;
    
    ctx = (uhash_ctx_t)malloc(sizeof(uhash_ctx)+ALLOC_BOUNDARY);
    if (ctx) {
        if (ALLOC_BOUNDARY) {
            bytes_to_add = ALLOC_BOUNDARY - ((int)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((char *)ctx + bytes_to_add);
            *((char *)ctx - 1) = bytes_to_add;
        }
        aes_setup((UINT8 *)key, prf_key);  /* Intitialize the block-cipher */
        uhash_init(ctx, prf_key);
    }
    return (ctx);
}

/* ---------------------------------------------------------------------- */

int uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    char bytes_to_sub;
    
    if (ctx) {
        if (ALLOC_BOUNDARY) {
            bytes_to_sub = *((char *)ctx - 1);
            ctx = (uhash_ctx_t)((char *)ctx - bytes_to_sub);
        }
        free(ctx);
    }
    return (1);
}

/* ---------------------------------------------------------------------- */

int uhash_update(uhash_ctx_t ctx, char *input, long len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD bytes_hashed, bytes_remaining;
    UINT8 nh_result[PREFIX_STREAMS*sizeof(LARGE_UWORD)];
    
    if (ctx->msg_len + len <= L1_KEY_LEN) {
        nh_update(&ctx->hash, (UINT8 *)input, len);
        ctx->msg_len += len;
    } else {
    
         bytes_hashed = ctx->msg_len % L1_KEY_LEN;
         if (ctx->msg_len == L1_KEY_LEN)
             bytes_hashed = L1_KEY_LEN;

         if (bytes_hashed + len >= L1_KEY_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             if (bytes_hashed) {
                 bytes_remaining = (L1_KEY_LEN - bytes_hashed);
                 nh_update(&ctx->hash, (UINT8 *)input, bytes_remaining);
                 nh_final(&ctx->hash, nh_result);
                 ctx->msg_len += bytes_remaining;
                 poly_hash(ctx,(UINT32 *)nh_result);
                 len -= bytes_remaining;
                 input += bytes_remaining;
             }

             /* Hash directly from input stream if enough bytes */
             while (len >= L1_KEY_LEN) {
                 nh(&ctx->hash, (UINT8 *)input, L1_KEY_LEN,
                                   L1_KEY_LEN, nh_result);
                 ctx->msg_len += L1_KEY_LEN;
                 len -= L1_KEY_LEN;
                 input += L1_KEY_LEN;
                 poly_hash(ctx,(UINT32 *)nh_result);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         if (len) {
             nh_update(&ctx->hash, (UINT8 *)input, len);
             ctx->msg_len += len;
         }
     }

    return (1);
}

/* ---------------------------------------------------------------------- */

int uhash_final(uhash_ctx_t ctx, char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT8 nh_result[PREFIX_STREAMS*sizeof(LARGE_UWORD)];

    if (ctx->msg_len > L1_KEY_LEN) {
        if (ctx->msg_len % L1_KEY_LEN) {
            nh_final(&ctx->hash, nh_result);
            poly_hash(ctx,(UINT32 *)nh_result);
        }
        /* If WORD_LEN == 2 and we have ramped-up to p64 in the polyhash,
         * then we must pad the data passed to poly64 with a 1 bit and then
         * zero bits up to the next multiple of 64 bits.
         */
        #if (WORD_LEN == 2)
        if (ctx->poly_invocations > poly_crossover) {
            UINT32 tmp[PREFIX_STREAMS];
            int i;
            for (i = 0; i < PREFIX_STREAMS; i++)
                tmp[i] = 0x80000000u;
            poly_hash(ctx,tmp);
            if (ctx->poly_store_full) {
                for (i = 0; i < PREFIX_STREAMS; i++)
                    tmp[i] = 0;
                poly_hash(ctx,tmp);
            }
        }
        #endif
        ip_long(ctx, res);
    } else {
        nh_final(&ctx->hash, nh_result);
        ip_short(ctx,nh_result, res);
    }
    uhash_reset(ctx);
    return (1);
}

/* ---------------------------------------------------------------------- */

int uhash(uhash_ctx_t ahc, char *msg, long len, char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
/* Does not handle zero length message                             */
{
    UINT8 nh_result[PREFIX_STREAMS*sizeof(LARGE_UWORD)];
    UINT32 nh_len;
    int extra_zeroes_needed;
        
    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    if (len <= L1_KEY_LEN) {
        nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)msg + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)msg, nh_len, len, nh_result);
        ip_short(ahc,nh_result, res);
    } else {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        do {
            nh(&ahc->hash, (UINT8 *)msg, L1_KEY_LEN, L1_KEY_LEN, nh_result);
            poly_hash(ahc,(UINT32 *)nh_result);
            len -= L1_KEY_LEN;
            msg += L1_KEY_LEN;
        } while (len >= L1_KEY_LEN);
        if (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)msg + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)msg, nh_len, len, nh_result);
            poly_hash(ahc,(UINT32 *)nh_result);
        }
        /* If WORD_LEN == 2 and we have ramped-up to p64 in the polyhash,
         * then we must pad the data passed to poly64 with a 1 bit and then
         * zero bits up to the next multiple of 64 bits.
         */
        #if (WORD_LEN == 2)
        if (ahc->poly_invocations > poly_crossover) {
            UINT32 tmp[PREFIX_STREAMS];
            int i;
            for (i = 0; i < PREFIX_STREAMS; i++)
                tmp[i] = 0x80000000u;
            poly_hash(ahc,tmp);
            if (ahc->poly_store_full) {
                for (i = 0; i < PREFIX_STREAMS; i++)
                    tmp[i] = 0;
                poly_hash(ahc,tmp);
            }
        }
        #endif
        ip_long(ahc, res);
    }
    
    uhash_reset(ahc);
    return 1;
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin UMAC Section --------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The UMAC interface has two interfaces, an all-at-once interface where
 * the entire message to be authenticated is passed to UMAC in one buffer,
 * and a sequential interface where the message is presented a bit at a time.   
 * The all-at-once is more optimaized than the sequential version and should
 * be preferred when the sequential interface is not required. 
 */
typedef struct umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
} umac_ctx;

/* ---------------------------------------------------------------------- */

int umac_reset(umac_ctx_t ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    return (1);
}

/* ---------------------------------------------------------------------- */

int umac_delete(umac_ctx_t ctx)
/* Deallocate the ctx structure */
{
    char bytes_to_sub;
    
    if (ctx) {
        if (ALLOC_BOUNDARY) {
            bytes_to_sub = *((char *)ctx - 1);
            ctx = (umac_ctx_t)((char *)ctx - bytes_to_sub);
        }
        free(ctx);
    }
    return (1);
}

/* ---------------------------------------------------------------------- */

umac_ctx_t umac_new(char key[])
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    umac_ctx_t ctx;
    char bytes_to_add;
    aes_int_key prf_key;
    
    ctx = (umac_ctx_t)malloc(sizeof(umac_ctx)+ALLOC_BOUNDARY);
    if (ctx) {
        if (ALLOC_BOUNDARY) {
            bytes_to_add = ALLOC_BOUNDARY - ((int)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (umac_ctx_t)((char *)ctx + bytes_to_add);
            *((char *)ctx - 1) = bytes_to_add;
        }
        aes_setup((UINT8 *)key, prf_key);
        pdf_init(&ctx->pdf, prf_key);
        uhash_init(&ctx->hash, prf_key);
    }
        
    return (ctx);
}

/* ---------------------------------------------------------------------- */

int umac_final(umac_ctx_t ctx, char tag[], char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    /* pdf_gen_xor writes OUTPUT_STREAMS * WORD_LEN bytes to its output
     * buffer, so if PREFIX_STREAMS == OUTPUT_STREAMS, we write directly
     * to the buffer supplied by the client. Otherwise we use a temporary
     * buffer.
     */
    #if ((PREFIX_STREAMS == OUTPUT_STREAMS) || HASH_ONLY)
    UINT8 *uhash_result = (UINT8 *)tag;
    #else
    UINT8 uhash_result[UMAC_OUTPUT_LEN];
    #endif
    
    uhash_final(&ctx->hash, (char *)uhash_result);
    #if ( ! HASH_ONLY)
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, uhash_result);
    #endif
    
    #if ((PREFIX_STREAMS != OUTPUT_STREAMS) && ! HASH_ONLY)
    memcpy(tag,uhash_result,UMAC_PREFIX_LEN);
    #endif
    
    return (1);
}

/* ---------------------------------------------------------------------- */

int umac_update(umac_ctx_t ctx, char *input, long len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, input, len);
    return (1);
}

/* ---------------------------------------------------------------------- */

int umac(umac_ctx_t ctx, char *input, 
         long len, char tag[],
         char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    #if ((PREFIX_STREAMS == OUTPUT_STREAMS) || HASH_ONLY)
    UINT8 *uhash_result = (UINT8 *)tag;
    #else
    UINT8 uhash_result[UMAC_OUTPUT_LEN];
    #endif
    
    uhash(&ctx->hash, input, len, (char *)uhash_result);
    #if ( ! HASH_ONLY)
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, uhash_result);
    #endif
    
    #if ((PREFIX_STREAMS != OUTPUT_STREAMS) && ! HASH_ONLY)
    memcpy(tag,uhash_result,UMAC_PREFIX_LEN);
    #endif

    return (1);
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* If RUN_TESTS is defined non-zero, then we define a main() function and */
/* run some verification and speed tests.                                 */

#if RUN_TESTS

#include <stdio.h>
#include <time.h>

static void pbuf(void *buf, UWORD n, char *s)
{
    UWORD i;
    UINT8 *cp = (UINT8 *)buf;
    
    if (n <= 0 || n >= 30)
        n = 30;
    
    if (s)
        printf("%s: ", s);
        
    for (i = 0; i < n; i++)
        printf("%2X", (unsigned char)cp[i]);
    printf("\n");
}

static void primitive_verify(void)
{
    #if (UMAC_KEY_LEN == 16)
    UINT8 key[16] = {0};
    UINT8 pt[16] = {'\x80',0,/* remainder auto filled with zeroes */};
    char res[] = "3AD78E726C1EC02B7EBFE92B23D9EC34";
    #elif (UMAC_KEY_LEN == 32)
    UINT8 key[32] = {0};
    UINT8 pt[16] = {'\x80',0,/* remainder auto filled with zeroes */};
    char res[] = "DDC6BF79 C1576 D8D9AEB6F9A75FD4E";
    #endif
    aes_int_key k1;
    
    aes_setup((UINT8 *)key, k1);
    aes(pt, pt, k1);
    printf("\nAES Test\n");
    pbuf(pt, 16, "Digest is       ");
    printf("Digest should be: %s\n", res);
}

static void umac_verify(void)
{
    umac_ctx_t ctx;
    char *data_ptr;
    int data_len = 4 * 1024;
    char nonce[8] = {0};
    char tag[21] = {0};
    char tag2[21] = {0};
    int bytes_over_boundary, i, j;
    int inc[] = {1,99,512};
    char *results416[] = {"A16710C2","7449 37A89925E18",
         "83A0ECE5CCFCF3F6975E75CE","83A0ECE5CCFCF3F6975E75CE9917D46B"};
    char *results432[] = {"99596515","C35A7D8247D3E476",
         "9EA197B6E634FBA8FF5948AB","9EA197B6E634FBA8FF5948ABB323C844"};
    
    /* Initialize Memory and UMAC */
    nonce[7] = 1;
    data_ptr = (char *)malloc(data_len + 16);
    bytes_over_boundary = (int)data_ptr & (16 - 1);
    if (bytes_over_boundary != 0)
        data_ptr += (16 - bytes_over_boundary);
    for (i = 0; i < data_len; i++)
        data_ptr[i] = (i%127) * (i%123) % 127;
    ctx = umac_new("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    
    umac(ctx, data_ptr, data_len, tag, nonce);
    umac_reset(ctx);

    #if ((WORD_LEN == 2) && (UMAC_OUTPUT_LEN == 8) && \
         (L1_KEY_LEN == 1024) && (UMAC_KEY_LEN == 16))
    printf("UMAC-2/8/1024/16/LITTLE/SIGNED Test\n");
    pbuf(tag, PREFIX_STREAMS*WORD_LEN, "Tag is                   ");
    printf("Tag should be a prefix of: %s\n", "E658CB58FAC91FB7");
    #elif ((WORD_LEN == 4) && (UMAC_OUTPUT_LEN <= 16) && \
         (L1_KEY_LEN == 1024) && (UMAC_KEY_LEN == 16))
    printf("UMAC-4/*/1024/16/LITTLE/UNSIGNED Test\n");
    pbuf(tag, PREFIX_STREAMS*WORD_LEN, "Tag is                   ");
    printf("Tag should be a prefix of: %s\n", results416[UMAC_OUTPUT_LEN/4-1]);
    #elif ((WORD_LEN == 4) && (UMAC_OUTPUT_LEN <= 16) && \
         (L1_KEY_LEN == 1024) && (UMAC_KEY_LEN == 32))
    printf("UMAC-4/8/1024/16/LITTLE/UNSIGNED Test\n");
    pbuf(tag, PREFIX_STREAMS*WORD_LEN, "Tag is                   ");
    printf("Tag should be a prefix of: %s\n", results432[UMAC_OUTPUT_LEN/4-1]);
    #endif



    printf("\nVerifying consistancy of single- and"
           " multiple-call interfaces.\n");
    for (i = 1; i < (int)(sizeof(inc)/sizeof(inc[0])); i++) {
            for (j = 0; j <= data_len-inc[i]; j+=inc[i])
                umac_update(ctx, data_ptr+j, inc[i]);
            umac_final(ctx, tag, nonce);
            umac_reset(ctx);

            umac(ctx, data_ptr, (data_len/inc[i])*inc[i], tag2, nonce);
            umac_reset(ctx);
            nonce[7]++;
            
            if (memcmp(tag,tag2,sizeof(tag)))
                printf("\ninc = %d data_len = %d failed!\n",
                       inc[i], data_len);
    }
    printf("Done.\n");
    umac_delete(ctx);
}


static double run_cpb_test(umac_ctx_t ctx, int nbytes, char *data_ptr,
                           int data_len, double hz)
{
    clock_t ticks;
    double secs;
    char nonce[8] = {0};
    char tag[UMAC_PREFIX_LEN+1] = {0}; /* extra char for null terminator */
    long total_mbs;
    long iters_per_tag, remaining;
    long tag_iters, i, j;
    
    if (nbytes < 16)
        total_mbs = 2;
    if (nbytes < 32)
        total_mbs = 10;
    else if (nbytes < 64)
        total_mbs = 50;
    else if (nbytes < 256)
        total_mbs = 150;
    else if (nbytes < 1024)
        total_mbs = 250;
    else
        total_mbs = 500;
    
    tag_iters = (total_mbs * 1024 * 1024) / (nbytes) + 1;
    
    if (nbytes <= data_len) {
    
        i = tag_iters;
        umac(ctx, data_ptr, nbytes, tag, nonce);
        ticks = clock();
        do {
            umac(ctx, data_ptr, nbytes, tag, nonce);
            nonce[7] += 1;
        } while (--i);
        ticks = clock() - ticks;
        
    } else {
    
        i = tag_iters;
        iters_per_tag = nbytes / data_len;
        remaining = nbytes % data_len;
        umac_update(ctx, data_ptr, data_len);
        umac_final(ctx, tag, nonce);
        ticks = clock();
        do {
            j = iters_per_tag;
            do {
                umac_update(ctx, data_ptr, data_len);
            } while (--j);
            if (remaining)
                umac_update(ctx, data_ptr, remaining);
            umac_final(ctx, tag, nonce);
            nonce[7] += 1;
        } while (--i);
        ticks = clock() - ticks;
        
    }

    secs = (double)ticks / CLOCKS_PER_SEC;
    return (secs * (hz/(tag_iters*nbytes)));
}

static void speed_test(void)
{
    umac_ctx_t ctx;
    char *data_ptr;
    int data_len;
    double hz;
    double cpb;
    int bytes_over_boundary, i;
    int length_range_low = 1;
    int length_range_high = 0;
    int length_pts[] = {43,64,256,1024,1500,256*1024};
    
    /* hz and data_len must be set appropriately for your system
     * for optimal results.
     */
    #if  (__GNUC__ && __i386__)
    hz = ((double)7.0e8);
    data_len = 4096;
    #elif  (_M_IX86)
    hz = ((double)8.66e8);
    data_len = 4096;
    #elif ((__MRC__ || __MWERKS__) && __POWERPC__)
    hz = ((double)4.33e8);
    data_len = 8192;
    #else
    #error -- unsupported platform
    #endif

    /* Allocate memory and align to 16-byte multiple */
    data_ptr = (char *)malloc(data_len + 16);
    bytes_over_boundary = (int)data_ptr & (16 - 1);
    if (bytes_over_boundary != 0)
        data_ptr += (16 - bytes_over_boundary);
    for (i = 0; i < data_len; i++)
        data_ptr[i] = (i*i) % 128;
    ctx = umac_new("abcdefghijklmnopqrstuvwxyz");
        
    printf("\n");
    if (length_range_low < length_range_high) {
        for (i = length_range_low; i <= length_range_high; i++) {
            cpb = run_cpb_test(ctx, i, data_ptr, data_len, hz);
            printf("Authenticating %8d byte messages: %5.2f cpb.\n", i, cpb);
        }
    }

    if (sizeof(length_pts) > 0) {
        for (i = 0; i < (int)(sizeof(length_pts)/sizeof(int)); i++) {
            cpb = run_cpb_test(ctx, length_pts[i], data_ptr, data_len, hz);
            printf("Authenticating %8d byte messages: %5.2f cpb.\n",
                                   length_pts[i], cpb);
        }
    }
    umac_delete(ctx);
}

int main(void)
{
    umac_verify();
    primitive_verify();
    speed_test();
    /* printf("Push return to continue\n"); getchar(); */
    return (1);
}

#endif
