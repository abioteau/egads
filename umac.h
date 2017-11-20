#ifndef _UMAC_H_
#define _UMAC_H_

#define _UMAC_H_

#include "platform.h"

/*------------------------------------------------------------------
 * 
 * umac.c -- C Implementation UMAC Message Authentication
 *
 * Version 0.04 of draft-krovetz-umac-00.txt -- 2000 August
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

/* umac.h */

#ifdef __cplusplus
    extern "C" {
#endif

/* ---------------------------------------------------------------------- */
/* --- User Switches ---------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* Following is the list of UMAC parameters supported by this code.
 * The following parameters are fixed in this implementation.
 *
 *      ENDIAN_FAVORITE_LITTLE  = 1
 *      L1-OPERATIONS-SIGN      = SIGNED   (when WORD_LEN == 2)
 *      L1-OPERATIONS-SIGN      = UNSIGNED (when WORD_LEN == 4)
 */

/* These can be set for different NESSIE attributes */
//#define UMAC_KEY_LEN           16   /* 16 | 32                            */
#define UMAC_OUTPUT_LEN         8   /* 4  | 8  | 12  | 16                 */

/* These should be fixed for NESSIE */
#define WORD_LEN                4   /* 2  | 4                             */
#define L1_KEY_LEN           1024   /* 32 | 64 | 128 | ... | 2^28         */

/* To produce a prefix of a tag rather than the entire tag defined
 * by the above parameters, set the following constant to a number
 * less than UMAC_OUTPUT_LEN.
 */
#define UMAC_PREFIX_LEN  UMAC_OUTPUT_LEN

/* This file implements UMAC in ANSI C as long as the compiler supports 64-
 * bit integers. To accellerate the execution of the code, architecture-
 * specific replacements have been supplied for some compiler/instruction-
 * set combinations. To enable the features of these replacements, the
 * following compiler directives must be set appropriately. Some compilers
 * include "intrinsic" support of basic operations like register rotation,
 * byte reversal, or vector SIMD manipulation. To enable these intrinsics
 * set USE_C_AND_INTRINSICS to 1. Most compilers also allow for inline
 * assembly in the C code. To allow intrinsics and/or assembly routines
 * (whichever is faster) set only USE_C_AND_ASSEMBLY to 1.
 */
#define USE_C_ONLY            1  /* ANSI C and 64-bit integers req'd */
#define USE_C_AND_INTRINSICS  0  /* Intrinsics for rotation, MMX, etc.    */
#define USE_C_AND_ASSEMBLY    0  /* Intrinsics and assembly */

#if (USE_C_ONLY + USE_C_AND_INTRINSICS + USE_C_AND_ASSEMBLY != 1)
#error -- Only one setting may be nonzero
#endif

#define RUN_TESTS             0  /* Run basic correctness/speed tests    */
#define HASH_ONLY             0  /* Only universal hash data, don't MAC   */

#ifdef _MSC_VER
typedef __int16            INT16;  /* 2 byte   */
typedef unsigned __int16   UINT16; /* 2 byte   */
typedef __int32            INT32;  /* 4 byte   */
typedef unsigned __int32   UINT32; /* 4 byte   */
typedef unsigned __int64   UINT64; /* 8 bytes  */
#else
typedef short              INT16;  /* 2 byte   */
typedef unsigned short     UINT16; /* 2 byte   */
typedef int                INT32;  /* 4 byte   */
typedef unsigned int       UINT32; /* 4 byte   */
typedef unsigned long long UINT64; /* 8 bytes  */
#endif
typedef unsigned long      UWORD;  /* Register */

//#define AES_BLOCK_LEN  16
//#define ROUNDS          ((UMAC_KEY_LEN / 4) + 6)
//typedef UINT8          aes_int_key[ROUNDS+1][4][4];
typedef struct umac_ctx *umac_ctx_t;

umac_ctx_t umac_new(char key[]);
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */

int umac_reset(umac_ctx_t ctx);
/* Reset a umac_ctx to begin authenicating a new message */

int umac_update(umac_ctx_t ctx, char *input, long len);
/* Incorporate len bytes pointed to by input into context ctx */

int umac_final(umac_ctx_t ctx, char tag[], char nonce[8]);
/* Incorporate any pending data and the ctr value, and return tag. 
 * This function returns error code if ctr < 0. 
 */

int umac_delete(umac_ctx_t ctx);
/* Deallocate the context structure */

int umac(umac_ctx_t ctx, char *input, 
         long len, char tag[],
         char nonce[8]);
/* All-in-one implementation of the functions Reset, Update and Final */


/* uhash.h */


typedef struct uhash_ctx *uhash_ctx_t;
  /* The uhash_ctx structure is defined by the implementation of the    */
  /* UHASH functions.                                                   */
 
uhash_ctx_t uhash_alloc(char key[16]);
  /* Dynamically allocate a uhash_ctx struct and generate subkeys using */
  /* the kdf and kdf_key passed in. If kdf_key_len is 0 then RC6 is     */
  /* used to generate key with a fixed key. If kdf_key_len > 0 but kdf  */
  /* is NULL then the first 16 bytes pointed at by kdf_key is used as a */
  /* key for an RC6 based KDF.                                          */
  
int uhash_free(uhash_ctx_t ctx);

int uhash_set_params(uhash_ctx_t ctx,
                   void       *params);

int uhash_reset(uhash_ctx_t ctx);

int uhash_update(uhash_ctx_t ctx,
               char       *input,
               long        len);

int uhash_final(uhash_ctx_t ctx,
              char        ouput[]);

int uhash(uhash_ctx_t ctx,
        char       *input,
        long        len,
        char        output[]);

int aes(UINT8 a[16], UINT8 b[16], aes_int_key rk);
int aes_setup(UINT8 key[UMAC_KEY_LEN], aes_int_key W);

#ifdef __cplusplus
    }
#endif
#endif /* _UMAC_H_ */
