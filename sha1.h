#ifndef _SHA1_H_
#define _SHA1_H_ 1

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* BYTE defines a unsigned character */
typedef unsigned char BYTE;

#ifndef TRUE
  #define FALSE 0
  #define TRUE  ( !FALSE )
#endif /* TRUE */


/* The structure for storing SHS info */

typedef struct
{
        UINT4 digest[ 5 ];            /* Message digest */
        UINT4 countLo, countHi;       /* 64-bit bit count */
        UINT4 data[ 16 ];             /* SHS data buffer */
        int Endianness;
} SHA_CTX;

/* Message digest functions */

void SHAInit(SHA_CTX *);
void SHAUpdate(SHA_CTX *, BYTE *buffer, int count);
void SHAFinal(BYTE *output, SHA_CTX *);



void endianTest(int *endianness);

#endif /* end _SHA1_H_ */


