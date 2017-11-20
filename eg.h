#include <stdio.h>
#include "egadspriv.h"

#define EPOOLSZ 512
#define BUFSZ 31 
#define EPOOL_OUTD 10
#define EPOOL_OUTN 1
#define SPOOL_SIZE 32
#define SPOOL_THRESH_START  8
#define SPOOL_THRESH_MAX    1024


#define NUM_COMP_SRCS 1


#if EPOOLSZ == 2048   /* 115 x^2048+x^1638+x^1231+x^819+x^411+x^1+1 */
#define TAP1    1638
#define TAP2    1231
#define TAP3    819
#define TAP4    411
#define TAP5    1
#elif EPOOLSZ == 1024 /* 290 x^1024+x^817+x^615+x^412+x^204+x^1+1 */
/* Alt: 115 x^1024+x^819+x^616+x^410+x^207+x^2+1 */
#define TAP1    817
#define TAP2    615
#define TAP3    412
#define TAP4    204
#define TAP5    1
#elif EPOOLSZ == 512  /* 225 x^512+x^411+x^308+x^208+x^104+x+1 */
/* Alt: 95 x^512+x^409+x^307+x^206+x^102+x^2+1
 *      95 x^512+x^409+x^309+x^205+x^103+x^2+1 */
#define TAP1    411
#define TAP2    308
#define TAP3    208
#define TAP4    104
#define TAP5    1
#elif EPOOLSZ == 256  /* 125 x^256+x^205+x^155+x^101+x^52+x+1 */
#define TAP1    205
#define TAP2    155
#define TAP3    101
#define TAP4    52
#define TAP5    1
#elif EPOOLSZ == 128  /* 105 x^128+x^103+x^76+x^51+x^25+x+1 */
/* Alt: 70 x^128+x^103+x^78+x^51+x^27+x^2+1 */
#define TAP1    103
#define TAP2    76
#define TAP3    51
#define TAP4    25
#define TAP5    1
#elif EPOOLSZ == 64   /* 15 x^64+x^52+x^39+x^26+x^14+x+1 */
#define TAP1    52
#define TAP2    39
#define TAP3    26
#define TAP4    14
#define TAP5    1
#elif EPOOLSZ == 32   /* 15 x^32+x^26+x^20+x^14+x^7+x^1+1 */
#define TAP1    26
#define TAP2    20
#define TAP3    14
#define TAP4    7
#define TAP5    1
#elif EPOOLSZ & (EPOOLSZ-1)
#error EPOOLSZ must be a power of 2
#else
#error No primitive polynomial available for chosen EPOOLSZ
#endif


extern int EG_add_entropy(int srcnum, unsigned char *ent, int len,  int est);
extern int EG_output(char *out, int howmuch, int block);
extern int EG_init(void);
extern int EG_register_source(void);
extern int EG_save_state(FILE *);
extern int EG_restore_state(FILE *);
extern void EG_startup_done(void);
extern double EG_entropy_level();

