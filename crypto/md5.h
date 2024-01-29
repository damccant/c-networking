#ifndef __MD5_H_
#define __MD5_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t md5_uint32;

/*#ifdef _WIN32

#else
typedef u_int32_t md5_uint32; // shrug
#endif*/

/* Structure to save state of computation between the single steps.  */
struct md5_ctx
{
  md5_uint32 A;
  md5_uint32 B;
  md5_uint32 C;
  md5_uint32 D;

  md5_uint32 total[2];
  md5_uint32 buflen;
  char buffer[128];
  unsigned char digest[16];
};

typedef struct md5_ctx MD5_CTX;

#ifndef __P
#define __P(args) args
#endif /* __P */

/*
 * The following three functions are build up the low level used in
 * the functions `md5_stream' and `md5_buffer'.
 */

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
static void md5_init_ctx __P ((struct md5_ctx *ctx));
void MD5Init(MD5_CTX *mdContext);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
static void md5_process_block __P ((const void *buffer, size_t len,
				    struct md5_ctx *ctx));

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
static void md5_process_bytes __P ((const void *buffer, size_t len,
				    struct md5_ctx *ctx));
void MD5Update(MD5_CTX *mdContext, const unsigned char *inBuf, unsigned int inLen);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 16 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.
   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
//static void *md5_finish_ctx __P ((struct md5_ctx *ctx, void *resbuf));
void MD5Final(struct md5_ctx *ctx);


void MDString_printf (char *inString);
char* MD5printable_from_context(MD5_CTX *mdContext, char *out);
char* MD5printable_from_context_new(MD5_CTX *mdContext);

char* MDString_printable(char *inString, size_t inString_len, char* out);
char* MDString_printable_new(char *inString, size_t inString_len);

#ifdef __cplusplus
}
#endif

#endif /* __MD5_H_ */