/******************************************************************************
** The Hash Engine
*/
/* Context for the SHA1 hash */
typedef struct SHA1Context SHA1Context;
struct SHA1Context {
  unsigned int state[5];
  unsigned int count[2];
  unsigned char buffer[64];
};

#define SHA_ROT(x,l,r) ((x) << (l) | (x) >> (r))
#define rol(x,k) SHA_ROT(x,k,32-(k))
#define ror(x,k) SHA_ROT(x,32-(k),k)

#define blk0le(i) (block[i] = (ror(block[i],8)&0xFF00FF00) \
    |(rol(block[i],8)&0x00FF00FF))
#define blk0be(i) block[i]
#define blk(i) (block[i&15] = rol(block[(i+13)&15]^block[(i+8)&15] \
    ^block[(i+2)&15]^block[i&15],1))

/*
 * (R0+R1), R2, R3, R4 are the different operations (rounds) used in SHA1
 *
 * Rl0() for little-endian and Rb0() for big-endian.  Endianness is
 * determined at run-time.
 */
#define Rl0(v,w,x,y,z,i) \
    z+=((w&(x^y))^y)+blk0le(i)+0x5A827999+rol(v,5);w=ror(w,2);
#define Rb0(v,w,x,y,z,i) \
    z+=((w&(x^y))^y)+blk0be(i)+0x5A827999+rol(v,5);w=ror(w,2);
#define R1(v,w,x,y,z,i) \
    z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=ror(w,2);
#define R2(v,w,x,y,z,i) \
    z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=ror(w,2);
#define R3(v,w,x,y,z,i) \
    z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=ror(w,2);
#define R4(v,w,x,y,z,i) \
    z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=ror(w,2);

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
void SHA1Transform(unsigned int state[5], const unsigned char buffer[64]){
  unsigned int qq[5]; /* a, b, c, d, e; */
  static int one = 1;
  unsigned int block[16];
  memcpy(block, buffer, 64);
  memcpy(qq,state,5*sizeof(unsigned int));

#define a qq[0]
#define b qq[1]
#define c qq[2]
#define d qq[3]
#define e qq[4]

  /* Copy p->state[] to working vars */
  /*
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  */

  /* 4 rounds of 20 operations each. Loop unrolled. */
  if( 1 == *(unsigned char*)&one ){
    Rl0(a,b,c,d,e, 0); Rl0(e,a,b,c,d, 1); Rl0(d,e,a,b,c, 2); Rl0(c,d,e,a,b, 3);
    Rl0(b,c,d,e,a, 4); Rl0(a,b,c,d,e, 5); Rl0(e,a,b,c,d, 6); Rl0(d,e,a,b,c, 7);
    Rl0(c,d,e,a,b, 8); Rl0(b,c,d,e,a, 9); Rl0(a,b,c,d,e,10); Rl0(e,a,b,c,d,11);
    Rl0(d,e,a,b,c,12); Rl0(c,d,e,a,b,13); Rl0(b,c,d,e,a,14); Rl0(a,b,c,d,e,15);
  }else{
    Rb0(a,b,c,d,e, 0); Rb0(e,a,b,c,d, 1); Rb0(d,e,a,b,c, 2); Rb0(c,d,e,a,b, 3);
    Rb0(b,c,d,e,a, 4); Rb0(a,b,c,d,e, 5); Rb0(e,a,b,c,d, 6); Rb0(d,e,a,b,c, 7);
    Rb0(c,d,e,a,b, 8); Rb0(b,c,d,e,a, 9); Rb0(a,b,c,d,e,10); Rb0(e,a,b,c,d,11);
    Rb0(d,e,a,b,c,12); Rb0(c,d,e,a,b,13); Rb0(b,c,d,e,a,14); Rb0(a,b,c,d,e,15);
  }
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;

#undef a
#undef b
#undef c
#undef d
#undef e
}


/* Initialize a SHA1 context */
static void hash_init(SHA1Context *p){
  /* SHA1 initialization constants */
  p->state[0] = 0x67452301;
  p->state[1] = 0xEFCDAB89;
  p->state[2] = 0x98BADCFE;
  p->state[3] = 0x10325476;
  p->state[4] = 0xC3D2E1F0;
  p->count[0] = p->count[1] = 0;
}

/* Add new content to the SHA1 hash */
static void hash_step(
  SHA1Context *p,                 /* Add content to this context */
  const unsigned char *data,      /* Data to be added */
  unsigned int len                /* Number of bytes in data */
){
  unsigned int i, j;

  j = p->count[0];
  if( (p->count[0] += len << 3) < j ){
    p->count[1] += (len>>29)+1;
  }
  j = (j >> 3) & 63;
  if( (j + len) > 63 ){
    (void)memcpy(&p->buffer[j], data, (i = 64-j));
    SHA1Transform(p->state, p->buffer);
    for(; i + 63 < len; i += 64){
      SHA1Transform(p->state, &data[i]);
    }
    j = 0;
  }else{
    i = 0;
  }
  (void)memcpy(&p->buffer[j], &data[i], len - i);
}

/* Add padding and compute the message digest.  Render the
** message digest as lower-case hexadecimal and put it into
** zOut[].  zOut[] must be at least 41 bytes long. */
static void hash_finish(
  SHA1Context *p,           /* The SHA1 context to finish and render */
  char *zOut                /* Store hexadecimal hash here */
){
  unsigned int i;
  unsigned char finalcount[8];
  unsigned char digest[20];
  static const char zEncode[] = "0123456789abcdef";

  for (i = 0; i < 8; i++){
    finalcount[i] = (unsigned char)((p->count[(i >= 4 ? 0 : 1)]
       >> ((3-(i & 3)) * 8) ) & 255); /* Endian independent */
  }
  hash_step(p, (const unsigned char *)"\200", 1);
  while ((p->count[0] & 504) != 448){
    hash_step(p, (const unsigned char *)"\0", 1);
  }
  hash_step(p, finalcount, 8);  /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++){
    digest[i] = (unsigned char)((p->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
  }
  for(i=0; i<20; i++){
    zOut[i*2] = zEncode[(digest[i]>>4)&0xf];
    zOut[i*2+1] = zEncode[digest[i] & 0xf];
  }
  zOut[i*2]= 0;
}

static void hash_finish_binary(
  SHA1Context *p,           /* The SHA1 context to finish and render */
  unsigned char *zOut                /* Store hexadecimal hash here */
){
  unsigned int i;
  unsigned char finalcount[8];
  //unsigned char digest[20];
  //static const char zEncode[] = "0123456789abcdef";

  for (i = 0; i < 8; i++){
    finalcount[i] = (unsigned char)((p->count[(i >= 4 ? 0 : 1)]
       >> ((3-(i & 3)) * 8) ) & 255); /* Endian independent */
  }
  hash_step(p, (const unsigned char *)"\200", 1);
  while ((p->count[0] & 504) != 448){
    hash_step(p, (const unsigned char *)"\0", 1);
  }
  hash_step(p, finalcount, 8);  /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++){
	zOut[i] = (unsigned char)((p->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
  }
}

static void hash_finish_base64(
  SHA1Context *p,           /* The SHA1 context to finish and render */
  unsigned char *zOut                /* Store hexadecimal hash here */
){
  unsigned int i;
  unsigned char finalcount[8];
  unsigned char digest[21];
  static const char zEncode[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  for (i = 0; i < 8; i++){
    finalcount[i] = (unsigned char)((p->count[(i >= 4 ? 0 : 1)]
       >> ((3-(i & 3)) * 8) ) & 255); /* Endian independent */
  }
  hash_step(p, (const unsigned char *)"\200", 1);
  while ((p->count[0] & 504) != 448){
    hash_step(p, (const unsigned char *)"\0", 1);
  }
  hash_step(p, finalcount, 8);  /* Should cause a SHA1Transform() */
  for (i = 0; i < 20; i++){
        digest[i] = (unsigned char)((p->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
  }
  digest[20] = 0;
  unsigned char* c = zOut;
  for(i = 0; i < 21; i += 3)
  {
	*c = zEncode[digest[i] >> 2];
	c++;
	*c = zEncode[((digest[i] << 4) & 0b00110000) | ((digest[i+1] >> 4) & 0b00001111)];
	c++;
	*c = zEncode[((digest[i+1] << 2) & 0b00111100) | ((digest[i+2] >> 6) & 0b00000011)];
	c++;
	*c = zEncode[(digest[i+2] & 0b00111111)];
	c++;
  }
  *(c-1) = '=';
  *c = 0;
}

/* End of the hashing logic
*****************************************************************************/