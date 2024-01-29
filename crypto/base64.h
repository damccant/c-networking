#include <stdio.h>
#include <stdlib.h>

// no bounds checking!!!!
char *base64_encode(char* dst, size_t dst_len, const char unsigned *src, size_t len);

char *base64_encode_malloc(const unsigned char *src, size_t len);