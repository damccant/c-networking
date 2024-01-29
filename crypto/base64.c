#include "base64.h"

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// shamelessly stolen
char *base64_encode(char* out, size_t dst_len, const char unsigned *src, size_t len)
{
	unsigned char *pos;
	const unsigned char *end, *in;
}

char *base64_encode_malloc(const unsigned char *src, size_t len)
{
	size_t olen = 4 * ((len + 2) / 3);
	if(olen < len) // overflow
		return NULL;
	char *dst = (char*)malloc(olen);
	if(dst == NULL)
	{
		perror("malloc()");
		return NULL;
	}
	return base64_encode(dst, olen, src, len);
}