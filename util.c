#include "util.h"

void enableTerminalColors()
{
	#ifdef _WIN32
	/**
	 * enable ANSI colors
	 */
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
	#endif /* _WIN32 */
}

int my_strincmp(const char* a1, const char* a2, size_t len)
{
	int ca, cb;
	for(size_t pos = 0; pos < len; pos++)
	{
		if(!a1[pos] && !a2[pos])
			return 0;

		ca = tolower(toupper(a1[pos]));
		cb = tolower(toupper(a2[pos]));
		if(ca != cb)
			return ca - cb;
	}
	return 0;
}

int my_stricmp(const char *a, const char *b)
{
	int ca, cb;
	do {
		ca = (unsigned char) *a++;
		cb = (unsigned char) *b++;
		ca = tolower(toupper(ca));
		cb = tolower(toupper(cb));
	} while(ca == cb && ca != '\0');
	return ca - cb;
}

void *my_memmem(const void *haystack, size_t haystack_len, const void * const needle, const size_t needle_len)
{
	if(haystack == NULL || haystack_len == 0 || needle == NULL || needle_len == 0)
		return NULL;
	for(const char *h = haystack; haystack_len >= needle_len; ++h, --haystack_len)
		if(memcmp(h, needle, needle_len) == 0)
			return h;
	return NULL;
}

char *strdup_normalize(char *str)
{
	char *normalized_name = strdup(str);
	for(char *t = normalized_name; *t; t++)
	{
		//*t |= 0b00100000
		if(*t >= 'A' && *t <= 'Z')
			*t += 0x20;
		else if(*t == '_')
			*t = ' ';
	}
	return normalized_name;
}

void sleep_ms(unsigned long int millis)
{
#ifdef _WIN32
	Sleep(millis);
#elif _POSIX_C_SOURCE >= 199309L
	struct timespec ts;
	ts.tv_sec = millis / 1000;
	ts.tv_nsec = (millis % 1000) * 1000000;
	nanosleep(&ts, NULL);
#else
	if(millis >= 1000)
		sleep(millis / 1000);
	usleep((millis % 1000) * 1000);
#endif
}

ssize_t read_fully(int fd, void* buf, size_t count)
{
	ssize_t total_size = 0;
	while(total_size < count)
	{
		//printf("trying to read %lu more bytes... ", count - total_size);
		ssize_t this_read = read(fd, buf + total_size, count - total_size);
		if(this_read == 0) perror("read()");
		//printf("actually read %lu bytes\n", this_read);
		total_size += this_read;
		if(this_read == 0)
		{
			printf("got EOF, trying to read %lu bytes, but only read %lu bytes\n", count, total_size);
			break;
		}
	}
	return total_size;
}

static const char hexchars_lower[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static const char hexchars_upper[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

static inline char *binary_to_hexprintable_charset(unsigned char *buf, size_t count, char *out, const char hexchars[])
{
	for(size_t i = 0; i < count; i++)
	{
		out[(i<<1) & 0xfffffffeul] = hexchars[(buf[i] >> 4) & 0x0f];
		out[(i<<1) | 0x00000001ul] = hexchars[(buf[i]) & 0x0f];
	}
	out[count << 1] = '\0';
	return out;
}

char *binary_to_hexprintable_lower(unsigned char *buf, size_t count, char *out)
{
	return binary_to_hexprintable_charset(buf, count, out, hexchars_lower);
}

char *binary_to_hexprintable_lower_new(unsigned char *buf, size_t count)
{
	return binary_to_hexprintable_charset(buf, count, (char*)malloc(count * 2 + 1), hexchars_lower);
}

char *binary_to_hexprintable_upper(unsigned char *buf, size_t count, char *out)
{
	return binary_to_hexprintable_charset(buf, count, out, hexchars_upper);
}

char *binary_to_hexprintable_upper_new(unsigned char *buf, size_t count)
{
	return binary_to_hexprintable_charset(buf, count, (char*)malloc(count * 2 + 1), hexchars_upper);
}


unsigned char *new_random_binary_string(size_t len)
{
	unsigned char *r = (unsigned char*)malloc(sizeof(unsigned char) * len);
	if(r == NULL)
		return NULL;
	//#if RAND_MAX >= 0xffff
	//for(size_t i = 0; i + 1 < len; i += 2)
	//{
	//	int i = rand();
	//	r[i] = (unsigned char)(i >> 8);
	//	r[i+1] = (unsigned char)(i & 0xff);
	//}
	//#else
	for(size_t i = 0; i < len; i++)
		r[i] = (unsigned char)rand();
	//#endif
	return r;
}

static const char base64[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

char *random_base64(char *out, size_t len)
{
	for(size_t i = 0; i < len; i++)
		out[i] = base64[rand() % (sizeof(base64) - 1)];
	out[len] = '\0';
	return out;
}

static const char alpha_num[] = "0123456789abcdefghijklmnopqrstuvwxyz";

char *random_alpha_num(char *out, size_t len)
{
	for(size_t i = 0; i < len; i++)
		out[i] = alpha_num[rand() % (sizeof(alpha_num) - 1)];
	out[len] = '\0';
	return out;
}

static const char alpha_hex[] = "0123456789abcdef";

char *random_hex(char *out, size_t len)
{
	for(size_t i = 0; i < len; i++)
		out[i] = alpha_hex[rand() % (sizeof(alpha_hex) - 1)];
	out[len] = '\0';
	return out;
}


char *new_random_base64(size_t len)
{
	return random_base64((char*)malloc(len + 1), len);
}


static inline char *random_printable_hex(char* out, size_t len, const char hexchars[])
{
	for(size_t i = 0; i < len; i++)
		out[i] = hexchars[rand() & 0x0f];
	out[len] = '\0';
	return out;
}

char *random_printable_hex_lower(char* out, size_t len)
{
	return random_printable_hex(out, len, hexchars_lower);
}

char *random_printable_hex_upper(char* out, size_t len)
{
	return random_printable_hex(out, len, hexchars_upper);
}

char *new_random_printable_hex_lower(size_t len)
{
	return random_printable_hex((char*)malloc(len + 1), len, hexchars_lower);
}

char *new_random_printable_hex_upper(size_t len)
{
	return random_printable_hex((char*)malloc(len + 1), len, hexchars_upper);
}

time_t add_seconds(time_t time1, int64_t seconds_to_add)
{
	static time_t one_second = -69420; // resolution of time_t is not defined by C standard, so added for portability
	if(one_second == -69420)
	{
		struct tm time1, time2;
		time1.tm_sec = 30;
		time1.tm_min = 24;
		time1.tm_hour = 22;
		time1.tm_mday = 25;
		time1.tm_mon = 11;
		time1.tm_year = 98;
		time1.tm_isdst = 0;
		memcpy(&time2, &time1, sizeof(struct tm));
		time2.tm_sec++;
		time_t t1 = mktime(&time1);
		time_t t2 = mktime(&time2);
		one_second = t2 - t1;
	}
	return time1 + seconds_to_add * one_second;
}