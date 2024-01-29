#ifndef __UTIL_H_
#define __UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h> // read()
#include <unistd.h>
#include <ctype.h> // toupper, tolower
#include <string.h> // memcmp()
#include <stdlib.h> // malloc(), rand()

#ifdef _WIN32
#include <windows.h>
#elif _POSIX_C_SOURCE >= 199309L
#include <time.h> // nanosleep()
#else
#include <unistd.h> // usleep()
#endif

// probably not necessary, but just in case
#if defined(_WIN32) && !defined(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

// required for windows
// user (file owner) has read, write, and execute permission
#ifndef S_IRWXU
#define S_IRWXU  00700
#endif /*S_IRWXU*/
// user has read permission
#ifndef S_IRUSR
#define S_IRUSR  00400
#endif /*S_IRUSR*/
// user has write permission
#ifndef S_IWUSR
#define S_IWUSR  00200
#endif /*S_IWUSR*/
// user has execute permission
#ifndef S_IXUSR
#define S_IXUSR  00100
#endif /*S_IXUSR*/
// group has read, write, and execute permission
#ifndef S_IRWXG
#define S_IRWXG  00070
#endif /*S_IRWXG*/
// group has read permission
#ifndef S_IRGRP
#define S_IRGRP  00040
#endif /*S_IRGRP*/
// group has write permission
#ifndef S_IWGRP
#define S_IWGRP  00020
#endif /*S_IWGRP*/
// group has execute permission
#ifndef S_IXGRP
#define S_IXGRP  00010
#endif /*S_IXGRP*/
// others have read, write, and execute permission
#ifndef S_IRWXO
#define S_IRWXO  00007
#endif /*S_IRWXO*/
// others have read permission
#ifndef S_IROTH
#define S_IROTH  00004
#endif /*S_IROTH*/
// others have write permission
#ifndef S_IWOTH
#define S_IWOTH  00002
#endif /*S_IWOTH*/
// others have execute permission
#ifndef S_IXOTH
#define S_IXOTH  00001
#endif /*S_IXOTH*/

#define  BOLD "\e[1m"
#define BLACK "\e[0;30m"
#define   RED "\e[0;31m"
#define GREEN "\e[0;32m"
#define YELLO "\e[0;33m"
#define  BLUE "\e[0;34m"
#define MAGEN "\e[0;35m"
#define  CYAN "\e[0;36m"
#define WHITE "\e[0;37m"
#define RESET "\e[0m"

void enableTerminalColors();
int my_strincmp(const char* a1, const char* a2, size_t len);
int my_stricmp(const char *a, const char *b);
void *my_memmem(const void *haystack, size_t haystack_len, const void * const needle, const size_t needle_len);
char *strdup_normalize(char *str);
void sleep_ms(unsigned long int millis);
ssize_t read_fully(int fd, void* buf, size_t count);
char *binary_to_hexprintable_lower(unsigned char *buf, size_t count, char *out);
char *binary_to_hexprintable_lower_new(unsigned char *buf, size_t count);
char *binary_to_hexprintable_upper(unsigned char *buf, size_t count, char *out);
char *binary_to_hexprintable_upper_new(unsigned char *buf, size_t count);
unsigned char *new_random_binary_string(size_t len);
char *random_base64(char* out, size_t len);
char *random_alpha_num(char *out, size_t len);
char *new_random_base64(size_t len);
char *random_printable_hex_lower(char* out, size_t len);
char *random_printable_hex_upper(char* out, size_t len);
char *new_random_printable_hex_lower(size_t len);
char *new_random_printable_hex_upper(size_t len);

time_t add_seconds(time_t time1, int64_t seconds_to_add);

#ifdef __cplusplus
}
#endif

#endif /* __UTIL_H_ */