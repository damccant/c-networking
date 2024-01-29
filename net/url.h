#ifndef __URL_H_
#define __URL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct URL
{
	char *scheme;
	char *user;
	char *pass;
	char *host;
	char *port;
	char *path;
	char *query;
	char *fragment;
};

int parseURL(const char *s, struct URL *url);
int parseURL_nocopy(char *s, struct URL *url);
void freeURL(struct URL *url);

char* urlToString(const struct URL url, char *str, size_t len);
void debugURL(const struct URL url, FILE* where);

#ifdef __cplusplus
}
#endif

#endif /* __URL_H_ */