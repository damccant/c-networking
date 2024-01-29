#include "url.h"

int parseURL(const char *s, struct URL *url)
{
	return parseURL_nocopy(strdup(s), url);
}

void freeURL(struct URL *url)
{
	if(url == NULL)
		return;
	free(url->scheme);
}

int parseURL_authority(char *s, char ** endptr, struct URL *url)
{
	if(*s == '/') s++; else return 1;
	if(*s == '/') s++; else return 1;
	char *at = strchr(s, '@');
	if(at != NULL)
	{
		url->user = s;
		while(s < at)
		{
			if(*s == ':')
			{
				*(s++) = '\0';
				url->pass = s;
			}
		}
	}
}

int parseURL_nocopy(char *s, struct URL *url)
{
	url->scheme = s;
	url->user = NULL;
	url->pass = NULL;
	url->host = NULL;
	url->port = NULL;
	url->path = NULL;
	url->query = NULL;
	url->fragment = NULL;

	char *here = strchr(s, ':');
	if(here == NULL)
		return 1;
	*here = '\0'; here++;
	if(here[0] == '/' && here[1] == '/')
		parseURL_authority(here, &here, url);
	url->path = here;
	url->query = strchr(url->path, '?');
	if(url->query != NULL)
		*(url->query++) = '\0';
	url->fragment = strchr(url->path, '#');
	if(url->fragment != NULL)
		*(url->fragment++) = '\0';
}

char *urlToString(const struct URL url, char *str, const size_t len)
{
	snprintf(str, len, "%s:%s%s%s%s%s%s%s%s%s%s%s%s",
		url.scheme,
		url.host != NULL ? "//" : "",
		url.host != NULL && url.user != NULL ? url.user : "",
		url.host != NULL && url.pass != NULL ? ":" : "",
		url.host != NULL && url.pass != NULL ? url.pass : "",
		url.host != NULL ? url.host : "",
		url.port != NULL ? ":" : "",
		url.port != NULL ? url.port : "",
		url.path,
		url.query != NULL ? "?" : "",
		url.query != NULL ? url.query : "",
		url.fragment != NULL ? "#" : "",
		url.fragment != NULL ? url.fragment : ""
		);
}

void debugURL(const struct URL url, FILE* where)
{
	fprintf(where, "scheme   = \"%s\"\n", url.scheme);
	fprintf(where, "user     = \"%s\"\n", url.user);
	fprintf(where, "pass     = \"%s\"\n", url.pass);
	fprintf(where, "host     = \"%s\"\n", url.host);
	fprintf(where, "path     = \"%s\"\n", url.path);
	fprintf(where, "query    = \"%s\"\n", url.query);
	fprintf(where, "fragment = \"%s\"\n", url.fragment);
}