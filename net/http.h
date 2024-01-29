#ifndef __HTTP_H_
#define __HTTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "socket.h"
#include "../util.h"
#include "../md5.h"
#include "../base64.h"

#define ENABLE_HTTPS_SUPPORT 1

#define DEFAULT_HTTP_PORT "80"

enum SameSite
{
	SAMESITE_NONE,
	SAMESITE_LAX,
	SAMESITE_STRICT,
};

#define INVALID_TIME ((time_t) -1)

const char * const getHttpMessageForCode(int code);

struct Cookie
{
	char* name;
	char* value;
	time_t expires;
	int secure;
	int httpOnly;
	enum SameSite samesite;
	char *originHost;
	char *domain;
	char *path;

};


int isCookieExpired(struct Cookie cookie);
int isCookieCSRF_valid(struct Cookie cookie, const char *site);
void freeCookie(struct Cookie* cookie);

struct HttpConnection
{
	void *in;
	void *out;
	int __impl__requires_seperate_in_out__;
	size_t (*fread)(void *buf, size_t len, size_t nmemb, void *stream);
	ssize_t (*fwrite)(const void *ptr, size_t size, size_t nmemb, void *stream);
	int (*fprintf)(void *stream, const char *format, ...);
	int (*fclose)(void *stream);
	int (*fflush)(void *stream);
	int (*feof)(void *stream);
	char* (*fgets)(char *str, int n, void *stream);
	char *host;
	char *realm;

	enum Auth_Scheme
	{
		AUTH_TYPE_NONE,
		AUTH_TYPE_BASIC,	// "Basic"	Basic		RFC7617
		//AUTH_TYPE_BEARER,	// "Bearer"	OAuth 2.0	RFC6750
		AUTH_TYPE_DIGEST,	// "Digest"	Digest		RFC7616
	} auth_scheme;

	struct Digest_Auth_CTX
	{
		uint32_t nonceCount;
		char cnonce[45]; // random 8 bytes as hex string + \0
		char *qop;
		char *nonce;
	} digest_auth_ctx;
	int secure;

	int doSaveCookies;
	size_t nCookies;
	struct Cookie* cookies;
};

void initHttpConnection(struct HttpConnection* conn, int saveCookies);

void freeHttpConnection(struct HttpConnection* conn);

int openHttpConnection(struct HttpConnection* conn, const char* host, const char* port);
#if ENABLE_HTTPS_SUPPORT
#define DEFAULT_HTTPS_PORT "443"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
int openHttpsConnection(struct HttpConnection* conn, const char* host, const char* port, int verifyCert);
#endif

int closeHttpConnection(struct HttpConnection* conn);
struct Cookie *findCookieByName(struct HttpConnection *conn, const char *cookie_name);

struct HttpRequest
{
	char *method;
	char *uri;
	char *http_version;
	size_t nheaders;
	char** header_name;
	char** header_value;

	int read_from_fd;
	union
	{
		int fd;
		char *buffer;
	} body;
	ssize_t content_length;
};

void initHttpRequest(struct HttpRequest *req);
void freeHttpRequest(struct HttpRequest *req);
void setupHttpRequest(struct HttpRequest *req, const char *method, const char *uri, const char *ver); // convenience function for below
void setUriHttpRequest(struct HttpRequest *req, const char* uri);
void setHttpVersionHttpRequest(struct HttpRequest *req, const char* ver);
void setMethodHttpRequest(struct HttpRequest *req, const char* method);

void addHeaderHttpRequest(struct HttpRequest *req, const char* header_name, const char* header_value);
void setHeaderHttpRequest(struct HttpRequest *req, const char* header_name, const char* header_value);

void setBufferedBodyHttpRequest(struct HttpRequest *req, const char* body, size_t len);
void setFdBodyHttpRequest(struct HttpRequest *req, int fd, ssize_t content_length);

void setHttpConnectionCreds(struct HttpConnection* conn, const char* user, const char* pass);
void authorizeHttpRequest(struct HttpConnection *conn, struct HttpRequest *req, const char *user, const char *pass);
int cookieShouldBeSent(struct HttpConnection *conn, struct HttpRequest *req, struct Cookie cookie);
void addCookiesToRequest(struct HttpConnection *conn, struct HttpRequest *req);

int sendHttpRequestHeaders(struct HttpConnection *conn, struct HttpRequest *req);
int debugHttpRequestHeaders(struct HttpConnection *conn, struct HttpRequest *req, FILE *out);


int recvHttpRequestHeaders(struct HttpConnection *conn, struct HttpRequest *req);

struct HttpResponse
{
	char *http_version;
	int http_code;
	char *http_code_desc;
	size_t nheaders;
	char** header_name;
	char** header_value;
	ssize_t content_length;
};

void freeHttpResponse(struct HttpResponse *res);
void setHttpVersionHttpResponse(struct HttpRequest *req, const char* ver);
int recvHttpResponseHeaders(struct HttpConnection *conn, struct HttpResponse *res);
char* findHeaderHttpResponse(struct HttpResponse *res, const char *header_name);
int addCookie(struct HttpConnection *conn, const char *the_cookie);

struct HttpResponse* makeRequest(struct HttpConnection *conn, struct HttpRequest *req);

#ifdef __cplusplus
}
#endif

#endif /* __HTTP_H_ */
