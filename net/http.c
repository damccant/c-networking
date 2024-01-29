#include "http.h"

const char * const getHttpMessageForCode(int code)
{
	switch(code)
	{
	case 100: return "Continue";						// Section 6.2.1 of [RFC7231]
	case 101: return "Switching Protocols";				// Section 6.2.2 of [RFC7231]
	case 102: return "Processing";						// RFC 2518
	case 103: return "Early Hints";						// RFC 8297
	case 110: return "Response is Stale";				// Section 5.5.1 of [RFC7234]
	case 111: return "Revalidation Failed";				// Section 5.5.2 of [RFC7234]
	case 112: return "Disconnected Operation";			// Section 5.5.3 of [RFC7234]
	case 113: return "Heuristic Expiration";			// Section 5.5.4 of [RFC7234]
	case 199: return "Miscellaneous Warning";			// Section 5.5.5 of [RFC7234]
	// 2xx Success
	case 200: return "OK";								// Section 6.3.1 of [RFC7231]
	case 201: return "Created";							// Section 6.3.2 of [RFC7231]
	case 202: return "Accepted";						// Section 6.3.3 of [RFC7231]
	case 203: return "Non-Authoritative Information";	// Section 6.3.4 of [RFC7231]
	case 204: return "No Content";						// Section 6.3.5 of [RFC7231]
	case 205: return "Reset Content";					// Section 6.3.6 of [RFC7231]
	case 206: return "Partial Content";					// Section 4.1 of [RFC7233]
	case 207: return "Multi-Status";					// Section 11.1 of [RFC4918]
	case 208: return "Already Reported";				// RFC 5842
	case 214: return "Transformation Applied";			// Section 5.5.6 of [RFC7234]
	case 226: return "IM Used";							// RFC 3229
	case 299: return "Miscellaneous Persistent Warning";// Section 5.5.7 of [RFC7234]
	// 3xx Redirection
	case 300: return "Multiple Choices";				// Section 6.4.1 of [RFC7231]
	case 301: return "Moved Permanently";				// Section 6.4.2 of [RFC7231]
	case 302: return "Found";							// Section 6.4.3 of [RFC7231]
	case 303: return "See Other";						// Section 6.4.4 of [RFC7231]
	case 304: return "Not Modified";					// Section 4.1 of [RFC7232]
	case 305: return "Use Proxy";						// Section 6.4.5 of [RFC7231]
	case 306: return "Switch Proxy";					// RFC 2616
	case 307: return "Temporary Redirect";				// Section 6.4.7 of [RFC7231]
	case 308: return "Permanent Redirect";				// Section 3 of [RFC7538]
	// 4xx Client Error
	case 400: return "Bad Request";						// Section 6.5.1 of [RFC7231]
	case 401: return "Unauthorized";					// Section 3.1 of [RFC7235]
	case 402: return "Payment Required";				// Section 6.5.2 of [RFC7231]
	case 403: return "Forbidden";						// Section 6.5.3 of [RFC7231]
	case 404: return "Not Found";						// Section 6.5.4 of [RFC7231]
	case 405: return "Method Not Allowed";				// Section 6.5.5 of [RFC7231]
	case 406: return "Not Acceptable";					// Section 6.5.6 of [RFC7231]
	case 407: return "Proxy Authentication Required";	// Section 3.2 of [RFC7235]
	case 408: return "Request Timeout";					// Section 6.5.7 of [RFC7231]
	case 409: return "Conflict";						// Section 6.5.8 of [RFC7231]
	case 410: return "Gone";							// Section 6.5.9 of [RFC7231]
	case 411: return "Length Required";					// Section 6.5.10 of [RFC7231]
	case 412: return "Precondition Failed";				// Section 4.2 of [RFC7232]
	case 413: return "Payload Too Large";				// Section 6.5.11 of [RFC7231]
	case 414: return "URI Too Long";					// Section 6.5.12 of [RFC7231]
	case 415: return "Unsupported Media Type";			// Section 6.5.13 of [RFC7231]
	case 416: return "Range Not Satisfiable";			// Section 4.4 of [RFC7233]
	case 417: return "Expectation Failed";				// Section 6.5.14 of [RFC7231]
	case 418: return "I'm a teapot";					// Section 2.3.3 of [RFC7168]
	case 421: return "Misdirected Request";				// Section 9.1.2 of [RFC7540]
	case 422: return "Unprocessable Entity";			// Section 11.2 of [RFC4918]
	case 423: return "Locked";							// Section 11.3 of [RFC4918]
	case 424: return "Failed Dependency";				// Section 11.4 of [RFC4918]
	case 425: return "Too Early";						// RFC 8470
	case 426: return "Upgrade Required";				// Section 6.5.15 of [RFC7231]
	case 428: return "Precondition Required";			// Section 3 of [RFC6585]
	case 429: return "Too Many Requests";				// Section 4 of [RFC6585]
	case 431: return "Request Header Fields Too Large";	// Section 5 of [RFC6585]
	case 451: return "Unavailable For Legal Reasons";	// Section 3 of [RFC7725]
	// 5xx Server Error
	case 500: return "Internal Server Error";			// Section 6.6.1 of [RFC7231]
	case 501: return "Not Implemented";					// Section 6.6.2 of [RFC7231]
	case 502: return "Bad Gateway";						// Section 6.6.3 of [RFC7231]
	case 503: return "Service Unavailable";				// Section 6.6.4 of [RFC7231]
	case 504: return "Gateway Timeout";					// Section 6.6.5 of [RFC7231]
	case 505: return "HTTP Version Not Supported";		// Section 6.6.6 of [RFC7231]
	case 506: return "Variant Also Negotiates";			// RFC 2295
	case 507: return "Insuffcient Storage";				// Section 11.5 of [RFC4918]
	case 508: return "Loop Detected";					// RFC 5842
	case 510: return "Not Extended";					// RFC 2774
	case 511: return "Network Authentication Required";	// Section 6 of [RFC6585]
	default: return NULL;
	}
}

// vectorized code
static int parse_month_3char_str(const char *s)
{
	if(s[0] == '\0' || s[1] == '\0' || s[2] == '\0')
		return -1;
	int_fast32_t d = (tolower(s[0]) << 16) | (tolower(s[1]) << 8) | (tolower(s[2]));
	switch(d)
	{
	case 0x6A616E: return 0;
	case 0x666562: return 1;
	case 0x6D6172: return 2;
	case 0x617072: return 3;
	case 0x6D6179: return 4;
	case 0x6A756E: return 5;
	case 0x6A756C: return 6;
	case 0x617567: return 7;
	case 0x736570: return 8;
	case 0x6F6374: return 9;
	case 0x6E6F76: return 10;
	case 0x646563: return 11;
	default:       return -1;
	}
}

// RFC6265 Section 5.1.1
static inline int char_is_cookie_date_delim(const char c)
{
	return (c == 0x09) ||
		(c >= 0x20 && c <= 0x2f) ||
		(c >= 0x3b && c <= 0x40) ||
		(c >= 0x5b && c <= 0x60) ||
		(c >= 0x7b && c <= 0x7e);
}

static int matches_cookie_date_time(const char *c, struct tm* t)
{
	int hour;
	int min;
	int sec;
	char d1, d2;
	if(!isdigit(d1 = *c))
		return 0;
	++c;
	if(*c == ':')
	{
		d2 = d1;
		d1 = '0';
		++c;
	}
	else if(isdigit(d2 = *c))
	{
		if(*(++c) != ':')
			return 0;
		++c;
	}
	else
		return 0;
	hour = (d1 - '0') * 10 + (d2 - '0');

	if(!isdigit(d1 = *c))
		return 0;
	++c;
	if(*c == ':')
	{
		d2 = d1;
		d1 = '0';
		++c;
	}
	else if(isdigit(d2 = *c))
	{
		if(*(++c) != ':')
			return 0;
		++c;
	}
	else
		return 0;
	min = (d1 - '0') * 10 + (d2 - '0');

	if(!isdigit(d1 = *c))
		return 0;
	++c;
	if(!isdigit(d2 = *c))
	{
		d2 = d1;
		d1 = '0';
	}
	sec = (d1 - '0') * 10 + (d2 - '0');
	t->tm_hour = hour;
	t->tm_min = min;
	t->tm_sec = sec;
	return 1;
}

static int matches_cookie_date_day_of_month(const char *c, struct tm* t)
{
	char d1, d2;
	if(!isdigit(d1 = *c))
		return 0;
	++c;
	if(!isdigit(d2 = *c))
	{
		d2 = d1;
		d1 = '0';
	}
	else if(isdigit(*(++c)))
		return 0;
	t->tm_mday = (d1 - '0') * 10 + (d2 - '0');
	return 1;
}

static int matches_cookie_date_month(const char *c, struct tm* t)
{
	int i = parse_month_3char_str(c);
	if(i < 0)
		return 0;
	t->tm_mon = i;
	return 1;
}

static int matches_cookie_date_year(const char *c, struct tm* t)
{
	if(!isdigit(*c))
		return 0;
	int year = strtol(c, NULL, 10);
	if(year == 0)
		return 0;
	if(year >= 0 && year <= 69)
		year += 100; // year 2000 or greater
	if(year > 99)
		year -= 1900; // 4 digit year
	t->tm_year = year;
	return 1;
}

time_t parse_cookie_date(const char *date)
{
	unsigned char flags = 0; // fits in a single CPU register
	struct tm the_time;
	the_time.tm_isdst = 0;
	//while(char_is_cookie_date_delim(*date)) date++;
	while(*date != '\0' && *date != ';')
	{
		while(char_is_cookie_date_delim(*date)) date++;
		const char *eot = date;
		
		while(*eot != ';' && *eot != '\0' && !char_is_cookie_date_delim(*eot)) eot++;
		//printf("trying to parse \"%s\"\n", date);
		// TODO: match dates
		if(!(flags & 0x01) && matches_cookie_date_time(date, &the_time))
			flags |= 0x01;
		else if(!(flags & 0x02) && matches_cookie_date_day_of_month(date, &the_time))
			flags |= 0x02;
		else if(!(flags & 0x04) && matches_cookie_date_month(date, &the_time))
			flags |= 0x04;
		else if(!(flags & 0x08) && matches_cookie_date_year(date, &the_time))
			flags |= 0x08;
		else
			;//fprintf(stderr, "warn: failed to parse token \"%s\" from cookie date\n", date);

		if(flags == 0b00001111)
			break;
		date = eot;
	}
	if(flags != 0b00001111)
		return INVALID_TIME;
	if(the_time.tm_mday < 1 || the_time.tm_mday >= 31)
		return INVALID_TIME;
	if(the_time.tm_year < -299)
		return INVALID_TIME;
	if(the_time.tm_hour > 23 || the_time.tm_min > 59 || the_time.tm_sec > 60) // allow for leap seconds
		return INVALID_TIME;
	return mktime(&the_time);
}

int addCookie(struct HttpConnection *conn, const char *the_cookie)
{
	//printf("parse_cookie(%p, \"%s\")\n", conn, the_cookie);
	if(the_cookie == NULL)
		return 1;
	struct Cookie cookie;
	cookie.expires = INVALID_TIME;
	cookie.secure = 0;
	cookie.httpOnly = 0;
	cookie.domain = NULL;
	cookie.path = NULL;
	cookie.originHost = strdup(conn->host);
	cookie.samesite = SAMESITE_LAX;
	const char *t = strchr(the_cookie, '=');
	if(t == NULL)
		return 1;
	cookie.name = strndup(the_cookie, t - the_cookie);
	const char *e = strchr(t, ';');
	if(e == NULL)
		cookie.value = strdup(++t);
	else
	{
		++t;
		cookie.value = strndup(t, e-t);
		while(*e == ';')
		{
			while(*e == ';' || *e == ' ' || *e == '\t') e++;
			if(*e == '\0') break;
			//printf("parsing \"%s\"\n", e);
			const char *eq = NULL;
			for(const char *u = e + 1; *u != ';' && *u != '\0'; u++)
				if(*u == '=')
				{
					eq = u + 1;
					break;
				}
			
			if(my_strincmp("Expires", e, sizeof("Expires") - 1) == 0)
			{
				if(eq == NULL)
					goto unk;
				cookie.expires = parse_cookie_date(eq);
			}
			else if(my_strincmp("Max-Age", e, sizeof("Max-Age") - 1) == 0)
			{
				if(eq == NULL)
					goto unk;
				cookie.expires = add_seconds(time(NULL), strtoull(eq, &eq, 0));
			}
			else if(my_strincmp("Domain", e, sizeof("Domain") - 1) == 0)
			{
				if(eq == NULL)
					goto unk;
				if(*eq == '.')
					eq++;
				// TODO copy this to cookie.domain
				;
			}
			else if(my_strincmp("Path", e, sizeof("Path") - 1) == 0)
				;
			else if(my_strincmp("Secure", e, sizeof("Secure") - 1) == 0)
				cookie.secure = 1;
			else if(my_strincmp("HttpOnly", e, sizeof("HttpOnly") - 1) == 0)
				cookie.httpOnly = 1;
			else if(my_strincmp("SameSite", e, sizeof("SameSite") - 1) == 0)
			{
				if(eq == NULL)
					goto unk;
				if(my_strincmp("None", eq, sizeof("None") - 1) == 0)
					cookie.samesite = SAMESITE_NONE;
				else if(my_strincmp("Lax", eq, sizeof("Lax") - 1) == 0)
					cookie.samesite = SAMESITE_LAX;
				else if(my_strincmp("Strict", eq, sizeof("Strict") - 1) == 0)
					cookie.samesite = SAMESITE_STRICT;
			}
			if(eq != NULL)
				e = eq;
			unk:
			while(*e != '\0' && *e != ';') e++;
		}
	}
	if(cookie.samesite == SAMESITE_NONE && !cookie.secure)
	{
		fprintf(stderr, "warn: rejecting insecure cookie \"%s\"=\"%s\" with SameSite=None!\n", cookie.name, cookie.value);
		freeCookie(&cookie);
		return 1;
	}
	printf("Cookie: \"%s\" = \"%s\", secure = %d, httponly = %d\n", cookie.name, cookie.value, cookie.secure, cookie.httpOnly);
	printf("Domain = \"%s\", Path = \"%s\", SameSite = %d\n", cookie.domain, cookie.path, cookie.samesite);
	char whatever[256];
	struct tm* yeah = gmtime(&cookie.expires);
	if(yeah != NULL)
		strftime(whatever, sizeof(whatever), "%c", yeah);
	else
		strcpy(whatever, "cookie.expires is NULL????\n");
	printf("Expires = %s\n", whatever);
}


// Thursday, Jan 1, 1970 00:00:00
const time_t __mkInvalidTime_t__()
{
	struct tm epoch;
	epoch.tm_sec = 0;
	epoch.tm_min = 0;
	epoch.tm_hour = 0;
	epoch.tm_mday = 0;
	epoch.tm_mon = 0;
	epoch.tm_year = 70;
	epoch.tm_wday = 4;
	epoch.tm_yday = 0;
	epoch.tm_isdst = 0;
	return mktime(&epoch);
}

int isCookieExpired(struct Cookie cookie)
{
	if(cookie.expires == INVALID_TIME)
		return 0;
	return difftime(cookie.expires, time(NULL)) < 0;
}

int isCookieCSRF_valid(struct Cookie cookie, const char *site)
{
	// TODO: check stuff
	return 1;
}

void freeCookie(struct Cookie *cookie)
{
	if(cookie == NULL)
		return;
	if(cookie->name != NULL)
		free(cookie->name);
	if(cookie->value != NULL)
		free(cookie->value);
}

void initHttpConnection(struct HttpConnection* conn, int saveCookies)
{
	conn->auth_scheme = AUTH_TYPE_NONE;
	conn->digest_auth_ctx.nonceCount = 0;
	conn->digest_auth_ctx.nonce = NULL;
	conn->digest_auth_ctx.qop = NULL;
	conn->realm = NULL;
	conn->host = NULL;
	conn->doSaveCookies = saveCookies;
	conn->nCookies = 0;
	conn->cookies = NULL;
}

void freeHttpConnection(struct HttpConnection* conn)
{
	if(conn->digest_auth_ctx.nonce != NULL)
		free(conn->digest_auth_ctx.nonce);
	if(conn->digest_auth_ctx.qop != NULL)
		free(conn->digest_auth_ctx.qop);
	if(conn->host != NULL)
		free(conn->host);
	if(conn->realm != NULL)
		free(conn->realm);
	if(conn->cookies != NULL)
	{
		for(size_t i = 0; i < conn->nCookies; i++)
			freeCookie(conn->cookies + i);
		free(conn->cookies);
	}
}

int openHttpConnection(struct HttpConnection* conn, const char* host, const char* port)
{
	if(conn->host == NULL)
		conn->host = strdup(host);
	else if(strcmp(host, conn->host))
	{
		free(conn->host);
		conn->host = strdup(host);
	}
	SOCKET sock = connectTcpSocket(host, port);
	if(sock == INVALID_SOCKET || sock == SOCKET_ERROR)
		return -1;
	conn->in = bufferInSocketToCStream(sock);
	conn->out = bufferOutSocketToCStream(sock);
	conn->secure = 0;
	conn->__impl__requires_seperate_in_out__ = 0;
	conn->fread = (size_t (*)(void *buf, size_t len, size_t nmemb, void *stream))fread;
	conn->fwrite = (ssize_t (*)(const void *ptr, size_t size, size_t nmemb, void *stream))fwrite;
	conn->fprintf = (int (*)(void *stream, const char *format, ...))fprintf;
	conn->fclose = (int (*)(void *stream))fclose;
	conn->fflush = (int (*)(void *stream))fflush;
	conn->feof = (int (*)(void *stream))feof;
	conn->fgets = (char* (*)(char *str, int n, void *stream))fgets;
	return 0;
}

#if ENABLE_HTTPS_SUPPORT

static int __close_BIO_stream__(BIO *b)
{
	BIO_set_close(b, BIO_CLOSE);
	BIO_free_all(b);
	return 0;
}

static char* __fixed_BIO_gets__(char *str, int n, BIO *stream)
{
	int i;
	if((i = BIO_gets(stream, str, n)) < 0)
	{
		fprintf(stderr, "BIO_gets() returned %i!\n", i);
		return NULL;
	}
	return str;
}

static size_t __fixed_BIO_read__(void *buf, size_t len, size_t nmemb, BIO *stream)
{
	int r = BIO_read(stream, buf, nmemb * len);
	return r;
}

static int __fixed_BIO_flush__(BIO *stream)
{
	if(BIO_flush(stream) == 1)
		return 0;
	while(BIO_should_retry(stream))
		if(BIO_flush(stream) == 1)
			return 0;
	return 1;
}

static int __fixed_BIO_eof__(BIO *stream)
{
	return BIO_eof(stream);
}

SSL_CTX *createClientSslContext()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_CTX *ssl = SSL_CTX_new(SSLv23_method());
#else
	SSL_CTX *ssl = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ssl, TLS1_2_VERSION);
#endif
	if(SSL_CTX_set_default_verify_paths(ssl) != 1)
	{
		fprintf(stderr, "failed to load trust store!\n");
		return NULL;
	}
	return ssl;
}

int certificateOK(SSL *ssl, const char *host)
{
	int err = SSL_get_verify_result(ssl);
	if(err != X509_V_OK)
	{
		const char *msg = X509_verify_cert_error_string(err);
		fprintf(stderr, "Certificate verifcation error: %s\n", msg);
		return 0;
	}
	X509 *cert = SSL_get_peer_certificate(ssl);
	if(cert == NULL)
	{
		fprintf(stderr, "Server did not present certificate!\n");
		return 0;
	}
	if(X509_check_host(cert, host, strlen(host), 0, NULL) != 1)
	{
		fprintf(stderr, "Certificate verification error: Hostname mismatch\n");
		return 0;
	}
	return 1;
}

int openTlsConnection(struct HttpConnection *conn, const char *host, const char *port, int verifyCert)
{
	SSL_CTX *ssl_ctx = createClientSslContext();
	if(ssl_ctx == NULL)
		return -1;
	SOCKET sock = connectTcpSocket(host, port);
        if(sock == INVALID_SOCKET || sock == SOCKET_ERROR)
                return -1;
	int fd = convertSocketToFd(sock, O_RDWR | O_BINARY);
	if(fd < 0)
		return -1;
	BIO *raw = BIO_new_fd(fd, BIO_CLOSE);
	if(raw == NULL)
		return -1;
	BIO *ssl_bio = BIO_new_ssl(ssl_ctx, 1); // 1 = client, 0 = server, we are a client
	if(ssl_bio == NULL)
		return -1;
	ssl_bio = BIO_push(ssl_bio, raw);
	if(ssl_bio == NULL)
		return -1;
	SSL *ssl = NULL;
	BIO_get_ssl(ssl_bio, &ssl);
	if(ssl == NULL)
		return -1;
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); // auto retry please :)
	if(SSL_set_tlsext_host_name(ssl, host) <= 0)
	{
		fprintf(stderr, "failed to set SNI hostname\n");
		return -1;
	}
	long i = BIO_do_handshake(ssl_bio);
	unsigned long err = ERR_get_error();
	if(i <= 0)
	{
		fprintf(stderr, "error during TLS handshake: %ld %lu %s\n", i, err, ERR_error_string(err, NULL));
		return -1;
	}
	if(verifyCert && !certificateOK(ssl, host))
	{
		fprintf(stderr, "error verifying certificate!\n");
		return -1;
	}
	BIO *bufferedStream = BIO_push(BIO_new(BIO_f_buffer()), ssl_bio);
	if(bufferedStream == NULL)
	{
		return -1;
	}
	conn->in = bufferedStream;
	conn->out = conn->in;
	conn->__impl__requires_seperate_in_out__ = 0;

	return 0;
}

int openHttpsConnection(struct HttpConnection* conn, const char* host, const char* port, int verifyCert)
{
	if(conn->host == NULL)
		conn->host = strdup(host);
	else if(strcmp(host, conn->host))
	{
		free(conn->host);
		conn->host = strdup(host);
	}
	// openconnection
	if(openTlsConnection(conn, host, port, verifyCert))
		return -1;
	conn->secure = 1;
	conn->fread = (size_t (*)(void*, size_t, size_t, void*))__fixed_BIO_read__;
	conn->fwrite = (ssize_t (*)(const void*, size_t, size_t, void*))BIO_write;
	conn->fprintf = (int (*)(void*, const char*, ...))BIO_printf;
	conn->fclose = (int (*)(void*))__close_BIO_stream__;
	conn->fflush = (int (*)(void*))__fixed_BIO_flush__;
	conn->feof = (int (*)(void*))__fixed_BIO_eof__;
	conn->fgets = (char* (*)(char*, int, void*))__fixed_BIO_gets__;
	return 0;
}
#endif

int closeHttpConnection(struct HttpConnection* conn)
{
	int i = conn->fclose(conn->out), j = 0;
	if(i)
	{
		perror("fclose()");
		fprintf(stderr, "fclose(conn->out) failed!\n");
	}
	if(conn->__impl__requires_seperate_in_out__)
	{
		j = conn->fclose(conn->in);
		if(j)
		{
			perror("fclose()");
			fprintf(stderr, "fclose(conn->in) failed!\n");
		}
	}
	return i || j; // can't do it direct because short-circuit evaluation works against us here
}

char *calculate_digest_ha1(const char* username, const char* realm, const char* password)
{
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, username, strlen(username));
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, realm, strlen(realm));
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, password, strlen(password));
	MD5Final(&md5);
	return MD5printable_from_context_new(&md5);
}

char *calculate_digest_ha2_auth(const char* method, const char* uri)
{
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, method, strlen(method));
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, uri, strlen(uri));
	MD5Final(&md5);
	return MD5printable_from_context_new(&md5);
}

char *calculate_digest_response_auth(const char* ha1, const char* nonce, uint32_t nonceCount, const char* cnonce, const char *qop, const char *ha2)
{
	MD5_CTX md5;
	MD5Init(&md5);
	MD5Update(&md5, ha1, strlen(ha1));
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, nonce, strlen(nonce));
	MD5Update(&md5, ":", 1);
	char ncs[9];
	snprintf(ncs, sizeof(ncs), "%08x", nonceCount);
	MD5Update(&md5, ncs, 8);
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, cnonce, strlen(cnonce));
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, qop, strlen(qop));
	MD5Update(&md5, ":", 1);
	MD5Update(&md5, ha2, strlen(ha2));
	MD5Final(&md5);
	return MD5printable_from_context_new(&md5);
	//return MD5(ha1:nonce:nonceCount:cnonce:qop:ha2)
}



static const char defaultRequestMethod[] = "GET";
static const char defaultRequestUri[] = "/";
static const char defaultRequestVersion[] = "HTTP/1.1";

void initHttpRequest(struct HttpRequest *req)
{
	// copy some sane defaults
	req->method = defaultRequestMethod;
	req->uri = defaultRequestUri;
	req->http_version = defaultRequestVersion;
	req->nheaders = 0;
	req->header_name = (char**)malloc(req->nheaders * sizeof(char*));
	req->header_value = (char**)malloc(req->nheaders * sizeof(char*));
	req->read_from_fd = 0;
	req->body.buffer = NULL;
	req->content_length = 0;
}

void freeHttpRequest(struct HttpRequest *req)
{
	if(req->method != defaultRequestMethod)
		free(req->method);
	if(req->uri != defaultRequestUri)
		free(req->uri);
	if(req->http_version != defaultRequestVersion)
		free(req->http_version);
	for(size_t i = 0; i < req->nheaders; i++)
	{
		free(req->header_name[i]);
		free(req->header_value[i]);
	}
	if(req->header_name != NULL)
		free(req->header_name);
	if(req->header_value != NULL)
		free(req->header_value);
}

void setupHttpRequest(struct HttpRequest *req, const char *method, const char *uri, const char *ver)
{
	setMethodHttpRequest(req, method);
	setUriHttpRequest(req, uri);
	setHttpVersionHttpRequest(req, ver);
}

void setUriHttpRequest(struct HttpRequest *req, const char *uri)
{
	req->uri = strdup(uri);
}

void setHttpVersionHttpRequest(struct HttpRequest *req, const char *ver)
{
	req->http_version = strdup(ver);
}

void setMethodHttpRequest(struct HttpRequest *req, const char *method)
{
	req->method = strdup(method);
}

static inline size_t __findHeaderHttpRequestIndex__(struct HttpRequest *req, const char *header_name)
{
	for(size_t i = 0; i < req->nheaders; i++)
		if(my_stricmp(header_name, req->header_name[i]) == 0)
			return i;
	return -1;
}

char* findHeaderHttpResponse(struct HttpResponse *res, const char *header_name)
{
	for(size_t i = 0; i < res->nheaders; i++)
		if(my_stricmp(header_name, res->header_name[i]) == 0)
		{
			//printf("found header \"%s\" = \"%s\"\n", res->header_name[i], res->header_value[i]);
			return res->header_value[i];
		}
	//printf("could not find header with name \"%s\"\n", header_name);
	return NULL;
}

/*void __addHeaderHttpRequest__(struct HttpRequest *req, const char *header_name, const char *header_value)
{
	req->nheaders++;
	req->header_name = (char**)realloc(req->header_name, sizeof(char*) * req->nheaders);
	req->header_value = (char**)realloc(req->header_value, sizeof(char*) * req->nheaders);
	size_t header_name_len = strlen(header_name);
	size_t header_val_len = strlen(header_value);
	req->header_value[req->nheaders-1] = (char*)malloc(header_name_len + 1 + header_value_len + 1);
	memcpy(req->header_name, header_name, header_name_len);
	req->header_name[header_name_len] = '\0';
	memcpy(req->header_name + header_name_len + 1, header_value, header_value_len);
	req->header_name[header_name_len + 1 + header_value_len] = '\0';
}*/

void addHeaderHttpRequest_nocopy(struct HttpRequest *req, char *header_name, char *header_value)
{
	req->nheaders++;
	if(req->header_name == NULL)
	{
		printf("this should never happen!\n");
		req->header_name = (char**)malloc(sizeof(char*) * req->nheaders);
		if(req->header_name == NULL)
		{
			perror("malloc()");
			fprintf(stderr, "failed to malloc(req->header_name = %p, %zu)\n", req->header_name, sizeof(char*) * req->nheaders);
		}
	}
	else
	{
		//printf("before realloc(), req->header_name = %p\n", req->header_name);
		req->header_name = (char**)realloc(req->header_name, sizeof(char*) * req->nheaders);
		if(req->header_name == NULL)
		{
			perror("realloc()");
			fprintf(stderr, "failed to realloc(req->header_name = %p, %zu)\n", req->header_name, sizeof(char*) * req->nheaders);
		}
	}
	
	req->header_name[req->nheaders-1] = header_name;

	if(req->header_value == NULL)
	{
		printf("this should never happen!\n");
		req->header_value = (char**)malloc(sizeof(char*) * req->nheaders);
		if(req->header_value == NULL)
		{
			perror("malloc()");
			fprintf(stderr, "failed to malloc(req->header_value = %p, %zu)\n", req->header_value, sizeof(char*) * req->nheaders);
		}
	}
	else
	{
		req->header_value = (char**)realloc(req->header_value, sizeof(char*) * req->nheaders);
		if(req->header_value == NULL)
		{
			perror("realloc()");
			fprintf(stderr, "failed to realloc(req->header_value = %p, %zu)\n", req->header_value, sizeof(char*) * req->nheaders);
		}
	}
	req->header_value[req->nheaders-1] = header_value;
}

void addHeaderHttpRequest(struct HttpRequest *req, const char *header_name, const char *header_value)
{
	req->nheaders++;
	req->header_name = (char**)realloc(req->header_name, sizeof(char*) * req->nheaders);
	req->header_value = (char**)realloc(req->header_value, sizeof(char*) * req->nheaders);
	req->header_value[req->nheaders-1] = strdup(header_value);
	req->header_name[req->nheaders-1] = strdup(header_name);
}

void setHeaderHttpRequest(struct HttpRequest *req, const char *header_name, const char *header_value)
{
	size_t found = __findHeaderHttpRequestIndex__(req, header_name);
	if(found < req->nheaders)
	{
		free(req->header_value[found]);
		req->header_value[found] = strdup(header_value);
	}
	else
		addHeaderHttpRequest(req, header_name, header_value);
}

int debugHttpRequestHeaders(struct HttpConnection *conn, struct HttpRequest *req, FILE *out)
{
	if(fprintf(out, "%s %s %s\r\n", req->method, req->uri, req->http_version) < 0)
	{
		perror("fprintf()");
		return -1;
	}
	if(fprintf(out, "Host: %s\r\n", conn->host) < 0)
	{
		perror("fprintf()");
		return -1;
	}
	for(size_t i = 0; i < req->nheaders; i++)
		if(fprintf(out, "%s: %s\r\n", req->header_name[i], req->header_value[i]) < 0)
			return -1;
	if(fprintf(out, "\r\n") < 0)
	{
		perror("fprintf()");
		return -1;
	}
	return 0;
}

int sendHttpRequestHeaders(struct HttpConnection *conn, struct HttpRequest *req)
{
	if(conn->fprintf(conn->out, "%s %s %s\r\n", req->method, req->uri, req->http_version) < 0)
	{
		perror("fprintf()");
		return -1;
	}
	if(conn->fprintf(conn->out, "Host: %s\r\n", conn->host) < 0)
	{
		perror("fprintf()");
		return -1;
	}
	for(size_t i = 0; i < req->nheaders; i++)
		if(conn->fprintf(conn->out, "%s: %s\r\n", req->header_name[i], req->header_value[i]) < 0)
			return -1;
	if(conn->fprintf(conn->out, "\r\n") < 0)
	{
		perror("fprintf()");
		return -1;
	}
	return 0;
}

static void add_digest_authorization_header(struct HttpConnection *conn, struct HttpRequest *req, const char *user, const char *pass)
{
	conn->digest_auth_ctx.nonceCount++;
	random_base64(conn->digest_auth_ctx.cnonce, sizeof(conn->digest_auth_ctx.cnonce) - 1);

	//printf("add_digest_authorization_header()\n");
	char *ha1 = calculate_digest_ha1(user, conn->realm, pass);
	char *ha2 = calculate_digest_ha2_auth(req->method, req->uri);
	char *response = calculate_digest_response_auth(ha1, conn->digest_auth_ctx.nonce, conn->digest_auth_ctx.nonceCount, conn->digest_auth_ctx.cnonce, conn->digest_auth_ctx.qop, ha2);
	// TODO: scrub ha1 and ha2 from memory
	//printf("calculated ha1 = \"%s\"\n", ha1);
	//printf("calculated ha2 = \"%s\"\n", ha2);
	memset(ha1, 0, strlen(ha1));
	memset(ha2, 0, strlen(ha2));

	free(ha1);
	free(ha2);
	char *auth_header = (char*)malloc(512);
	if(auth_header == NULL)
		perror("malloc()");
	snprintf(auth_header, 512, "Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",cnonce=\"%s\",nc=%08x,qop=%s,response=\"%s\"",
		user, conn->realm, conn->digest_auth_ctx.nonce, req->uri, conn->digest_auth_ctx.cnonce, conn->digest_auth_ctx.nonceCount, conn->digest_auth_ctx.qop, response);
	free(response);
	addHeaderHttpRequest_nocopy(req, strdup("Authorization"), auth_header);
}

static void add_basic_authorization_header(struct HttpConnection *conn, struct HttpRequest *req, const char *user, const char *pass)
{
	char *cred = (char*)malloc(512);
	size_t cred_len = snprintf(cred, 512, "%s:%s", user, pass);
	char *auth_header = (char*)malloc(512);
	strcpy(auth_header, "Basic ");
	// TODO: some better bounds checking
	base64_encode(auth_header + 6, 512 - 6, cred, cred_len);
	// TODO: scrub cred from memory
	free(cred);
	addHeaderHttpRequest_nocopy(req, strdup("Authorization"), auth_header);
}

void authorizeHttpRequest(struct HttpConnection *conn, struct HttpRequest *req, const char *user, const char *pass)
{
	switch(conn->auth_scheme)
	{
	case AUTH_TYPE_NONE:
		break;
	case AUTH_TYPE_BASIC:
		add_basic_authorization_header(conn, req, user, pass);
		break;
	case AUTH_TYPE_DIGEST:
		add_digest_authorization_header(conn, req, user, pass);
		break;
	}
}

int cookieShouldBeSent(struct HttpConnection *conn, struct HttpRequest *req, struct Cookie cookie)
{
	if(isCookieExpired(cookie))
		return 0;
	if(cookie.secure && !conn->secure)
		return 0;
	return 1;
}

void addCookiesToRequest(struct HttpConnection *conn, struct HttpRequest *req)
{
	if(conn->nCookies <= 0 || conn->cookies == NULL)
		return;
	size_t pos = 0;
	size_t buf_sz = 20;
	char *buf = (char*)malloc(buf_sz);
	buf[0] = '\0';
	int first = 1;
	for(size_t i = 0; i < conn->nCookies; i++)
	{
		if(!cookieShouldBeSent(conn, req, conn->cookies[i]))
			continue;
		size_t req_size = strlen(conn->cookies[i].name) + 1 + strlen(conn->cookies[i].value) + 2;
		if(buf_sz - pos < req_size + 1)
			; // realloc
	}
}

static const char AUTH_TYPE_BASIC_NAME[5] = { 'B', 'a', 's', 'i', 'c' };
static const char AUTH_TYPE_DIGEST_NAME[6] =  { 'D', 'i', 'g', 'e', 's', 't'};

static inline void parse_basic_authorization_header(struct HttpConnection *conn, const char *t)
{

}

static inline void parse_digest_authorization_header(struct HttpConnection *conn, const char *t)
{
	const char *x, *y, *z;
	x = y = z = t;

	while(*x != '\0')
	{
		if(*x == '\0') return;
		y = x;
		while(*y != '\0' && *y != ' ' && *y != '=') y++;
		if(*y == '=')
		{
			size_t klen = y - x;
			size_t vlen;
			while(*y == '=' || *y == ' ') y++;
			if(*y == '\"')
			{
				y++;
				z = y;
				while(*z != '\0' && *z != '\"') z++;
				vlen = z-y;
				if(*z == '\"') z++;
				while(*z == ',' || *z == ' ') z++;
			}
			else
			{
				z = y;
				while(*z != '\0' && *z != ',') z++;
				vlen = z-y;
				while(*z == ',' || *z == ' ') z++;
			}

			if(klen == 0)
			{
				; // ?
			}
			else if(my_strincmp("qop", x, klen) == 0)
			{
				if(my_memmem(y, vlen, "auth", 4) != NULL)
				{
					if(conn->digest_auth_ctx.qop != NULL)
						free(conn->digest_auth_ctx.qop);
					conn->digest_auth_ctx.qop = strdup("auth");
				}
				else
				{
					fprintf(stderr, "Unrecognized qop \"");
					fwrite(y, 1, vlen, stderr);
					fprintf(stderr, "\"!\n");
				}
			}
			else if(my_strincmp("realm", x, klen) == 0)
			{
				if(conn->realm != NULL)
					free(conn->realm);
				conn->realm = (char*)malloc(vlen + 1);
				memcpy(conn->realm, y, vlen);
				conn->realm[vlen] = '\0';
			}
			else if(my_strincmp("nonce", x, klen) == 0)
			{
				if(conn->digest_auth_ctx.nonce != NULL)
					free(conn->digest_auth_ctx.nonce);
				conn->digest_auth_ctx.nonce = (char*)malloc(vlen + 1);
				memcpy(conn->digest_auth_ctx.nonce, y, vlen);
				conn->digest_auth_ctx.nonce[vlen] = '\0';
			}
			x = z;
		}
	}
}

int parse_authorization_header(struct HttpConnection *conn, const char *t)
{
	if(my_strincmp(t, AUTH_TYPE_BASIC_NAME, sizeof(AUTH_TYPE_BASIC_NAME)) == 0)
	{
		conn->auth_scheme = AUTH_TYPE_BASIC;
		t += sizeof(AUTH_TYPE_BASIC_NAME);
		while(*t == ' ') t++;
		parse_basic_authorization_header(conn, t);
	}
	else if(my_strincmp(t, AUTH_TYPE_DIGEST_NAME, sizeof(AUTH_TYPE_DIGEST_NAME)) == 0)
	{
		conn->auth_scheme = AUTH_TYPE_DIGEST;
		t += sizeof(AUTH_TYPE_DIGEST_NAME);
		while(*t == ' ') t++;
		parse_digest_authorization_header(conn, t);
	}
	else
		fprintf(stderr, "unknown authorization type \"%s\"\n", t);
	return 0;
}




void freeHttpResponse(struct HttpResponse *res)
{
	if(res->http_version != NULL)
		free(res->http_version);
	for(size_t i = 0; i < res->nheaders; i++)
		free(res->header_name[i]);
	if(res->header_name != NULL)
		free(res->header_name);
	if(res->header_value != NULL)
		free(res->header_value);
}

int recvHttpResponseHeaders(struct HttpConnection *conn, struct HttpResponse *res)
{
	conn->fflush(conn->out); // flush all the output so the server can respond
	res->http_version = NULL;
	res->nheaders = 0;
	res->header_name = NULL;
	res->header_value = NULL;
	char *tmp = (char*)malloc(1024);
	if(tmp == NULL)
	{
		perror("malloc()");
		return -1;
	}
	char *t;
	if(conn->fgets(tmp, 1024, conn->in) == NULL)
	{
		perror("fgets()");
		free(tmp);
		return -1;
	}

	res->http_version = strdup(tmp);
	if(res->http_version == NULL)
	{
		perror("strdup()");
		free(tmp);
		return -1;
	}
	t = res->http_version;
	while(*t != ' ' && *t != '\0') t++;
	if(*t == ' ') *(t++) = '\0';
	while(*t == ' ') t++;
	res->http_code = strtoull(t, &t, 0);
	//res->http_code = t;
	while(*t != ' ' && *t != '\0') t++;
	if(*t == ' ') *(t++) = '\0';
	while(*t == ' ') t++;
	res->http_code_desc = t;
	while(*t != '\r' && *t != '\n' && *t != '\0') t++;
	if(*t == '\r' || *t == '\n') *t = '\0';

	res->nheaders = 0;
	res->header_name = (char**)malloc(1 * sizeof(char*));
	res->header_value = (char**)malloc(1 * sizeof(char*));

	while(*tmp != '\r' && *tmp != '\n' && *tmp != '\0')
	{
		if(conn->fgets(tmp, 1024, conn->in) == NULL)
		{
			perror("fgets()");
			free(tmp);
			return -1;
		}
		if(*tmp != '\0' && *tmp != '\r' && *tmp != '\n')
		{
			res->nheaders++;
			res->header_name = (char**)realloc(res->header_name, res->nheaders * sizeof(char*));
			res->header_value = (char**)realloc(res->header_value, res->nheaders * sizeof(char*));
			res->header_name[res->nheaders - 1] = strdup(tmp);
			t = res->header_name[res->nheaders - 1];
			while(*t != '\0' && *t != ':' && *t != ' ') t++;
			if(*t == ':' || *t == ' ') *(t++) = '\0';
			else
			{
				fprintf(stderr, "did not found ':' or ' ' in \"%s\"\n", res->header_name[res->nheaders - 1]);
				res->header_value[res->nheaders - 1] = NULL;
			}
			while(*t == ' ') t++;
			res->header_value[res->nheaders - 1] = t;
			while(*t != '\r' && *t != '\n' && *t != '\0') t++;
			if(*t == '\r' || *t == '\n') *t = '\0';
		}
	}
	free(tmp);
	res->content_length = -1;
	for(size_t i = 0; i < res->nheaders; i++)
		if(my_stricmp("Content-Length", res->header_name[i]) == 0)
			res->content_length = strtoull(res->header_value[i], NULL, 0);
		else if(my_stricmp("WWW-Authenticate", res->header_name[i]) == 0)
			parse_authorization_header(conn, res->header_value[i]);
		else if(conn->doSaveCookies && my_stricmp("Set-Cookie", res->header_name[i]) == 0)
			addCookie(conn, res->header_value[i]);

	return 0;
}

