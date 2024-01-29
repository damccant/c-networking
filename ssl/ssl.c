#include "ssl.h"

static openssl_init = 0;
int init_openssl()
{
	if(openssl_init)
		return 0;
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_string();
	SSL_load_error_strings();
	SSL_library_init();
	openssl_init = 1;
	return 0;
}
