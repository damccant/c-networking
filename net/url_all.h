#ifndef __URL_H_
#define __URL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "url.h"
#include "ftp.h"
#include "http.h"

enum CONN_TYPE
{
	URL_DATA,
	URL_FILE,
	URL_FTP,
	URL_HTTP,
#if ENABLE_HTTPS_SUPPORT
	URL_HTTPS,
#endif
};


#ifdef __cplusplus
}
#endif

#endif /* __URL_H_ */