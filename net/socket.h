#ifndef __SOCKET_H_
#define __SOCKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32

#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")

#define WIN32_LEAN_AND_MEAN
// we are running at least Windows XP
// #if defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0501
// #define _WIN32_WINNT 0x0501
// #endif

// #ifndef _WIN32_WINNT
// #define _WIN32_WINNT 0x0501
// #endif /*_WIN32_WINNT*/

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

int my_inet_pton(int af, const char *restrict src, void *restrict dst);
const char *my_inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size);

#else /* _WIN32 */

typedef int SOCKET;
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h> // inet_ntop(), inet_pton()
#include <stdarg.h>
#include <netdb.h>

#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket( x )  close( x )
#define my_inet_pton( x, y, z ) inet_pton( x, y, z )
#define my_inet_ntop( w, x, y, z ) inet_ntop( w, x, y, z )
#endif /* _WIN32 */

#ifndef O_BINARY //needed for broken operating systems (windows)
#define O_BINARY 0

#endif

int initializeSocketLib();
void cleanupSocketLib();
int convertSocketToFd(SOCKET sock, int flags);
SOCKET createSocket(int af, int type, int protocol);
int setSocketBlocking(SOCKET sock, int blocking);
SOCKET connectTcpSocket(const char* host, const char* port);
// set IP to NULL to bind to all interfaces
SOCKET createTcpServer(const char* ip, const char* port);
FILE* bufferOutSocketToCStream(SOCKET sock);
FILE* bufferInSocketToCStream(SOCKET sock);
int getMacAddressFromIPv4(const char* ip, unsigned char mac_out[6]);

//void skipToEnd(FILE* file);

#ifdef __cplusplus
}
#endif

#endif /* __SOCKET_H_ */