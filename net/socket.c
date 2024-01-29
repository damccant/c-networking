#include "socket.h"

#ifdef _WIN32


int __Winsock2_is_init = 0;
int initializeSocketLib()
{
	if(!__Winsock2_is_init)
	{
		WSADATA wsaData;
		return WSAStartup(MAKEWORD(2,2), &wsaData);
	}
}

void cleanupSocketLib()
{
	WSACleanup();
}

int convertSocketToFd(SOCKET sock, int flags) // O_RDWR | O_BINARY
{
	return _open_osfhandle(sock, flags);
}

SOCKET createSocket(int af, int type, int protocol)
{
	return WSASocket(af, type, protocol, NULL, 0, 0);
}

int setSocketBlocking(SOCKET sock, int blocking)
{
	if(sock == INVALID_SOCKET)
		return 1;
	unsigned long mode = blocking ? 0 : 1;
	return ioctlsocket(sock, FIONBIO, &mode);
}

int my_inet_pton(int af, const char *restrict src, void *restrict dst)
{
	struct sockaddr_storage ss;
	int size = sizeof(ss);
	char src_copy[INET6_ADDRSTRLEN + 1];

	memset(&ss, 0, sizeof(ss));
	strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
	src_copy[INET6_ADDRSTRLEN] = 0;
	if(WSAStringToAddress(src_copy, af, NULL, (struct sockaddr*)&ss, &size) == 0)
	{
		switch(af)
		{
		case AF_INET:
			*(struct in_addr*)dst = ((struct sockaddr_in*)&ss)->sin_addr;
			return 1;
		case AF_INET6:
			*(struct in6_addr*)dst = ((struct sockaddr_in6*)&ss)->sin6_addr;
			return 1;
		}
	}
	return 0;
}

const char *my_inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size)
{
	DWORD buf_size = (DWORD)size;
	struct sockaddr_storage src_hack;
	src_hack.ss_family = af;
	if(af == AF_INET)
	{
		struct sockaddr_in *the_sock = (struct sockaddr_in*)&src_hack;
		the_sock->sin_port = htons(0);
		memcpy(&(the_sock->sin_addr), src, sizeof(struct in_addr));
	}
	else if(af == AF_INET6)
	{
		struct sockaddr_in6 *the_sock = (struct sockaddr_in6*)&src_hack;
		the_sock->sin6_port = htons(0);
		memcpy(&(the_sock->sin6_addr), src, sizeof(struct in_addr));
	}

	if(WSAAddressToString((struct sockaddr*)&src_hack, sizeof(struct sockaddr_storage), NULL, dst, &buf_size))
	{
		fprintf(stderr, "WSAAddressToString() failed with code %d\n", WSAGetLastError());
		return NULL;
	}
	return dst;
}

int getMacAddressFromIPv4(const char* ip, unsigned char mac_out[6])
{
	struct sockaddr_in addr;
	if(my_inet_pton(AF_INET, ip, (void*)&addr) != 1)
	{
		fprintf(stderr, "inet_pton() failed!\n");
		return 1;
	}
	IPAddr theIp;
	theIp = addr.sin_addr.s_addr;
	unsigned long int mac_long[2];
	long unsigned int mac_len = sizeof(mac_long);
	int i;
	if((i = SendARP(theIp, INADDR_ANY, mac_long, &mac_len)) != NO_ERROR)
	{
		printf("theIp = %08x, %d.%d.%d.%d\n", theIp, (theIp & 0xff000000) >> 24, (theIp & 0x00ff0000) >> 16, (theIp & 0x0000ff00) >> 8, theIp & 0x000000ff);
		perror("SendARP()");
		fprintf(stderr, "SendARP() failed with return code %d\n", i);
		return 1;
	}
	memcpy(mac_out, mac_long, mac_len);
	return 0;
}

#else

int initializeSocketLib()
{
	return 0;
}

void cleanupSocketLib() {}

#ifndef O_BINARY
#define O_BINARY 0
#endif /*O_BINARY*/

int convertSocketToFd(SOCKET sock, int flags)
{
	return sock; // in BSD, a socket IS a file descriptor
}

SOCKET createSocket(int af, int type, int protocol)
{
	return socket(af, type, protocol);
}

int setSocketBlocking(SOCKET sock, int blocking)
{
	if(sock < 0)
		return 1;
	int flags = fcntl(sock, F_GETFL, 0);
	if(flags == -1)
		return 1;
	flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
	return fcntl(sock, F_SETFL, flags);
}

int getMacAddressFromIPv4(const char* ip, unsigned char mac_out[6])
{
	fprintf(stderr, "getMacAddressFromIPv4(): not implemented on this platform, sorry\n");
	return 1;
}

#endif /* _WIN32 */

// generic implementation
SOCKET connectTcpSocket(const char* host, const char* port)
{
	struct addrinfo hints, *result = NULL, *ptr = NULL;
	SOCKET sock;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	int rc = getaddrinfo(host, port, &hints, &result);
	if(rc)
	{
		perror("getaddrinfo()");
		fprintf(stderr, "getaddrinfo() failed with return %d\n", rc);
		return INVALID_SOCKET;
	}

	// try every IP in the DNS lookup
	for(ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		sock = createSocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if(sock == INVALID_SOCKET)
		{
			fprintf(stderr, "socket() failed\n");
			return INVALID_SOCKET;
		}

		if(connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR)
		{
			closesocket(sock);
			sock = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	return sock;
}

// set IP to NULL to bind to all interfaces
SOCKET createTcpServer(const char* ip, const char* port)
{
	struct addrinfo hints, *result = NULL, *ptr = NULL;
	SOCKET sock;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	int rc = getaddrinfo(ip, port, &hints, &result);
	if(rc)
	{
		perror("getaddrinfo()");
		fprintf(stderr, "getaddrinfo() failed with return %d\n", rc);
		return INVALID_SOCKET;
	}

	for(ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		sock = createSocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if(sock == INVALID_SOCKET)
		{
			fprintf(stderr, "socket() failed\n");
			return INVALID_SOCKET;
		}
		if(bind(sock, ptr->ai_addr, ptr->ai_addrlen))
		{
			perror("bind()");
			closesocket(sock);
			sock = INVALID_SOCKET;
			continue;
		}
		break;
	}
	if(sock == INVALID_SOCKET)
		return 1;
	if(listen(sock, 128))
	{
		perror("listen()");
		fprintf(stderr, "listen() failed\n");
		closesocket(sock);
		return INVALID_SOCKET;
	}
	return sock;
}


/*char *get_ip_str(const struct sockaddr *sa, char * restrict s, size_t maxlen)
{
	switch(sa->sa_family)
	{
		case AF_INET:
			inet_ntop(sa->sa_family, &(((struct sockaddr_in*)sa)->sin_addr), s, maxlen);
			break;
		case AF_INET6:
			inet_ntop(sa->sa_family, &(((struct sockaddr_in6*)sa)->sin6_addr), s, maxlen);
			break;
		default:
			strncpy(s, "Unknown socket family", maxlen);
			return NULL;
	}
	return s;
}*/

FILE* bufferOutSocketToCStream(SOCKET sock)
{
	if(sock == INVALID_SOCKET)
		return NULL;
	int sockFd = convertSocketToFd(sock, O_RDWR | O_BINARY);
	if(sockFd < 0)
	{
		perror("_open_osfhandle()");
		return NULL;
	}
	FILE* file = fdopen(sockFd, "ab+");
	if(file == NULL)
		perror("fdopen()");
	return file;
}

FILE* bufferInSocketToCStream(SOCKET sock)
{
	if(sock == INVALID_SOCKET)
		return NULL;
	int sockFd = convertSocketToFd(sock, O_RDWR | O_BINARY);
	if(sockFd < 0)
	{
		perror("_open_osfhandle()");
		return NULL;
	}
	FILE* file = fdopen(sockFd, "rb+");
	if(file == NULL)
		perror("fdopen()");
	return file;
}