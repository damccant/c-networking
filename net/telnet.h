#ifndef __TELNET_H_
#define __TELNET_H_

#define DEFAULT_TELNET_PORT "23"
#define __TELNET_BUFFER_SIZE__ 8192

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>

#include "socket.h"
#include "../util.h"

struct TelnetClient
{
	char* host;
	char* port;
	char* user;
	char* pass;
	int connected;
	int loggedIn;
	SOCKET sock;
	/*size_t __buf_sz__;
	char *__buf_edge__;
	char *__buf__;
	char *__pos__;*/
};

void TelnetClient_init(struct TelnetClient* cli);
void TelnetClient_reset(struct TelnetClient* cli);
int TelnetClient_connect(struct TelnetClient* cli, const char* host, const char* port);
int TelnetClient_reconnect(struct TelnetClient* cli);
int TelnetClient_login(struct TelnetClient* cli, const char* user, const char* pass);

struct Telnet_cmd_msg
{
	ssize_t size;
	char* msg;
};

struct Telnet_cmd_msg TelnetClient_run(struct TelnetClient* cli, const char* format, ...);

#ifdef __cplusplus
}
#endif

#endif /* __TELNET_H_ */