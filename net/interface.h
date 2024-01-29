#ifndef __INTERFACE_H_
#define __INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "socket.h"

#include <unistd.h> // geteuid()
#ifdef _WIN32

#include <windows.h>
#include <iphlpapi.h> // SendARP()
//#include <inaddr.h> // struct in_addr

#else

#endif /* _WIN32 */

#define IF_METHOD_WIN32 0
#define IF_METHOD_IOCTL 1
#define IF_METHOD_NETLINK 2

#ifdef _WIN32
#define IF_METHOD IF_METHOD_WIN32
#else
#define IF_METHOD IF_METHOD_IOCTL
#endif /* _WIN32 */

#if (IF_METHOD == IF_METHOD_IOCTL)
#include <sys/ioctl.h>
#include <net/if.h>

// workaround for glibc 2.1 bug
#ifndef ifr_newname
#define ifr_newname ifr_ifru.ifru_slave
#endif /* ifr_newname */

#endif

int isAdminOrRoot();
int listInterfaces(char*** ifnames);
int setInterfaceIPAddress(const char* ifname, struct sockaddr* addr);
int delInterfaceIPAddress(const char* ifname, struct sockaddr* addr);
int checkIpPresentOnInterfaceViaArpProbe(const char* ifname, struct sockaddr* addr);



#ifdef __cplusplus
}
#endif

#endif /* __INTERFACE_H_ */