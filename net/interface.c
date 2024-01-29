#include "interface.h"

// all this stuff is pretty OS-specific


#ifdef _WIN32

int isAdminOrRoot()
{

}

#else /* not Windows */

int isAdminOrRoot()
{
	return geteuid() == 0;
}

#endif /* _WIN32 */

int sendArpProbe(SOCKET sock, char my_mac[6], uint32_t src_ip, uint32_t dst_ip, char enemy_mac[6])
{
#ifdef _WIN32
	long unsigned int enemy_mac_len = 6;
	int ret;
	ret = SendARP(dst_ip, src_ip, (long unsigned int*)enemy_mac, &enemy_mac_len);
	switch(ret)
	{
		case NO_ERROR:
			return 1;
		case ERROR_BAD_NET_NAME:	// Windows Vista and later
		case ERROR_GEN_FAILURE:		// Windows Server 2003 and earlier
			perror("SendARP()");
			return 0;
		case ERROR_BUFFER_OVERFLOW:
		case ERROR_INVALID_PARAMETER:
		case ERROR_INVALID_USER_BUFFER:
		case ERROR_NOT_FOUND:
		case ERROR_NOT_SUPPORTED:
		default:
			perror("SendARP()");
			return -1;
	}
#else
	// TODO
#endif
}

//#ifndef IP_HDRINCL
//#define IP_HDRINCL
//#endif /* IP_HDRINCL */

int checkIpPresentOnInterfaceViaArpProbe(const char* ifname, struct sockaddr* addr)
{
	SOCKET sock = createSocket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock == INVALID_SOCKET)
	{
		perror("socket()");
		return -1;
	}
	int one = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&one, sizeof(one)))
	{
		perror("setsockopt(SO_BROADCAST)");
		closesocket(sock);
		return -1;
	}
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one)))
	{
		perror("setsockopt(SOL_REUSEADDR)");
		closesocket(sock);
		return -1;
	}
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&one, sizeof(one)))
	{
		perror("setsockopt(IP_HDRINCL)");
		closesocket(sock);
		return -1;
	}
	/*if(setsockopt(sock, SOL_SOCKET, SOL_DONTROUTE, (char*)&one, sizeof(one)))
	{
		perror("setsockopt(SOL_DONTROUTE)");
		closesocket(sock);
		return -1;
	}*/
	char msg[] = {"hello, world!"};
	int bytes = sendto(sock, msg, sizeof(msg), 0, NULL, 0);
	if(bytes < 0)
	{
		perror("sendto()");
		printf("sendto() returned code %d!\n", bytes);
		//printf("sendto() returned code %d! WSAGetLastError() = %d\n", bytes, WSAGetLastError());
	}
}

#if IF_METHOD == IF_METHOD_WIN32

char* copyWCStoNewMBS(const wchar_t* wStr)
{
	if(wStr == NULL)
		return NULL;
	/*
	 * this is ugly, but for the most part, works as long as the string is not
	 * mostly unicode. 1 or 2 emojis are ok, but if most of the string is
	 * emojis, then this probably is not enough memory
	 */
	// TODO: improve this
	size_t mbs_len = wcslen(wStr) * sizeof(wchar_t);
	char* ret = (char*)malloc(mbs_len);
	wcstombs(ret, wStr, mbs_len);
	return ret;
}

wchar_t* copyMBStoNewWCS(const char* str)
{
	if(str == NULL)
		return NULL;
	/*
	 * blah blah blah this is super ugly and probably doesnt even work
	 */
	// TODO: improve this
	size_t wcs_len = strlen(str) * sizeof(wchar_t);
	wchar_t* ret = (wchar_t*)malloc(wcs_len);
	mbstowcs(ret, str, wcs_len);
	return ret;
}

/*char* getInterfaceFriendlyName(const char* interfaceRaw)
{
	wchar_t *name = copyMBStoNewWCS(interfaceRaw);
	unsigned long ifindex;
	GetAdapterIndex(name, &ifindex);
	free(name);
	NET_LUID ifluid;
	ConvertInterfaceIndexToLuid(ifindex, &ifluid);
	wchar_t alias[NDIS_IF_MAX_STRING_SIZE + 1];
	ConvertInterfaceLuidToAlias(&ifluid, alias, sizeof(alias));
	return copyWCStoNewMBS(alias);
}*/


int listInterfaces(char *** ifnames)
{
	unsigned long int pIfTableLen = 30 * sizeof(IP_INTERFACE_INFO);
	IP_INTERFACE_INFO *pIfTable = (IP_INTERFACE_INFO*)malloc(pIfTableLen);
	int ret;

	GetInterfaceInfoArea:
	ret = GetInterfaceInfo(pIfTable, &pIfTableLen);
	switch(ret)
	{
		case NO_ERROR:
			break;
		case ERROR_INSUFFICIENT_BUFFER:
			pIfTableLen += sizeof(IP_INTERFACE_INFO);
			pIfTable = (IP_INTERFACE_INFO*)realloc(pIfTable, pIfTableLen);
			goto GetInterfaceInfoArea;
		case ERROR_INVALID_PARAMETER:
		case ERROR_NOT_SUPPORTED:
			free(pIfTable);
			return -1;
		case ERROR_NO_DATA:		// there are no network interfaces!
			free(pIfTable);
			return 0;
	}
	if(ifnames != NULL)
	{
		*ifnames = (char**)malloc(sizeof(char*) * pIfTable->NumAdapters);
		for(unsigned long int i = 0; i < pIfTable->NumAdapters; ++i)
		{
			// sure, Windows wide char -> multibyte char auto conversion
			// "works" and is totally not "a massive source of frustration"
			// within the Win32 API >:(
			(*ifnames)[i] = copyWCStoNewMBS(pIfTable->Adapter[i].Name);
		}
	}
	ret = (int)pIfTable->NumAdapters;
	free(pIfTable);
	return ret;
}

#elif IF_METHOD == IF_METHOD_IOCTL

struct ifconf* getIfConf()
{
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(sock < 0)
	{
		perror("socket()");
		return NULL;
	}
	size_t ifc_buf_len = 30 * sizeof(struct ifreq);
	char *the_ifc_buf = (char*)malloc(ifc_buf_len);
	struct ifconf *conf = (struct ifconf*)malloc(sizeof(struct ifconf));
	conf->ifc_len = ifc_buf_len;
	conf->ifc_buf = the_ifc_buf;
	while(1)
	{
		if(ioctl(sock, SIOCGIFCONF, conf) < 0)
		{
			perror("ioctl()");
			return NULL;
		}
		if(conf->ifc_len < ifc_buf_len)
			break;
		ifc_buf_len += sizeof(struct ifreq);
		the_ifc_buf = (char*)realloc(the_ifc_buf, ifc_buf_len);
		conf->ifc_len = ifc_buf_len;
		conf->ifc_buf = the_ifc_buf;
	}
	close(sock);
	return conf;
}

void delIfConf(struct ifconf* conf)
{
	free(conf->ifc_buf);
	free(conf);
}

int listInterfaces(char*** ifnames)
{
	struct ifconf *conf = getIfConf();
	if(conf == NULL)
		return -1;
	struct ifreq *ifr;
	ifr = conf->ifc_req;
	size_t count = 0;
	for(ifr = conf->ifc_req; (char*)ifr < (conf->ifc_buf + conf->ifc_len); ++ifr)
	{
		if(ifnames != NULL)
		{
			if(count == 0)
				*ifnames = (char**)malloc(sizeof(char*));
			else
				*ifnames = (char**)realloc(*ifnames, sizeof(char*) * (count + 1));
			(*ifnames)[count] = strdup(ifr->ifr_name);
		}
		count++;
	}
	delIfConf(conf);
	return (int)(count);
}

#elif IF_METHOD == IF_METHOD_NETLINK

int openNetlinkSocket()
{
	int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if(sock < 0)
		return sock;
	//setsockopt(sock, SOL_SOCKET, SO_)
	// TODO
	return sock;
}

#error Sorry, netlink is not yet finished, please use IF_METHOD_IOCTL

#else

#error Must define a method to setup interfaces!

#endif /* IF_METHOD */