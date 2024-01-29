#include "ftp.h"

void FTPClient_init(struct FTPClient* cli)
{
	cli->host = NULL;
	cli->port = NULL;
	cli->user = NULL;
	cli->pass = NULL;
	cli->loggedIn = 0;
	cli->streaming = 0;
	cli->pasv = 1;
	//cli->cmd = NULL;
	cli->cmdin = cli->cmdout = NULL;
	cli->__cntlSock__ = INVALID_SOCKET;
	cli->dataSock = INVALID_SOCKET;
	cli->__buf__ = NULL;
	cli->__pasv_failed__ = 0;
}

void FTPClient_reset(struct FTPClient* cli)
{
	if(cli->dataSock != INVALID_SOCKET)
		closesocket(cli->dataSock);
	if(cli->cmdin != NULL)
		fclose(cli->cmdin);
	//if(cli->cmdout != NULL)
	//	fclose(cli->cmdout);
	if(cli->host != NULL)
		free(cli->host);
	if(cli->port != NULL)
		free(cli->port);
	if(cli->user != NULL)
		free(cli->user);
	if(cli->pass != NULL)
		free(cli->pass);
	if(cli->__buf__ != NULL)
		free(cli->__buf__);
	FTPClient_init(cli);
}

void FTPClient_quit(struct FTPClient *cli)
{
	if(cli->cmdout != NULL)
	{
		fprintf(cli->cmdout, "QUIT\r\n");
		fflush(cli->cmdout);
		fclose(cli->cmdout);
	}
	FTPClient_reset(cli);
}

int FTPClient_connect(struct FTPClient* cli, const char* host, const char* port)
{
	if(cli->cmdin != NULL || cli->cmdout != NULL)
		return 0;
	cli->__cntlSock__ = connectTcpSocket(host, port);
	cli->loggedIn = 0;
	if(cli->__cntlSock__ != INVALID_SOCKET)
	{
		//FILE* stream = bufferSocketToCStream(cli->__cntlSock__);
		cli->cmdin = bufferInSocketToCStream(cli->__cntlSock__);
		cli->cmdout = bufferOutSocketToCStream(cli->__cntlSock__);
		//cli->cmd = stream;
		if(cli->cmdin == NULL || cli->cmdout == NULL)
		//if(cli->cmd == NULL)
		{
			closesocket(cli->__cntlSock__);
			return 1;
		}
		cli->__buf__ = (char*)malloc(sizeof(char) * __FTP_BUFFER_SIZE__);
		cli->host = strdup(host);
		cli->port = strdup(port);
		return 0;
	}
	return 1;
}

struct FTP_cmd_msg __to_FTP_cmd_msg__(long int code, char* msg)
{
	struct FTP_cmd_msg ftp;
	ftp.code = code;
	ftp.msg = msg;
	return ftp;
}

struct FTP_cmd_msg __FTPClient_readline__(struct FTPClient* cli)
{
	if(cli->__buf__ == NULL)
		cli->__buf__ = (char*)malloc(sizeof(char) * __FTP_BUFFER_SIZE__);
	if(fgets(cli->__buf__, __FTP_BUFFER_SIZE__, cli->cmdin) == NULL)
	{
		perror("fgets()");
		return __to_FTP_cmd_msg__(-1, NULL);
	}
	//printf("[debug] read line \"%s\"\n", cli->__buf__);
	struct FTP_cmd_msg msg;
	msg.msg = cli->__buf__;
	msg.code = strtol(cli->__buf__, &(msg.msg), 10);
	return msg;
}

struct FTP_cmd_msg FTPClient_run(struct FTPClient* cli, const char* format, ...)
{
	//fseek(cli->cmd, 0, SEEK_END);

	va_list args;//, args2;
	va_start(args, format);
	//va_copy(args2, args);
	int ret = vfprintf(cli->cmdout, format, args);
	if(ret < 0)
		perror("vfprintf()");
	va_end(args);
	/*
	if(ret < 0)
	{
		printf("disconnected, attempting autoreconnect...\n");
		if(FTPClient_reconnect(cli))
			return __to_FTP_cmd_msg__(-1, NULL);
		va_start(args2, format);
		vfprintf(cli->cmdout, format, args2);
		va_end(args2);
	}*/
	fflush(cli->cmdout);
	return __FTPClient_readline__(cli);
}

int FTPClient_login(struct FTPClient* cli, const char* user, const char* pass)
{
	if(FTPClient_prepare_login(cli))
	{
		fprintf(stderr, "Failed to prepare login!\n");
		return 1;
	}
	if(FTPClient_retry_login(cli, user, pass))
	{
		fprintf(stderr, "Failed to send credentials\n");
		return 1;
	}
	return 0;
	//return FTPClient_prepare_login(cli) || FTPClient_retry_login(cli, user, pass);
}

int FTPClient_prepare_login(struct FTPClient* cli)
{
	if(cli->cmdout == NULL || cli->cmdin == NULL)
	{
		if(cli->cmdout == NULL)
			fprintf(stderr, "cli->cmdout == NULL\n");
		if(cli->cmdin == NULL)
			fprintf(stderr, "cli->cmdin == NULL\n");
		return 1;
	}
	if(cli->loggedIn)
	{
		fprintf(stderr, "Already logged in!\n");
		return 0;
	}

	//fgetc(cli->cmdin);

	char *dummy = (char*)malloc(8192);
	recv(cli->__cntlSock__, dummy, 8192, 0);
	free(dummy);
	return 0;
	//fseek(cli->cmdin, 0, SEEK_END); // get the server banner and discard it
}

int FTPClient_retry_login(struct FTPClient *cli, const char *user, const char *pass)
{
	struct FTP_cmd_msg msg;

	msg = FTPClient_run(cli, "USER %s\r\n", user);
	if(msg.code == 230) // password not required
	{
		cli->loggedIn = 1;
		cli->user = strdup(user);
		cli->pass = strdup("");
		return 0;
	}
	if(msg.code != 331)
	{
		fprintf(stderr, "USER failed with code %lu%s\n", msg.code, msg.msg);
		return 1;
	}
	msg = FTPClient_run(cli, "PASS %s\r\n", pass);
	if(msg.code != 230)
	{
		//fprintf(stderr, "Login failed! (%lu%s)\n", msg.code, msg.msg);
		return 1;
	}
	cli->loggedIn = 1;
	cli->user = strdup(user);
	cli->pass = strdup(pass);
	return 0;
}

int FTPClient_reconnect(struct FTPClient* cli)
{
	fclose(cli->cmdin);
	cli->cmdin = NULL;
	cli->cmdout = NULL;
	if(FTPClient_connect(cli, cli->host, cli->port))
	{
		fprintf(stderr, "failed to reconnect \"%s\" on port %s!!\n", cli->host, cli->port);
		return 1;
	}
	if(FTPClient_login(cli, cli->user, cli->pass))
	{
		fprintf(stderr, "failed to login as \"%s\" on reconnect!\n", cli->user);
		return 1;
	}
	return 0;
}

static int __FTPClient_parsePASVret__(const struct FTP_cmd_msg msg, struct sockaddr_in* addr)
{
	//printf("here 1\n");
	if(msg.code != 227 || msg.msg == NULL)
	{
		addr->sin_addr.s_addr = 0;
		return 1;
	}
	//printf("here 2\n");
	char *tmp = strrchr(msg.msg, '(');
	if(tmp == NULL)
	{
		addr->sin_addr.s_addr = 0;
		return 1;
	}
	tmp++;
	//printf("here 3\n");
	unsigned int port_setting[6];
	for(int i = 0; i < sizeof(port_setting) / sizeof(port_setting[0]); ++i)
	{
		if(*tmp >= '0' && *tmp <= '9')
			port_setting[i] = strtol(tmp, &tmp, 10);
		tmp++;
		//printf("port_setting[%d] = %d\n", i, port_setting[i]);
	}
	//printf("parsing %s\n", msg.msg);
	addr->sin_addr.s_addr = htonl(
							((unsigned long)port_setting[0]) << 24 |
							((unsigned long)port_setting[1]) << 16 |
							((unsigned long)port_setting[2]) << 8 |
							((unsigned long)port_setting[3]));
	addr->sin_port = (((unsigned int)port_setting[5]) << 8) | port_setting[4];
	//printf("ip address (binary) is 0x%08x and port is %d\n", addr->sin_addr.s_addr, ntohs(addr->sin_port));
	return 0;
	//const size_t remote_str_ip_len = INET_ADDRSTRLEN;
	//*ip = malloc(remote_str_port_len);
	//snprintf(ip, remote_str_ip_len, "%d.%d.%d.%d", port_setting[1], port_setting[2], port_setting[3], port_setting[4]);
}

// This function is only ever used in one place
static int __FTPClient_connectPASV__(struct FTPClient* cli, short sin_family)
{
	//printf("in __FTPClient_connectPASV__()\n");
	struct sockaddr_storage remote_addr;
	socklen_t remotelen = sizeof(remote_addr);
	getpeername(cli->__cntlSock__, (struct sockaddr*)&remote_addr, &remotelen);

	struct FTP_cmd_msg msg;

	if(sin_family == AF_INET)
	{
		msg = FTPClient_run(cli, "PASV\r\n");

		if(msg.code < 0 || msg.code == 421)
		{
			fprintf(stderr, "seems like the server has booted us off, reconnecting...\n");
			FTPClient_reconnect(cli);
			FTPClient_run(cli, "TYPE I\r\n");
			msg = FTPClient_run(cli, "PASV\r\n");
		}
		//printf("PASV command completed with code %d%s\n", msg.code, msg.msg);
		if(__FTPClient_parsePASVret__(msg, (struct sockaddr_in*)&remote_addr))
		{
			fprintf(stderr, "Failed to parse PASV reply from server: %lu%s\n", msg.code, msg.msg);
			cli->pasv = 0;
			cli->__pasv_failed__ = 1;
			return 1;
		}
	}
	else
	{
		msg = FTPClient_run(cli, "EPSV\r\n");
		// TODO this stuff
		if(msg.code != 227)
		{
			cli->pasv = 0;
			cli->__pasv_failed__ = 1;
			return 1;
		}
		else
		{
			// TODO
		}
	}
	cli->dataSock = createSocket(sin_family, SOCK_STREAM, IPPROTO_TCP);
	if(cli->dataSock == INVALID_SOCKET)
	{
		fprintf(stderr, "createSocket() failed!\n");
		// There is no way to recover from this so give up here
		return 1;
	}
	int ret;
	if((ret = connect(cli->dataSock, (struct sockaddr*)&remote_addr, remotelen)) == SOCKET_ERROR)
	{
		perror("connect()");
		fprintf(stderr, "connect failed!\n");
		cli->__pasv_failed__ = 1;
		return 1;
	}
	//printf("successfully opened passive mode connection\n");
	cli->pasv = 1;
	cli->__pasv_failed__ = 0;
	return 0;
}

SOCKET __FTPClient_vOpenDataConnection__(struct FTPClient* cli, const char* format, va_list arg)
{
	//printf("opening data connection... "); fflush(stdout);
	printf("[%s] opening data connection in \"%s\" mode\n", cli->host, cli->pasv ? "PASV" : "PORT");
	//___printStackTrace___(stderr, "\tin %s\n");
	if(!cli->loggedIn)
		return INVALID_SOCKET;
	if(cli->streaming)
		return INVALID_SOCKET;
	struct FTP_cmd_msg msg;
	SOCKET server;

	try_again:
	msg = FTPClient_run(cli, "TYPE I\r\n");
	if(msg.code != 200)
		fprintf(stderr, "TYPE I failed with code %lu%s\n", msg.code, msg.msg);

	
	struct sockaddr_storage local_addr;
	socklen_t addrlen = sizeof(local_addr);
	if(getsockname(cli->__cntlSock__, (struct sockaddr*)&local_addr, &addrlen))
	{
		perror("getsockname()");
		return INVALID_SOCKET;
	}
	int ipv4 = local_addr.ss_family == AF_INET;

	if(cli->pasv)
		if(__FTPClient_connectPASV__(cli, local_addr.ss_family))
			if(!cli->__pasv_failed__)
				if(__FTPClient_connectPASV__(cli, local_addr.ss_family)) // try again
					cli->pasv = 0; // ok, PASV really is not working, try PORT

	if(!cli->pasv)
	{
		server = createSocket(local_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if(server == INVALID_SOCKET)
		{
			fprintf(stderr, "createSocket() failed!\n");
			// There is no way to recover from this so don't even try
			return INVALID_SOCKET;
		}

		if(ipv4)
			((struct sockaddr_in*)&local_addr)->sin_port = htons(0); // probably bad :(
		else
			((struct sockaddr_in6*)&local_addr)->sin6_port = htons(0); // probably bad :(

		if(bind(server, (struct sockaddr*)&local_addr, addrlen))
		{
			perror("bind()");
			fprintf(stderr, "bind() failed!\n");
			cli->pasv = 1;
			closesocket(server);
			return INVALID_SOCKET;
		}

		if(getsockname(server, (struct sockaddr*)&local_addr, &addrlen))
		{
			perror("getsockname()");
			// There is no way to recover from this
			closesocket(server);
			return INVALID_SOCKET;
		}
		//server = createTcpServer(ip_address, "0");

		if(listen(server, 1))
		{
			perror("listen()");
			fprintf(stderr, "listen() failed!\n");
			// maybe the firewall is blocking us? so try pasv
			cli->pasv = 1;
			closesocket(server);
			return INVALID_SOCKET;
		}

		const size_t local_str_ip_len = INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
		char local_str_ip[local_str_ip_len];
		const void* in_addr = ipv4 ? (const void*)(&((struct sockaddr_in*)&local_addr)->sin_addr) :
					(const void*)(&((struct sockaddr_in6*)&local_addr)->sin6_addr);

		if(my_inet_ntop(local_addr.ss_family, in_addr, local_str_ip, local_str_ip_len) == NULL)
		{
			perror("inet_ntop()");
			closesocket(server);
			return INVALID_SOCKET;
		}

		// TODO: get local address and send to server via below command
		if(ipv4)
		{
			for(int i = 0; i < local_str_ip_len; i++)
			{
				if(local_str_ip[i] == '\0')
					break;
				else if(local_str_ip[i] == '.')
					local_str_ip[i] = ',';
			}
			//printf("local_str_ip = \"%s\"\n", local_str_ip);
			unsigned short the_port = ntohs(((struct sockaddr_in*)&local_addr)->sin_port);
			//printf("local_port = %d (%d,%d)\n", the_port, (the_port >> 8) & 0xff, (the_port & 0xff));
			msg = FTPClient_run(cli, "PORT %s,%d,%d\r\n", local_str_ip, (the_port >> 8) & 0xff, (the_port & 0xff));
		}
		else
			msg = FTPClient_run(cli, "EPRT |2|%s|%d|\r\n", local_str_ip, ntohs(((struct sockaddr_in*)&local_addr)->sin_port));
		if(msg.code != 200)
		{
			cli->pasv = 1;
			closesocket(server);
			return INVALID_SOCKET;
		}
	}

	//fseek(cli->cmd, 0, SEEK_END);

	/*va_list args;
	va_start(args, format);
	vfprintf(cli->cmd, format, args);
	va_end(args);*/
	vfprintf(cli->cmdout, format, arg);
	fflush(cli->cmdout);

	if(!cli->pasv)
	{
		struct sockaddr client_addr;
		socklen_t addrlen;
		cli->dataSock = accept(server, &client_addr, &addrlen);
		if(cli->dataSock < 0)
		{
			perror("accept()");
			cli->dataSock = INVALID_SOCKET;
		}
		closesocket(server);
	}
	msg = __FTPClient_readline__(cli);
	if(!(msg.code == 125 || msg.code == 150))
	{
		printf("Data connection failed with code %lu%s\n", msg.code, msg.msg);
		if(msg.code == 421) // no transfer time exceeded
			goto try_again;
		return INVALID_SOCKET;
	}
	cli->streaming = 1;
	//else
	//	printf("data connection succeeded with code %lu\n", msg.code);
	return cli->dataSock;
}

SOCKET __FTPClient_openDataConnection__(struct FTPClient* cli, const char* format, ...)
{
	SOCKET sock;
	va_list args;
	va_start(args, format);
	sock = __FTPClient_vOpenDataConnection__(cli, format, args);
	va_end(args);
	return sock;
}

int __read_string_len__(int fd, char** string, ssize_t i)
{
	//printf("reading string of length %d... ", i); fflush(stdout);
	if(*string == NULL)
	{
		//printf("allocating room... "); fflush(stdout);
		*string = (char*)malloc(sizeof(char) * (i + 1));
	}
	else
		fprintf(stderr, "in __read_string_len__(), passed arg is not NULL (it should be!)\n");
	if(read_fully(fd, *string, i) != i)
		return 1;
	//printf("adding null terminator... "); fflush(stdout);
	(*string)[i] = 0;
	//printf("added... "); fflush(stdout);
	return 0;
}

int read_string(int fd, char** string)
{
	uint8_t i;
	ssize_t this_read = read(fd, &i, sizeof(i));
	if(this_read != sizeof(i))
		return 1;
	return __read_string_len__(fd, string, i);
}

int read_long_string(int fd, char** string)
{
	uint16_t i;
	ssize_t this_read = read_fully(fd, &i, sizeof(i));
	if(this_read != sizeof(i))
		return 1;
	return __read_string_len__(fd, string, i);
}

void write_string(int fd, char* string)
{
	uint8_t i;
	if(string != NULL)
	{
		i = strlen(string);
		write(fd, &i, sizeof(i));
		write(fd, string, i);
	}
	else
	{
		i = 0;
		write(fd, &i, sizeof(i));
	}
}

void write_long_string(int fd, char* string)
{
	uint16_t i;
	if(string != NULL)
	{
		i = strlen(string);
		write(fd, &i, sizeof(i));
		write(fd, string, i);
	}
	else
	{
		i = 0;
		write(fd, &i, sizeof(i));
	}
}

void serialize_FTP_File(struct FTP_File* file, int fd)
{
	printf("called serialize_FTP_File() with file descriptor %d\n", fd);
	if(file == NULL)
	{
		char zero = 0;
		write(fd, &zero, 1);
		return;
	}
	printf("saving \"%s\"\n", file->fullpath);
	unsigned char i = file->valid;
	printf("writing fd for the first time...\n");
	write(fd, &i, 1);
	if(i)
	{
		printf("file is valid...\n");

		//unsigned long magic = htonl(0xdeadbeef);
		//write(fd, &magic, sizeof(magic));

		write(fd, &file->type, 1);
		write(fd, file->permissions, sizeof(file->permissions));
		write(fd, &file->link_count, sizeof(file->link_count));
		write_string(fd, file->owner);
		write_string(fd, file->group);
		write(fd, &file->size, sizeof(file->size));
		write(fd, &file->date, sizeof(file->date));
		write_long_string(fd, file->fullpath);
		// ignore name
		write(fd, &file->child_count, sizeof(file->child_count));
		printf("saving %lu children\n", file->child_count);
		for(ssize_t children = 0; children < file->child_count; children++)
			serialize_FTP_File(&file->child[children], fd);
	}
	printf("serializing \"%s\" successful\n", file->fullpath);
}

struct FTP_File* deserialize_FTP_File(struct FTP_File* file, int fd)
{
	unsigned char valid;
	ssize_t this_read;



	valid = 0;
	this_read = read(fd, &valid, 1);
	//printf("valid = %d and this_read = %lu\n", valid, this_read);
	if(this_read == 0 || !(valid & 0x01))
	{
		printf("this_read (%lu) == 0 or not valid\n", this_read);
		if(file != NULL)
			file->valid = 0;
		exit(1);
		return NULL;
	}
	//else
	//	printf("continuing....\n");

	/*unsigned long magic;
	read(fd, &magic, sizeof(magic));
	magic = ntohl(magic);
	if(magic != 0xdeadbeef)
	{
		printf("magic is invalid! (expected %08x, got %08x)\n", 0xdeadbeef, magic);
		exit(1);
	}*/
	//else
	//	printf("magic is valid :)\n");

	if(file == NULL)
		file = (struct FTP_File*)malloc(sizeof(struct FTP_File));
	//printf("clearing struct for new info\n");
	memset(file, 0, sizeof(struct FTP_File));
	//printf("setting file->valid\n");
	file->valid = 0; // this will be changed to 1 once we load everything else in
	//printf("ready to read...\n");
	this_read = read(fd, &file->type, 1);
	//printf("read %d bytes (type is now %c)\n", this_read, file->type);
	if(this_read == 0)
		return file;
	//printf("about to use read_fully()\n");
	//if(file->permissions == NULL) printf("file->permissions is NULL!\n");
	this_read = read_fully(fd, &file->permissions, sizeof(file->permissions));
	//printf("read %d bytes for permissions (", this_read);
	//fwrite(file->permissions, sizeof(char), sizeof(file->permissions), stdout);
	//printf(")\n"); fflush(stdout);
	if(this_read != sizeof(file->permissions))
	{
		printf("unexpected EOF!\n");
		printf("when reading permissions, read %zu bytes and file->permissions is %zu bytes\n", this_read, sizeof(file->permissions));
		return file;
	}
	//printf("reading link_count...\n");
	this_read = read_fully(fd, &file->link_count, sizeof(file->link_count));
	if(this_read != sizeof(file->link_count))
	{
		printf("unexpected EOF!\n");
		printf("when reading link_count, read %zu bytes and file->link_count is %zu bytes\n", this_read, sizeof(file->link_count));
		return file;
	}
	//printf("read %d bytes for link_count (%lu)\n", this_read, file->link_count);
	//printf("reading owner... "); fflush(stdout);
	if(read_string(fd, &file->owner))
	{
		printf("failed to read owner\n");
		return file;
	}
	if(file->owner == NULL)
	{
		printf("file->owner is NULL?!\n");
	}
	//printf("ok (\"%s\")\n", file->owner);
	//printf("reading group... "); fflush(stdout);
	if(read_string(fd, &file->group))
		return file;
	if(file->group == NULL)
	{
		printf("file->group is NULL?!\n");
	}
	//printf("ok (\"%s\")\n", file->group);
	//printf("trying to read file size (%d bytes)...\n", sizeof(file->size));
	this_read = read_fully(fd, &file->size, sizeof(file->size));
	if(this_read != sizeof(file->size))
	{
		printf("unexpected EOF!\n");
		printf("when reading file->size, read %zu bytes and file->size is %zu bytes\n", this_read, sizeof(file->size));
		return file;
	}
	//printf("trying to read file date (%d bytes)...\n", sizeof(file->date));
	this_read = read_fully(fd, &file->date, sizeof(file->date));
	if(this_read != sizeof(file->date))
	{
		printf("unexpected EOF!\n");
		printf("when reading file->date, read %zu bytes and file->date is %zu bytes\n", this_read, sizeof(file->date));
		return file;
	}
	//printf("loaded date info\n");
	if(read_long_string(fd, &file->fullpath))
		return file;
	//printf("loaded path \"%s\"\n", file->fullpath);
	file->name = strrchr(file->fullpath, '/');
	this_read = read_fully(fd, &file->child_count, sizeof(file->child_count));
	//printf("loading %lu children...\n", file->child_count);
	if(file->child_count > 0)
	{
		file->child = (struct FTP_File*)malloc(sizeof(struct FTP_File) * file->child_count);
		for(ssize_t children = 0; children < file->child_count; children++)
		{
			//printf("trying read child #%lu of \"%s\"...\n", children + 1, file->fullpath);
			deserialize_FTP_File(&file->child[children], fd);
			file->child[children].parent_file = file;
		}
	}
	else
		file->child = NULL;
	//printf("successfully loaded \"%s\", setting to valid\n", file->fullpath);
	file->valid = 1;
	return file;
}

/**
 * Compares the timestamps of the 2 specified files
 * Returns:
 *  > 0 if file1 is newer than file2
 *  0   if file1 was created at the same time as file2
 *  < 0 if file1 is older than file2
 */
int FTP_File_compareTime(const struct FTP_File file1, const struct FTP_File file2)
{
	return difftime(file1.date, file2.date);
}


char __prettySizeBuf__[16];
char* prettySize(const uint64_t size)
{
	if(size == UINT64_MAX)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "infinity");
	/*else if(size >= 1208925819614629174706176ull) // this is bigger than SSIZE_MAX!
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f YB", ((double)size) / 1208925819614629174706176.0);
	else if(size >= 1180591620717411303424ull) // this is bigger than SSIZE_MAX!
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f ZB", ((double)size) / 1180591620717411303424.0);*/
	else if(size >= 1152921504606846976ull)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f EB", ((double)size) / 1152921504606846976.0);
	else if(size >= 1125899906842624ull)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f PB", ((double)size) / 1125899906842624.0);
	else if(size >= 1099511627776ull)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f TB", ((double)size) / 1099511627776.0);
	else if(size >= 1073741824ull)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f GB", ((double)size) / 1073741824.0);
	else if(size >= 1048576ull)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f MB", ((double)size) / 1048576.0);
	else if(size >= 1024ull)
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%.2f KB", ((double)size) / 1024.0);
	else
		snprintf(__prettySizeBuf__, sizeof(__prettySizeBuf__), "%ld B", size);
	return __prettySizeBuf__;
}

// TODO: remove debug code
void snprintf_FTP_File(const struct FTP_File theFile, char* buf, const size_t buf_len)
{
	char date[256];
	strftime(date, sizeof(date), "%c", localtime(&theFile.date));
	snprintf(buf, buf_len, "%c %c%c%c%c%c%c%c%c%c%c %2u %s %s %10lu %s \"%s\"",
		theFile.valid ? 'v' : '!',
		theFile.type,
		theFile.permissions[0],
		theFile.permissions[1],
		theFile.permissions[2],
		theFile.permissions[3],
		theFile.permissions[4],
		theFile.permissions[5],
		theFile.permissions[6],
		theFile.permissions[7],
		theFile.permissions[8],
		theFile.link_count,
		theFile.owner,
		theFile.group,
		theFile.size,
		date,
//		theFile.parent_path,
		theFile.fullpath
		);
}

struct FTP_File* FTP_File_find_direct_child_w_hint(struct FTP_File* file, const char* child, size_t hint) // optimized :)
{
	if(file == NULL || child == NULL)
		return NULL;
	if(hint >= file->child_count) // our hint sucks so fallback
		return FTP_File_find_direct_child(file, child);
	if(strcmp(file->child[hint].name, child) == 0) // check our hint first
		return &(file->child[hint]);
	for(size_t i = hint - 1; i >= 0 && i < hint; --i) // when size_t in an unsigned type, when it goes < 0, it actually means it rolls over and becomes big
		if(strcmp(file->child[i].name, child) == 0)
			return &(file->child[i]);
	for(size_t i = hint + 1; i < file->child_count; ++i)
		if(strcmp(file->child[i].name, child) == 0)
			return &(file->child[i]);
	return NULL;
}

struct FTP_File* FTP_File_find_direct_child(struct FTP_File* file, const char* child)
{
	if(file == NULL || child == NULL)
		return NULL;
	for(size_t i = 0; i < file->child_count; ++i)
		if(strcmp(file->child[i].name, child) == 0)
			return &(file->child[i]);
	return NULL;
}

void destroy_FTP_File(struct FTP_File* file)
{
	if(file == NULL)
		return;
	//printf("destroying \"%s\"...\n", file->fullpath);
	if(file->owner != NULL)
		free(file->owner);
	if(file->group != NULL)
		free(file->group);
	if(file->fullpath != NULL)
		free(file->fullpath);
	if(file->child != NULL)
	{
		for(int i = 0; i < file->child_count; ++i)
			destroy_FTP_File(&file->child[i]);
		free(file->child);
	}

}

int tm_mon_fromString(const char* mon)
{
	int tm_mon = -1;
	const char const * const months[] = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };

	for(int i = 0; i < sizeof(months) / sizeof(char*); ++i)
		if(my_strincmp(mon, months[i], strlen(months[i])) == 0)
		{
			tm_mon = i;
			break;
		}
	
	return tm_mon;
}

struct FTP_File* __FTPClient_FTP_File_parseFileStruct__(char* data, struct FTP_File* parent_path, struct FTP_File* file, char** end)
{
	char *tmp;
	memset(file, 0, sizeof(struct FTP_File));
	file->owner = NULL;
	file->group = NULL;
	file->name = NULL;
	file->valid = 0;
	file->parent_file = parent_path;
	file->child_count = 0;
	file->child = NULL;
	if(end != NULL)
		*end = NULL;
	if(data == NULL)
		return file;
	file->type = *data;
	data++;
	if(!*data)
		return file;
	//printf("parsed type: %c\n", file.type);

	for(int i = 0; i < sizeof(file->permissions) / sizeof(char); ++i)
	{
		if(!*data)
			return file;
		file->permissions[i] = *data;
		data++;
	}
	//printf("parsed permissions: %9s\n", file.permissions);

	// link_count
	if(!*data)
		return file;
	file->link_count = strtol(data, &data, 10);
	if(data == NULL || !*data)
		return file;
	//printf("parsed link count: %d\n", file.link_count);
	
	// owner
	for(; *data == ' ' || *data == '\t'; data++); // skip whitespace
	tmp = data;
	for(; *data && !(*data == ' ' || *data == '\t'); data++);
	if(!*data)
		return file;
	file->owner = (char*)malloc(data - tmp + 1);
	if(file->owner == NULL)
	{
		perror("malloc()");
		fprintf(stderr, "in __FTPClient_FTP_File_parseFileStruct__(): failed to allocate %lu bytes for file.owner!\n", data - tmp + 1);
		exit(1);
	}
	memcpy(file->owner, tmp, data - tmp);
	file->owner[data - tmp] = 0;
	//printf("parsed owner: %s\n", file.owner);

	// group
	for(; *data == ' ' || *data == '\t'; data++); // skip whitespace
	tmp = data;
	for(; *data && !(*data == ' ' || *data == '\t'); data++);
	if(!*data)
		return file;
	file->group = (char*)malloc(data - tmp + 1);
	if(file->group == NULL)
	{
		perror("malloc()");
		fprintf(stderr, "in __FTPClient_FTP_File_parseFileStruct__(): failed to allocate %lu bytes for file.group!\n", data - tmp + 1);
		exit(1);
	}
	memcpy(file->group, tmp, data - tmp);
	file->group[data - tmp] = 0;
	//printf("parsed group: %s\n", file.group);

	// size
	if(!*data)
		return file;
	file->size = strtoull(data, &data, 10);
	if(data == NULL || !*data)
		return file;

	//printf("parsed size: %lu\n", file.size);
	file->date = 0;
	time(&file->date);
	struct tm* theDate = gmtime(&file->date);

	// month
	for(; *data == ' ' || *data == '\t'; data++); // skip whitespace
	if(!*data)
		return file;
	theDate->tm_mon = tm_mon_fromString(data);
	theDate->tm_isdst = -1;
	for(; *data && !(*data == ' ' || *data == '\t'); data++);

	// day
	if(!*data)
		return file;
	theDate->tm_mday = strtol(data, &data, 10);
	if(data == NULL || !*data)
		return file;

	int item; // could be either hour or year
	item = strtol(data, &data, 10);
	if(data == NULL || !*data)
		return file;
	if(*data == ':')
	{
		theDate->tm_hour = item;
		data++;
		if(!*data)
			return file;
		theDate->tm_min = strtol(data, &data, 10);
		if(data == NULL || !*data)
			return file;
		theDate->tm_sec = 0;
	}
	else
	{
		theDate->tm_year = item - 1900; // tm_year holds number of years since 1900
		theDate->tm_hour = theDate->tm_min = theDate->tm_sec = 0;
	}
	file->date = mktime(theDate); // fix theDate.tm_wday

	//char yeah[256];
	//strftime(yeah, sizeof(yeah), "%c", localtime(&file.date));
	//printf("parsed time: (raw time %u) %s\n", file.date, yeah);

	// name
	for(; *data == ' ' || *data == '\t'; data++); // skip whitespace
	if(!*data)
		return file;
	tmp = data;
	while(*data && *data != '\r' && *data != '\n') data++;
	//file.name = (char*)malloc(data - tmp + 1);
	//memcpy(file.name, tmp, data - tmp);
	//file.name[data - tmp] = 0;

	size_t fullpath_size = strlen(file->parent_file->fullpath) + (data - tmp) + 2;
	file->fullpath = (char*)malloc(fullpath_size * sizeof(char));
	if(file->fullpath == NULL)
	{
		perror("malloc()");
		fprintf(stderr, "in __FTPClient_FTP_File_parseFileStruct__(): failed to allocate %lu bytes for file.fullpath!\n", fullpath_size);
		exit(1);
	}
	snprintf(file->fullpath, fullpath_size, "%s/%.*s", file->parent_file->fullpath, (int)(data-tmp), tmp);
	file->name = strrchr(file->fullpath, '/');
	//while(*(file->name) == '/')
	//	file->name++;
	//printf("parsed name: %s\n", file.fullpath);

	while(*data && (*data == '\r' || *data == '\n'))
		data++;

	file->valid = 1;
	if(end != NULL)
		*end = data;
	return file;
}

char* __FTPClient_readIntoBuffer__(SOCKET data_sock, char** buffer, ssize_t* download_size)
{
	if(data_sock == INVALID_SOCKET)
		return NULL;
	//if(buffer == NULL)
	//	buffer = (char**)malloc(sizeof(char*));
	int chunk_size = 16;
	// we carefully manage our memory here, since the directory might be huge and we dont
	// want to consume too much memory when calling download_ftp_folder()
	int bytes_read = 0;
	ssize_t total_size = chunk_size;
	*buffer = (char*)malloc(chunk_size); // initalize 1kB of RAM
	if(*buffer == NULL)
	{
		perror("malloc()");
		fprintf(stderr, "in __FTPClient_readIntoBuffer__(): failed to allocate initial chunk of size %d bytes!\n", chunk_size);
		return NULL;
	}
	do
	{
		bytes_read = recv(data_sock, (*buffer) + total_size - chunk_size, chunk_size, 0);
		if(bytes_read < 0)
		{
			perror("recv()");
			closesocket(data_sock); // something happened!
			free(buffer);
			return NULL;
		}
		else
		{
			if(bytes_read)
			{
				total_size += bytes_read;
				*buffer = realloc(*buffer, total_size);
			}
		}
		//*(buffer + total_size) = 0;
	} while (bytes_read > 0);
	*(*buffer + total_size - chunk_size) = 0;
	if(download_size != NULL)
		*download_size = total_size - chunk_size;
	closesocket(data_sock);
	return *buffer;
}

uint64_t __FTPClient_readIntoFd__(SOCKET data_sock, int fd)
{
	if(data_sock == INVALID_SOCKET)
		return -1;
	char *buf = (char*)malloc(4096);
	if(buf == NULL)
	{
		perror("malloc()");
		return -1;
	}
	int bytes_read;
	uint64_t total_size = 0;
	do
	{
		bytes_read = recv(data_sock, buf, 4096, 0);
		if(bytes_read < 0)
		{
			perror("recv()");
			closesocket(data_sock);
			free(buf);
			return -1;
		}
		else if(bytes_read)
		{
			total_size += bytes_read;
			write(fd, buf, bytes_read);
		}
	} while (bytes_read > 0);
	closesocket(data_sock);
	return total_size;
}

uint64_t __FTPClient_writeIntoFd__(SOCKET data_sock, int fd)
{
	if(data_sock == INVALID_SOCKET)
		return -1;
	char *buf = (char*)malloc(4096);
	if(buf == NULL)
	{
		perror("malloc()");
		return -1;
	}
	int bytes_read;
	uint64_t total_size = 0;
	do
	{
		bytes_read = recv(data_sock, buf, 4096, 0);
		if(bytes_read < 0)
		{
			perror("recv()");
			closesocket(data_sock);
			free(buf);
			return -1;
		}
		else if(bytes_read)
		{
			total_size += bytes_read;
			send(data_sock, buf, bytes_read, 0);
		}
	} while(bytes_read > 0);
	closesocket(data_sock);
	return total_size;
}

struct FTP_File* FTP_Directory_findFirstDepthFirstSearch(struct FTP_File* dir, int (*which)(struct FTP_File))
{
	if(dir == NULL)
		return NULL;
	if(!dir->valid)
	{
		fprintf(stderr, "WARNING: Skipping invalid entry \"%s\" in search!", dir->fullpath);
		return NULL;
	}
	if(which(*dir))
		return dir;
	if(dir->type != 'd')
		return NULL; // base case
	for(size_t i = 0; i < dir->child_count; ++i)
	{
		printf("stepping into \"%s\"\n", dir->child[i].fullpath);
		struct FTP_File* match = FTP_Directory_findFirstDepthFirstSearch(&dir->child[i], which);
		if(match != NULL)
			return match;
	}
	return NULL;
}

/*void destroy_FTP_File_LinkedList(FTP_File_LinkedList* list)
{
	struct FTP_File_LinkedList *i = list;
	struct FTP_File_LinkedList *t;
	while(i != NULL)
	{
		t = i->next;
		free(i);
		i = t;
	}
}*/

void destroy_FTP_File_List(struct FTP_File_List* list)
{
	if(list->file != NULL)
		free(list->file); // don't destroy FTP_File since there may be other references to it!
}

void destroy_FTP_File_Diff_List(struct FTP_File_Diff_List* list)
{
	if(list->file != NULL)
		free(list->file); // don't destroy FTP_File since there may be other references to it!
	if(list->change != NULL)
		free(list->change);
}

#define __FTP_File_List_INITIAL_CAP__ 1
#define __FTP_File_List_BLOCK_SIZE__ 1

void add_FTP_File_List(struct FTP_File_List* list, struct FTP_File *elem)
{
	if(list->file == NULL)
	{
		list->count = 1;
		list->__cap__ = __FTP_File_List_INITIAL_CAP__;
		list->file = (struct FTP_File**)malloc(__FTP_File_List_INITIAL_CAP__ * sizeof(struct FTP_File*));
		list->file[0] = elem;
	}
	else
	{
		if(list->count >= list->__cap__)
		{
			list->__cap__ += __FTP_File_List_BLOCK_SIZE__;
			list->file = (struct FTP_File**)realloc(list->file, list->__cap__ * sizeof(struct FTP_File*));
		}
		list->file[list->count] = elem;
		list->count++;
	}
}

void add_FTP_File_Diff_List(struct FTP_File_Diff_List* list, struct FTP_File *elem, enum change_type change)
{
	if(list->file == NULL)
	{
		list->count = 1;
		list->__cap__ = __FTP_File_List_INITIAL_CAP__;
		list->file = (struct FTP_File**)malloc(__FTP_File_List_INITIAL_CAP__ * sizeof(struct FTP_File*));
		list->file[0] = elem;
		list->change = (enum change_type*)malloc(__FTP_File_List_INITIAL_CAP__ * sizeof(enum change_type));
		list->change[0] = change;
	}
	else
	{
		if(list->count >= list->__cap__)
		{
			list->__cap__ += __FTP_File_List_BLOCK_SIZE__;
			list->file = (struct FTP_File**)realloc(list->file, list->__cap__ * sizeof(struct FTP_File*));
			list->change = (enum change_type*)realloc(list->change, list->__cap__ * sizeof(enum change_type));
		}
		list->file[list->count] = elem;
		list->change[list->count] = change;
		list->count++;
	}
}

void addall_FTP_File_List(struct FTP_File_List* list, struct FTP_File_List *add)
{
	if(list->file == NULL)
	{
		list->count = add->count;
		list->__cap__ = add->__cap__;
		list->file = add->file;
	}
	else
	{
		if(list->__cap__ < list->count + add->count)
		{
			list->__cap__ = list->count + add->count;
			list->file = (struct FTP_File**)realloc(list->file, list->__cap__);
		}
		memcpy(&list->file[list->count], add->file, sizeof(struct FTP_File*) * add->count);
		list->count += add->count;
	}
}

struct FTP_File_Diff_List* FTP_Directory_compare(struct FTP_File* lhs, struct FTP_File* rhs, struct FTP_File_Diff_List* list)
{
	if(list == NULL)
	{
		list = (struct FTP_File_Diff_List*)malloc(sizeof(struct FTP_File_Diff_List));
		list->file = NULL;
		list->change = NULL;
		list->count = 0;
		list->__cap__ = 0;
	}
	if(lhs == NULL && rhs == NULL)
		return list;

	if(lhs == NULL && rhs != NULL)
	{
		add_FTP_File_Diff_List(list, rhs, ADDED);
		for(size_t i = 0; i < rhs->child_count; ++i)
			FTP_Directory_compare(NULL, &(rhs->child[i]), list);
		return list;
	}

	if(lhs != NULL && rhs == NULL)
	{
		add_FTP_File_Diff_List(list, lhs, REMOVED);
		for(size_t i = 0; i < lhs->child_count; ++i)
			FTP_Directory_compare(&(lhs->child[i]), NULL, list);
		return list;
	}

	if(strcmp(lhs->fullpath, rhs->fullpath) != 0)
	{
		fprintf(stderr, "warning: attempting to compare dissimilar file paths \"%s\" and \"%s\"!\n", lhs->fullpath, rhs->fullpath);
		fprintf(stderr, "warning: this should never happen!!");
	}

	if(lhs->type != rhs->type)
		add_FTP_File_Diff_List(list, rhs, MODIFIED);
	else if(strncmp(lhs->permissions, rhs->permissions, sizeof(lhs->permissions)) != 0)
		add_FTP_File_Diff_List(list, rhs, MODIFIED);
	else if(strcmp(lhs->owner, rhs->owner) != 0)
		add_FTP_File_Diff_List(list, rhs, MODIFIED);
	else if(strcmp(lhs->group, rhs->group) != 0)
		add_FTP_File_Diff_List(list, rhs, MODIFIED);
	else if(lhs->size != rhs->size)
		add_FTP_File_Diff_List(list, rhs, MODIFIED);
	else if(FTP_File_compareTime(*lhs, *rhs) != 0)
		add_FTP_File_Diff_List(list, rhs, MODIFIED);

	for(size_t i = 0; i < lhs->child_count; ++i)
	{
		FTP_Directory_compare(&(lhs->child[i]), FTP_File_find_direct_child_w_hint(rhs, lhs->child[i].name, i), list);
	}
	for(size_t i = 0; i < rhs->child_count; ++i)
	{
		if(FTP_File_find_direct_child_w_hint(lhs, rhs->child[i].name, i) == NULL)
			FTP_Directory_compare(NULL, &(rhs->child[i]), list);
	}
	return list;
}

struct FTP_File_List* FTP_Directory_findAllDepthFirstSearch(struct FTP_File* root, struct FTP_File_List *list, int (*which)(struct FTP_File))
{
	if(root == NULL)
		return NULL;
	if(list == NULL)
	{
		list = (struct FTP_File_List*)malloc(sizeof(struct FTP_File_List));
		list->file = NULL;
		list->count = 0;
		list->__cap__ = 0;
	}
	if(which(*root))
		add_FTP_File_List(list, root);
	if(root->type != 'd')
		return list;
	for(size_t i = 0; i < root->child_count; ++i)
		FTP_Directory_findAllDepthFirstSearch(&root->child[i], list, which);
	return list;
}

/*struct FTP_File* FTP_Directory_breadthFirstSearch(struct FTP_Directory *dir, int (*which)(struct FTP_File))
{
	for(size_t i = 0; i < dir->child_count; ++i)
	{
		if(which(dir->child[i]))
			return &dir->child[i];
	}
}

struct FTP_File* FTP_Directory_findFileThat(struct FTP_Directory *dir, int (*which)(struct FTP_File))
{
	for(size_t i = 0; i < dir->child_count; ++i)
		if(which(dir->child[i]))
			return &dir->child[i];
	return NULL;
}

int FTP_Directory_hasFileThat(struct FTP_Directory *dir, int (*which)(struct FTP_File))
{
	return FTP_Directory_findFileThat(dir, which) != NULL;
}*/

void __FTP_File__registerChild__(struct FTP_File* parent, struct FTP_File child)
{
	if(parent->child_count == 0)
	{
		parent->child = (struct FTP_File*)malloc(1 * sizeof(struct FTP_File));
		memset(parent->child, 0, sizeof(struct FTP_File));
		if(parent->child == NULL)
		{
			perror("malloc()");
		}
		parent->child_count = 1;
		parent->child[0] = child;
	}
	else
	{
		parent->child_count++;
		parent->child = realloc(parent->child, parent->child_count * sizeof(struct FTP_File));
		memset(&parent->child[parent->child_count - 1], 0, sizeof(struct FTP_File));
		if(parent->child == NULL)
		{
			perror("malloc()");
		}
		parent->child[parent->child_count - 1] = child;
	}
}



void FTPClient_download_single_directory(struct FTPClient* cli, struct FTP_File* dir, const char* theDirectory)
{
	//memset(&dir, 0, sizeof(dir));
	
	dir->valid = 0;
	if(!*theDirectory)
		dir->fullpath = strdup("/");
	else
		dir->fullpath = strdup(theDirectory);
	//dir->fullpath = theDirectory;
	if(dir->fullpath == NULL)
	{
		perror("strdup()");
		fprintf(stderr, "in FTPClient_download_single_directory(): failed to allocate memory for dir->fullpath!\n");
		fprintf(stderr, "attempting to duplicate string of len %lu: \"%s\"\n", strlen(theDirectory), theDirectory);
		exit(1);
	}
	dir->name = strrchr(dir->fullpath, '/');
	//if(dir->name == NULL) // ???????
	//	return; // theDirectory MUST be absolute path
		//dir->name = dir->fullpath;
	dir->type = 'd';
	dir->child_count = 0;
	dir->child = NULL;

	//printf("downloading directory listing for \"%s\"\n", dir->fullpath);

	//printf("waiting for data connection...\n");
	SOCKET data_sock = __FTPClient_openDataConnection__(cli, "LIST %s\r\n", dir->fullpath);
	if(data_sock == INVALID_SOCKET)
	{
		printf("failed to connect!\n");
		struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
		return;
	}
	else
		;//printf("data connection successful\n");

	// TODO: read the response and fill out dir
	size_t buffer_len = 4096; // there probably wont be any file names that are anywhere close to this long so we should be ok
	char *buffer = (char*)malloc(buffer_len * sizeof(char));
	if(buffer == NULL)
	{
		// this is bad :(
		perror("malloc()");
		closesocket(data_sock);
		exit(1); // yeah honestly theres no coming back from this
		return;
	}
	FILE *stream = bufferInSocketToCStream(data_sock);
	if(stream == NULL)
	{
		closesocket(data_sock);
		free(buffer);
		return;
	}
	dir->child_count = 0;
	ssize_t fileno = 0;
	while(fgets(buffer, buffer_len, stream) != NULL)
	{
		fileno++;
		struct FTP_File theFile;
		__FTPClient_FTP_File_parseFileStruct__(buffer, dir, &theFile, NULL);
		char* name = theFile.name;

		if(theFile.valid)
			__FTP_File__registerChild__(dir, theFile);
	}
	//printf("download success, waiting for confirmation on control connection\n");
	struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
	if(msg.code == 226)
		dir->valid = 1;
	else
		printf("unexpected code %lu%s\n", msg.code, msg.msg);
	cli->streaming = 0;
	//printf("downloaded directory listing of \"%s\" successfully!\n", theDirectory);
	fclose(stream);
	free(buffer);
}

struct FTP_File* __FTPClient_map_directory_recur__(struct FTPClient* cli, struct FTP_File* toFill, const char* theDirectory)
{
	//printf("mapping \"%s\"\n", theDirectory);
	if(toFill == NULL)
	{
		printf("toFill is NULL!\n");
	}
	//	toFill = (struct FTP_File*)malloc(sizeof(struct FTP_File));
	FTPClient_download_single_directory(cli, toFill, theDirectory);
	if(!toFill->valid)
	{
		printf("WARN: %s directory listing invalid!\n", theDirectory);
		return NULL;
	}
	if(toFill->type == 'd')
		for(size_t i = 0; i < toFill->child_count; ++i)
		{
			if(toFill->child[i].type == 'd')
			{
				size_t newsz = strlen(theDirectory) + strlen(toFill->child[i].name) + sizeof('\0');
				char* newSub = (char*)malloc(newsz);
				if(newSub == NULL)
				{
					perror("malloc()");
					fprintf(stderr, "in __FTPClient_map_directory_recur__(): failed to allocate %lu bytes for newSub!\n", newsz);
					exit(1);
				}
				strcpy(newSub, theDirectory);
				strcat(newSub, toFill->child[i].name);
				//snprintf(newSub, newsz, "%s%s", theDirectory, toFill->child[i].name);
				printf("attempting to map subdir \"%s\"\n", newSub);
				__FTPClient_map_directory_recur__(cli, &toFill->child[i], newSub);
				if(!toFill->child[i].valid)
				{
					printf("could not map subdir \"%s\"!\n", newSub);
					exit(1);
				}
				//printf("theDirectory = \"%s\", newSub = \"%s\", freeing newSub with size %d at %p\n", theDirectory, newSub, newsz, (void*)newSub);
				free(newSub);
				//printf("freed\n");
			}
			else
			{
				printf("not mapping nondirectory \"%s\"\n", toFill->child[i].fullpath);
			}
		}
	else
		printf("\"%s\" is not a directory, skipping! (type = %c)\n", theDirectory, toFill->type); // this should never happen
	return toFill;
}

struct FTP_File* __FTPClient_map_directory_recur_w_extra__(struct FTPClient* cli, struct FTP_File* toFill, const char* theDirectory, void (*prerecursive)())
{
	printf("mapping \"%s\"\n", theDirectory);
	if(toFill == NULL)
	{
		printf("toFill is NULL!\n");
	}
	//	toFill = (struct FTP_File*)malloc(sizeof(struct FTP_File));
	FTPClient_download_single_directory(cli, toFill, theDirectory);
	if(!toFill->valid)
	{
		printf("WARN: %s directory listing invalid!\n", theDirectory);
		return NULL;
	}
	if(toFill->type == 'd')
		for(size_t i = 0; i < toFill->child_count; ++i)
		{
			if(toFill->child[i].type == 'd')
			{
				size_t newsz = strlen(theDirectory) + strlen(toFill->child[i].name) + sizeof('\0');
				char* newSub = (char*)malloc(newsz);
				if(newSub == NULL)
				{
					perror("malloc()");
					fprintf(stderr, "in __FTPClient_map_directory_recur__(): failed to allocate %lu bytes for newSub!\n", newsz);
					exit(1);
				}
				strcpy(newSub, theDirectory);
				strcat(newSub, toFill->child[i].name);
				//snprintf(newSub, newsz, "%s%s", theDirectory, toFill->child[i].name);
				if(prerecursive != NULL)
					prerecursive();
				printf("attempting to map subdir \"%s\"\n", newSub);
				__FTPClient_map_directory_recur_w_extra__(cli, &toFill->child[i], newSub, prerecursive);
				//printf("theDirectory = \"%s\", newSub = \"%s\", freeing newSub with size %d at %p\n", theDirectory, newSub, newsz, (void*)newSub);
				free(newSub);
				//printf("freed\n");
			}
			else
			{
				printf("not mapping nondirectory \"%s\"\n", toFill->child[i].fullpath);
			}
		}
	else
		printf("\"%s\" is not a directory, skipping! (type = %c)\n", theDirectory, toFill->type); // this should never happen
	return toFill;
}

struct FTP_File* FTPClient_map_directory(struct FTPClient* cli, struct FTP_File* file, const char* theDirectory)
{
	memset(file, 0, sizeof(struct FTP_File));
	file->owner = strdup("");
	file->group = strdup("");
	__FTPClient_map_directory_recur__(cli, file, theDirectory);
}

struct FTP_File* FTPClient_map_directory_w_extra(struct FTPClient* cli, struct FTP_File* file, const char* theDirectory, void (*prerecursive)())
{
	memset(file, 0, sizeof(struct FTP_File));
	file->owner = strdup("");
	file->group = strdup("");
	__FTPClient_map_directory_recur_w_extra__(cli, file, theDirectory, prerecursive);
}

char* FTPClient_download_file_raw(struct FTPClient* cli, char** buffer, ssize_t* download_size, const char* format, ...)
{
	int needFreeBuffer = 0;
	if(buffer == NULL)
	{
		buffer = (char**)malloc(sizeof(char*));
		needFreeBuffer = 1;
	}
	va_list args;
	va_start(args, format);
	SOCKET data = __FTPClient_vOpenDataConnection__(cli, format, args);
	va_end(args);
	if(data == INVALID_SOCKET)
	{
		fprintf(stderr, "Failed to open data connection!");
		if(needFreeBuffer)
			free(buffer);
		struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
		return NULL;
	}
	if(__FTPClient_readIntoBuffer__(data, buffer, download_size) == NULL)
	{
		closesocket(data);
		if(needFreeBuffer)
			free(buffer);
		struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
		return NULL;
	}
	struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
	if(msg.code != 226)
	{
		return NULL;
	}
	char *ret = *buffer;
	if(needFreeBuffer)
		free(buffer);
	cli->streaming = 0;
	return ret;
}

uint64_t FTPClient_download_file(struct FTPClient* cli, const char* remote_file, const char* local_file)
{
	SOCKET data = __FTPClient_openDataConnection__(cli, "RETR %s\r\n", remote_file);
	if(data == INVALID_SOCKET)
	{
		fprintf(stderr, "[%s] Failed to open data connection!\n", cli->host);
		//struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
		return -1;
	}
	int fd = open(local_file, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if(fd < 0)
	{
		perror("open()");
		closesocket(data);
		return -1;
	}
	uint64_t size = __FTPClient_readIntoFd__(data, fd);
	close(fd);
	struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
	cli->streaming = 0;
	if(msg.code != 226)
	{
		fprintf(stderr, "Server returned abnormal return %ld%s\n", msg.code, msg.msg);
		return -1;
	}
	return size;
}

uint64_t FTPClient_upload_fd(struct FTPClient* cli, const char* remote_file, int fd)
{
	SOCKET data = __FTPClient_openDataConnection__(cli, "STOR \"%s\"\r\n", remote_file);
	if(data == INVALID_SOCKET)
	{
		fprintf(stderr, "[%s] Failed to open data connection!\n", cli->host);
		//struct FTP_cmd_msg msg = __FTPClient_readline__(cli);
		return -1;
	}
	uint64_t size = __FTPClient_writeIntoFd__(data, fd);
	close(fd);
	return size;
}

SOCKET FTPClient_openUploadConnection(struct FTPClient* cli, const char* remote_file)
{
	//return __FTPClient_openDataConnection__(cli, "STOR \"%s\"\r\n", remote_file);
	return __FTPClient_openDataConnection__(cli, "STOR %s\r\n", remote_file);
}

struct FTP_cmd_msg FTPClient_endUpload(struct FTPClient *cli, SOCKET sock)
{
	int i;
	if(i = closesocket(sock))
	{
		perror("closesocket()");
		fprintf(stderr, "in FTPClient_endUpload(), closesocket() failed with code %d!\n", i);
	}
	cli->streaming = 0;
	return __FTPClient_readline__(cli);
}

FILE* FTPClient_openBufferedUploadConnection(struct FTPClient* cli, const char* remote_file)
{
	SOCKET s = FTPClient_openUploadConnection(cli, remote_file);
	if(s == INVALID_SOCKET || s == SOCKET_ERROR)
		return NULL;
	return bufferOutSocketToCStream(s);
}

struct FTP_cmd_msg FTPClient_endBufferedUpload(struct FTPClient *cli, FILE *conn)
{
	fclose(conn);
	cli->streaming = 0;
	return __FTPClient_readline__(cli);
}

ssize_t FTPClient_readToStream(SOCKET data_sock, FILE* str)
{
	if(data_sock == INVALID_SOCKET)
		return -1;
	// TODO 
}