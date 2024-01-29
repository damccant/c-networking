#ifndef __FTP_H_
#define __FTP_H_

#define DEFAULT_FTP_PORT "21"
#define __FTP_BUFFER_SIZE__ 8192

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <time.h> // struct tm
#include <limits.h>
#include <stdint.h>
#include <inttypes.h> // uint64_t


#include "socket.h"
#include "../util.h"

struct FTPClient
{
	char* host;
	char* port;
	char* user;
	char* pass;
	int loggedIn;
	int streaming;
	int pasv;
	int __pasv_failed__;
	//FILE* cmd;
	FILE *cmdin, *cmdout;
	SOCKET __cntlSock__;
	SOCKET dataSock;
	char *__buf__;
};

void FTPClient_init(struct FTPClient* cli);
void FTPClient_reset(struct FTPClient* cli);
int FTPClient_connect(struct FTPClient* cli, const char* host, const char* port);
int FTPClient_reconnect(struct FTPClient* cli);
int FTPClient_prepare_login(struct FTPClient* cli);
int FTPClient_retry_login(struct FTPClient *cli, const char *user, const char *pass);
int FTPClient_login(struct FTPClient* cli, const char* user, const char* pass);
void FTPClient_quit(struct FTPClient *cli);

struct FTP_cmd_msg
{
	long int code;
	char* msg;
};

struct FTP_cmd_msg FTPClient_run(struct FTPClient* cli, const char* format, ...);

struct FTP_File
{
	unsigned int valid:1;	// valid should be set to 1 for valid entries
	char type;	// should be 'd' for directories
	char permissions[9];
	unsigned int link_count;
	char* owner;
	char* group;
	ssize_t size;
	time_t date;
	char* fullpath;
	char* name; // this points to something in fullpath, so do not free() this!
	struct FTP_File* parent_file;

	// only set for directories
	size_t child_count; // 0 if unknown
	struct FTP_File* child;
};

void snprintf_FTP_File(const struct FTP_File theFile, char* buf, const size_t buf_len);
void serialize_FTP_File(struct FTP_File* file, int fd);
struct FTP_File* deserialize_FTP_File(struct FTP_File* file, int fd);
/**
 * Compares the timestamps of the 2 specified files
 * Returns:
 *  > 0 if file1 is newer than file2
 *  0   if file1 was created at the same time as file2
 *  < 0 if file1 is older than file2
 */
int FTP_File_compareTime(const struct FTP_File file1, const struct FTP_File file2);
struct FTP_File* FTP_Directory_findFirstDepthFirstSearch(struct FTP_File* dir, int (*which)(struct FTP_File));
void destroy_FTP_File(struct FTP_File* file);
struct FTP_File* FTP_File_find_direct_child(struct FTP_File* file, const char* child);

struct FTP_File_List
{
	ssize_t count;
	ssize_t __cap__;
	struct FTP_File** file; // this should be referenced by other struct FTP_File so don't free here
};

void destroy_FTP_File_List(struct FTP_File_List* list);
void add_FTP_File_List(struct FTP_File_List* list, struct FTP_File *elem);
void addall_FTP_File_List(struct FTP_File_List* list, struct FTP_File_List *add);
struct FTP_File_List* FTP_Directory_findAllDepthFirstSearch(struct FTP_File* root, struct FTP_File_List *list, int (*which)(struct FTP_File));

struct FTP_File_Diff_List
{
	ssize_t count;
	ssize_t __cap__;
	struct FTP_File** file; // this should be referenced by other struct FTP_File so don't free here
	enum change_type
	{
		MODIFIED,
		ADDED,
		REMOVED,
	} *change;
};

void destroy_FTP_File_Diff_List(struct FTP_File_Diff_List* list);
void add_FTP_File_Diff_List(struct FTP_File_Diff_List* list, struct FTP_File *elem, enum change_type change);
struct FTP_File_Diff_List* FTP_Directory_compare(struct FTP_File* lhs, struct FTP_File* rhs, struct FTP_File_Diff_List* list);

void FTPClient_download_single_directory(struct FTPClient* cli, struct FTP_File* dir, const char* theDirectory);
struct FTP_File* FTPClient_map_directory(struct FTPClient* cli, struct FTP_File* file, const char* theDirectory);
struct FTP_File* FTPClient_map_directory_w_extra(struct FTPClient* cli, struct FTP_File* file, const char* theDirectory, void (*prerecursive)());
uint64_t FTPClient_download_file(struct FTPClient* cli, const char* remote_file, const char* local_file);
SOCKET FTPClient_openUploadConnection(struct FTPClient* cli, const char* remote_file);
struct FTP_cmd_msg FTPClient_endUpload(struct FTPClient *cli, SOCKET sock);
FILE* FTPClient_openBufferedUploadConnection(struct FTPClient* cli, const char* remote_file);
struct FTP_cmd_msg FTPClient_endBufferedUpload(struct FTPClient *cli, FILE *conn);
uint64_t FTPClient_upload_fd(struct FTPClient* cli, const char* remote_file, int fd);

#ifdef __cplusplus
}
#endif

#endif /* __FTP_H_ */