#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>

/* Default values */
#define MAX_FAILURE_COUNT 30
#define PORT 8081
#define THREAD_COUNT 10
#define BIND_ADDR "::"

/* Arguments for worker threads */
struct filed_worker_thread_args {
	int fd;
};

/* File information */
struct filed_fileinfo {
	pthread_mutex_t mutex;
	char *path;
	int fd;
	size_t len;
	char *lastmod;
	char lastmod_b[64];
	char *type;
};

/* Global variables */
struct filed_fileinfo *filed_fileinfo_fdcache;
unsigned int filed_fileinfo_fdcache_size = 8192;

/* Initialize process */
static int filed_init(void) {
	unsigned int idx;
	int mutex_init_ret;

	mlockall(MCL_CURRENT | MCL_FUTURE);

	filed_fileinfo_fdcache = malloc(sizeof(*filed_fileinfo_fdcache) * filed_fileinfo_fdcache_size);
	if (filed_fileinfo_fdcache == NULL) {
		return(1);
	}

	for (idx = 0; idx < filed_fileinfo_fdcache_size; idx++) {
		mutex_init_ret = pthread_mutex_init(&filed_fileinfo_fdcache[idx].mutex, NULL);
		if (mutex_init_ret != 0) {
			return(1);
		}

		filed_fileinfo_fdcache[idx].path = strdup("");
		filed_fileinfo_fdcache[idx].fd = -1;
		filed_fileinfo_fdcache[idx].lastmod = "";
		filed_fileinfo_fdcache[idx].type = "";
	}

	return(0);
}

/* Listen on a particular address/port */
static int filed_listen(const char *address, unsigned int port) {
	struct sockaddr_in6 addr;
	int pton_ret, bind_ret, listen_ret;
	int fd;

	addr.sin6_family = AF_INET6;
	addr.sin6_flowinfo = 0;
	addr.sin6_scope_id = 0;
	addr.sin6_port = htons(port);
	pton_ret = inet_pton(AF_INET6, address, addr.sin6_addr.s6_addr);
	if (pton_ret != 1) {
		return(-1);
	}

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		return(fd);
	}

	bind_ret = bind(fd, (const struct sockaddr *) &addr, sizeof(addr));
	if (bind_ret < 0) {
		close(fd);

		return(-1);
	}

	listen_ret = listen(fd, 128);
	if (listen_ret != 0) {
		close(fd);

		return(-1);
	}

	return(fd);
}

/* Log a message */
#define FILED_DONT_LOG
#ifdef FILED_DONT_LOG
#  define filed_logging_thread_init() 0
#  define filed_log_msg_debug(x, ...) /**/
#  define filed_log_msg(x) /**/
#else
/* Initialize logging thread */
static int filed_logging_thread_init(void) {
	/* XXX:TODO: Unimplemented */
	return(0);
}

#define filed_log_msg_debug(x, ...) { fprintf(stderr, x, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr); }
static void filed_log_msg(const char *buffer) {
	/* XXX:TODO: Unimplemented */
	fprintf(stderr, "%s\n", buffer);

	return;
}

#endif
/* Format time per RFC2616 */
static char *filed_format_time(char *buffer, size_t buffer_len, const time_t timeinfo) {
	struct tm timeinfo_tm, *timeinfo_tm_p;

	timeinfo_tm_p = gmtime_r(&timeinfo, &timeinfo_tm);
	if (timeinfo_tm_p == NULL) {
		return("unknown");
	}

	buffer[buffer_len - 1] = '\0';
	buffer_len = strftime(buffer, buffer_len - 1, "%a, %d %b %Y %H:%M:%S GMT", timeinfo_tm_p);

	return(buffer);
}

/* hash */
static unsigned int filed_hash(const unsigned char *value, unsigned int modulus) {
	unsigned char curr;
	unsigned int retval;

	retval = modulus - 1;

	while ((curr = *value)) {
		if (curr < 32) {
			curr = 255 - curr;
		} else {
			curr -= 32;
		}

		retval <<= 5;
		retval += curr;

		value++;
	}

	retval = retval % modulus;

	return(retval);
}

/* Open a file and return file information */
static struct filed_fileinfo *filed_open_file(const char *path, struct filed_fileinfo *buffer) {
	struct filed_fileinfo *cache;
	unsigned int cache_idx;
	off_t len;
	int fd;

	cache_idx = filed_hash((const unsigned char *) path, filed_fileinfo_fdcache_size);

	cache = &filed_fileinfo_fdcache[cache_idx];

	filed_log_msg_debug("Locking mutex for idx: %lu", (unsigned long) cache_idx);

	pthread_mutex_lock(&cache->mutex);

	filed_log_msg_debug("Completed locking mutex for idx: %lu", (unsigned long) cache_idx);

	if (strcmp(path, cache->path) != 0) {
		filed_log_msg_debug("Cache miss for idx: %lu: OLD \"%s\", NEW \"%s\"", (unsigned long) cache_idx, cache->path, path);

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			pthread_mutex_unlock(&cache->mutex);

			return(NULL);
		}

		free(cache->path);
		if (cache->fd >= 0) {
			close(cache->fd);
		}

		len = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);

		cache->fd = fd;
		cache->len = len;
		cache->path = strdup(path);

		/* XXX:TODO: Determine */
		cache->type = "application/octet-stream";
		cache->lastmod = filed_format_time(cache->lastmod_b, sizeof(cache->lastmod_b), time(NULL) - 30);
	} else {
		filed_log_msg_debug("Cache hit for idx: %lu: PATH \"%s\"", (unsigned long) cache_idx, path);
	}

	/*
	 * We have to make a duplicate FD, because once we release the cache
	 * mutex, the file descriptor may be closed
	 */
	fd = dup(cache->fd);
	if (fd < 0) {
		pthread_mutex_unlock(&cache->mutex);

		return(NULL);
	}

	buffer->fd = fd;
	buffer->len = cache->len;
	buffer->type = cache->type;
	memcpy(buffer->lastmod_b, cache->lastmod_b, sizeof(buffer->lastmod_b));
	buffer->lastmod = buffer->lastmod_b + (cache->lastmod - cache->lastmod_b);

	pthread_mutex_unlock(&cache->mutex);

	return(buffer);
}

/* Process an HTTP request and return the path requested */
static char *filed_get_http_request(FILE *fp, char *buffer, size_t buffer_len) {
	char *method, *path;
	char tmpbuf[1010];
	int i;

	filed_log_msg("WAIT_FOR_REQUEST FD=...");

	fgets(buffer, buffer_len, fp);

	method = buffer;

	buffer = strchr(buffer, ' ');
	if (buffer == NULL) {
		filed_log_msg("GOT_REQUEST FD=... ERROR=format");

		return(NULL);
	}

	*buffer = '\0';
	buffer++;

	path = buffer;

	buffer = strchr(buffer, ' ');
	if (buffer != NULL) {
		*buffer = '\0';
		buffer++;
	}

	filed_log_msg("GOT_REQUEST FD=... PATH=...");

	filed_log_msg("WAIT_FOR_HEADERS FD=...");

	for (i = 0; i < 100; i++) {
		fgets(tmpbuf, sizeof(tmpbuf), fp);
		if (memcmp(tmpbuf, "\r\n", 2) == 0) {
			break;
		}
	}

	filed_log_msg("GOT_HEADERS FD=...");

	fflush(fp);

	/* We only handle the "GET" method */
	if (strcasecmp(method, "get") != 0) {
		return(NULL);
	}

	return(path);
}

/* Return an error page */
static void filed_error_page(FILE *fp, const char *date_current, int error_number) {
	char *error_string = "<html><head><title>ERROR</title></head><body>Unable to process request</body></html>";

	fprintf(fp, "HTTP/1.1 %i OK\r\nDate: %s\r\nServer: filed\r\nLast-Modified: %s\r\nContent-Length: %llu\r\nContent-Type: %s\r\nConnection: close\r\n\r\n%s",
		error_number,
		date_current,
		date_current,
		(unsigned long long) strlen(error_string),
		"text/html",
		error_string
	);
}

/* Handle a single request from a client */
static void filed_handle_client(int fd) {
	struct filed_fileinfo *fileinfo, fileinfo_b;
	ssize_t sendfile_ret;
	size_t sendfile_len;
	off_t sendfile_offset;
	char *path, path_b[1010];
	char *date_current, date_current_b[64];
	FILE *fp;

	/* Determine current time */
	date_current = filed_format_time(date_current_b, sizeof(date_current_b), time(NULL));

	/* Open socket as ANSI I/O for ease of use */
	fp = fdopen(fd, "w+b");
	if (fp == NULL) {
		close(fd);

		return;
	}

	path = filed_get_http_request(fp, path_b, sizeof(path_b));

	filed_log_msg("PROCESS_REPLY_START FD=... PATH=...");

	if (path == NULL) {
		filed_error_page(fp, date_current, 500);

		filed_log_msg("PROCESS_REPLY_COMPLETE FD=... ERROR=500");

		fclose(fp);

		return;
	}

	fileinfo = filed_open_file(path, &fileinfo_b);
	if (fileinfo == NULL) {
		filed_error_page(fp, date_current, 404);

		filed_log_msg("PROCESS_REPLY_COMPLETE FD=... ERROR=404");
	} else {
		fprintf(fp, "HTTP/1.1 200 OK\r\nDate: %s\r\nServer: filed\r\nLast-Modified: %s\r\nContent-Length: %llu\r\nContent-Type: %s\r\nConnection: close\r\n\r\n",
			date_current,
			fileinfo->lastmod,
			(unsigned long long) fileinfo->len,
			fileinfo->type
		);
		fflush(fp);

		filed_log_msg("PROCESS_REPLY_COMPLETE FD=... STATUS=200");

		filed_log_msg("SEND_START IFD=... OFD=... BYTES=...");

		sendfile_offset = 0;
		sendfile_len = fileinfo->len;
		while (1) {
			sendfile_ret = sendfile(fd, fileinfo->fd, &sendfile_offset, sendfile_len);
			if (sendfile_ret <= 0) {
				break;
			}

			sendfile_len -= sendfile_ret;
			if (sendfile_len == 0) {
				break;
			}
		}

		filed_log_msg("SEND_COMPLETE STATUS=... IFD=... OFD=... BYTES=... BYTES_SENT=...");

		close(fileinfo->fd);

		filed_log_msg("CLOSE_FILE FD=...");
	}

	filed_log_msg("CLOSE_CONNECTION FD=...");

	fclose(fp);

	return;
}

/* Handle incoming connections */
static void *filed_worker_thread(void *arg_v) {
	struct filed_worker_thread_args *arg;
	struct sockaddr_in6 addr;
	socklen_t addrlen;
	int failure_count = 0, max_failure_count = MAX_FAILURE_COUNT;
	int master_fd, fd;

	/* Read arguments */
	arg = arg_v;

	master_fd = arg->fd;

	while (1) {
		/* Failure loop prevention */
		if (failure_count > max_failure_count) {
			break;
		}

		/* Accept a new client */
		addrlen = sizeof(addr);
		fd = accept(master_fd, (struct sockaddr *) &addr, &addrlen);

		/*
		 * If we fail, make a note of it so we don't go into a loop of
		 * accept() failing
		 */
		if (fd < 0) {
			/* Log the new connection */
			filed_log_msg("ACCEPT_FAILED");

			failure_count++;

			continue;
		}

		/* Log the new connection */
		filed_log_msg("NEW_CONNECTION SRC_ADDR=... SRC_PORT=... FD=...");

		/* Reset failure count*/
		failure_count = 0;

		/* Handle socket */
		filed_handle_client(fd);
	}

	/* Report error */
	filed_log_msg("THREAD_DIED ABNORMAL");

	return(NULL);
}

/* Create worker threads */
static int filed_worker_threads_init(int fd, int thread_count) {
	struct filed_worker_thread_args *arg;
	pthread_t threadid;
	int pthread_ret;
	int i;

	for (i = 0; i < thread_count; i++) {
		arg = malloc(sizeof(*arg));

		arg->fd = fd;

		pthread_ret = pthread_create(&threadid, NULL, filed_worker_thread, arg);
		if (pthread_ret != 0) {
			return(-1);
		}
	}

	return(0);
}

/* Run process */
int main(int argc, char **argv) {
	int port = PORT, thread_count = THREAD_COUNT;
	const char *bind_addr = BIND_ADDR;
	int init_ret;
	int fd;

	/* Ignore */
	argc = argc;
	argv = argv;

	/* Create listening socket */
	fd = filed_listen(bind_addr, port);
	if (fd < 0) {
		perror("filed_listen");

		return(1);
	}

	/* Become a daemon */
	/* XXX:TODO: Become a daemon */

	/* Initialize */
	init_ret = filed_init();
	if (init_ret != 0) {
		perror("filed_init");

		return(3);
	}

	/* Create logging thread */
	init_ret = filed_logging_thread_init();
	if (init_ret != 0) {
		perror("filed_logging_thread_init");

		return(4);
	}

	/* Create worker threads */
	init_ret = filed_worker_threads_init(fd, thread_count);
	if (init_ret != 0) {
		perror("filed_worker_threads_init");

		return(4);
	}

	/* Wait for threads to exit */
	/* XXX:TODO: Monitor thread usage */
	while (1) {
		sleep(60);
	}

	/* Return in failure */
	return(2);
}
