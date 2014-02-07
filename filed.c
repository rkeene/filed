#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <strings.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>

/* Compile time constants */
#define FILED_SENDFILE_MAX 16777215
#define MAX_FAILURE_COUNT 30
#define FILED_DEFAULT_TYPE "application/octet-stream"

/* Default values */
#define PORT 80
#define THREAD_COUNT 5
#define BIND_ADDR "::"
#define CACHE_SIZE 8209

/* Arguments for worker threads */
struct filed_worker_thread_args {
	int fd;
};

/* File information */
struct filed_fileinfo {
	pthread_mutex_t mutex;
	char *path;
	int fd;
	off_t len;
	char *lastmod;
	char lastmod_b[64];
	const char *type;
};

/* Request variables */
struct filed_http_request {
	/** Buffers **/
	struct filed_fileinfo fileinfo;
	char path_b[1010];
	char tmpbuf[1010];

	/** HTTP Request information **/
	char *path;     /*** Path being requested ***/

	struct {
		struct {
			int present;
			off_t offset;   /*** Range start ***/
			off_t length;   /*** Range length ***/
		} range;
	} headers;
};

/* Global variables */
/** Open File cache **/
struct filed_fileinfo *filed_fileinfo_fdcache = NULL;
unsigned int filed_fileinfo_fdcache_size = 0;

/* Initialize cache */
static int filed_init_cache(unsigned int cache_size) {
	unsigned int idx;
	int mutex_init_ret;

	/* Cache may not be re-initialized */
	if (filed_fileinfo_fdcache_size != 0 || filed_fileinfo_fdcache != NULL) {
		return(1);
	}

	/* Allocate cache */
	filed_fileinfo_fdcache_size = cache_size;
	filed_fileinfo_fdcache = malloc(sizeof(*filed_fileinfo_fdcache) * filed_fileinfo_fdcache_size);
	if (filed_fileinfo_fdcache == NULL) {
		return(1);
	}

	/* Initialize cache entries */
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

/* Initialize process */
static int filed_init(unsigned int cache_size) {
	static int called = 0;
	int cache_ret;

	if (called) {
		return(0);
	}

	called = 1;

	mlockall(MCL_CURRENT | MCL_FUTURE);

	signal(SIGPIPE, SIG_IGN);

	cache_ret = filed_init_cache(cache_size);
	if (cache_ret != 0) {
		return(cache_ret);
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
//#define FILED_DONT_LOG
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

/* XXX:TODO: Unimplemented */
#define filed_log_msg_debug(x, ...) { fprintf(stderr, x, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr); }

static void filed_log_msg(const char *fmt, ...) {
	char buffer[1010];
	va_list args;

	va_start(args, fmt);

	vsnprintf(buffer, sizeof(buffer), fmt, args);

	va_end(args);

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
/* XXX:TODO: Rewrite this */
static unsigned int filed_hash(const unsigned char *value, unsigned int modulus) {
	unsigned char curr, prev;
	int diff;
	unsigned int retval;

	retval = modulus - 1;
	prev = modulus % 255;

	while ((curr = *value)) {
		if (curr < 32) {
			curr = 255 - curr;
		} else {
			curr -= 32;
		}

		if (prev < curr) {
			diff = curr - prev;
		} else {
			diff = prev - curr;
		}

		prev = curr;

		retval <<= 3;
		retval &= 0xFFFFFFFFLU;
		retval ^= diff;

		value++;
	}

	retval = retval % modulus;

	return(retval);
}

/* Find a mime-type based on the filename */
static const char *filed_determine_mimetype(const char *path) {
	const char *p;

	p = strrchr(path, '.');
	if (p == NULL) {
		return(FILED_DEFAULT_TYPE);
	}

	p++;
	if (*p == '\0') {
		return(FILED_DEFAULT_TYPE);
	}

	filed_log_msg_debug("Looking up MIME type for %s (hash = %llu)", p, (unsigned long long) filed_hash((const unsigned char *) p, 16777259));

#include "filed-mime-types.h"

	return(FILED_DEFAULT_TYPE);
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

		fd = open(path, O_RDONLY | O_LARGEFILE);
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
		cache->type = filed_determine_mimetype(path);

		/* XXX:TODO: Determine */
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
static struct filed_http_request *filed_get_http_request(FILE *fp, struct filed_http_request *buffer_st) {
	char *method, *path;
	char *buffer, *tmpbuffer, *workbuffer, *workbuffer_next;
	size_t buffer_len, tmpbuffer_len;
	off_t range_start, range_end, range_length;
	int range_request;
	int fd;
	int i;

	fd = fileno(fp);

	range_start = 0;
	range_end   = 0;
	range_request = 0;
	range_length = -1;

	buffer = buffer_st->path_b;
	buffer_len = sizeof(buffer_st->path_b);

	tmpbuffer = buffer_st->tmpbuf;
	tmpbuffer_len = sizeof(buffer_st->tmpbuf);

	filed_log_msg("WAIT_FOR_REQUEST FD=%i", fd);

	fgets(buffer, buffer_len, fp);

	method = buffer;

	buffer = strchr(buffer, ' ');
	if (buffer == NULL) {
		filed_log_msg("GOT_REQUEST FD=%i ERROR=format", fd);

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

	filed_log_msg("GOT_REQUEST FD=%i PATH=%s", fd, path);

	filed_log_msg("WAIT_FOR_HEADERS FD=%i", fd);

	for (i = 0; i < 100; i++) {
		fgets(tmpbuffer, tmpbuffer_len, fp);

		if (strncasecmp(tmpbuffer, "Range: ", 7) == 0) {
			workbuffer = tmpbuffer + 7;

			if (strncasecmp(workbuffer, "bytes=", 6) == 0) {
				workbuffer += 6;

				range_request = 1;

				range_start = strtoull(workbuffer, &workbuffer_next, 10);

				workbuffer = workbuffer_next;

				if (*workbuffer == '-') {
					workbuffer++;

					if (*workbuffer != '\r' && *workbuffer != '\n') {
						range_end = strtoull(workbuffer, &workbuffer_next, 10);
					}
				}
			}
		}

		if (memcmp(tmpbuffer, "\r\n", 2) == 0) {
			break;
		}
	}

	filed_log_msg("GOT_HEADERS FD=%i", fd);

	/* We only handle the "GET" method */
	if (strcasecmp(method, "get") != 0) {
		return(NULL);
	}

	/* Determine range */
	if (range_end != 0) {
		if (range_end <= range_start) {
			return(NULL);
		}

		range_length = range_end - range_start;

		filed_log_msg_debug("Computing length parameter: %llu = %llu - %llu",
			(unsigned long long) range_length,
			(unsigned long long) range_end,
			(unsigned long long) range_start
		);
	}

	/* Fill up structure to return */
	buffer_st->path   = path;
	buffer_st->headers.range.present = range_request;
	buffer_st->headers.range.offset  = range_start;
	buffer_st->headers.range.length  = range_length;

	return(buffer_st);
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
static void filed_handle_client(int fd, struct filed_http_request *request) {
	struct filed_fileinfo *fileinfo;
	ssize_t sendfile_ret;
	size_t sendfile_len, sendfile_sent, sendfile_size;
	off_t sendfile_offset;
	char *path;
	char *date_current, date_current_b[64];
	int http_code;
	FILE *fp;

	/* Determine current time */
	date_current = filed_format_time(date_current_b, sizeof(date_current_b), time(NULL));

	/* Open socket as ANSI I/O for ease of use */
	fp = fdopen(fd, "w+b");
	if (fp == NULL) {
		close(fd);

		return;
	}

	request = filed_get_http_request(fp, request);

	if (request == NULL || request->path == NULL) {
		filed_error_page(fp, date_current, 500);

		filed_log_msg("INVALID_REQUEST FD=%i ERROR=500", fd);

		fclose(fp);

		return;
	}

	if (request->headers.range.present) {
		filed_log_msg("PROCESS_REPLY_START FD=%i PATH=%s RANGE_START=%llu RANGE_LENGTH=%llu",
			fd,
			request->path,
			(unsigned long long) request->headers.range.offset,
			(unsigned long long) request->headers.range.length
		);
	} else {
		filed_log_msg("PROCESS_REPLY_START FD=%i PATH=%s", fd, request->path);
	}

	path = request->path;

	http_code = -1;

	fileinfo = filed_open_file(path, &request->fileinfo);
	if (fileinfo == NULL) {
		filed_error_page(fp, date_current, 404);

		filed_log_msg("PROCESS_REPLY_COMPLETE FD=%i ERROR=404", fd);
	} else {
		if (request->headers.range.offset != 0 || request->headers.range.length >= 0) {
			if (request->headers.range.offset >= fileinfo->len) {
				filed_log_msg("PROCESS_REPLY_COMPLETE FD=%i ERROR=416", fd);

				filed_error_page(fp, date_current, 416);
			} else {
				if (request->headers.range.length < 0) {
					filed_log_msg_debug("Computing length to fit in bounds: fileinfo->len = %llu, request->headers.range.offset = %llu",
						(unsigned long long) fileinfo->len,
						(unsigned long long) request->headers.range.offset
					);

					request->headers.range.length = fileinfo->len - request->headers.range.offset;
				}

				filed_log_msg_debug("Partial request, starting at: %llu and running for %llu bytes",
					(unsigned long long) request->headers.range.offset,
					(unsigned long long) request->headers.range.length
				);

				http_code = 206;
			}
		} else {
			if (request->headers.range.present) {
				http_code = 206;
			} else {
				http_code = 200;
			}
			request->headers.range.offset = 0;
			request->headers.range.length = fileinfo->len;
		}

		if (http_code > 0) {
			fprintf(fp, "HTTP/1.1 %i OK\r\nDate: %s\r\nServer: filed\r\nLast-Modified: %s\r\nContent-Length: %llu\r\nAccept-Ranges: bytes\r\nContent-Type: %s\r\nConnection: close\r\n",
				http_code,
				date_current,
				fileinfo->lastmod,
				(unsigned long long) request->headers.range.length,
				fileinfo->type
			);
			if (http_code == 206) {
				fprintf(fp, "Content-Range: bytes %llu-%llu/%llu\r\n",
					(unsigned long long) request->headers.range.offset,
					(unsigned long long) (request->headers.range.offset + request->headers.range.length - 1),
					(unsigned long long) fileinfo->len
				);
			}
			fprintf(fp, "\r\n");
			fflush(fp);

			filed_log_msg("PROCESS_REPLY_COMPLETE FD=%i STATUS=%i", fd, http_code);

#ifdef FILED_NONBLOCK_HTTP
			int socket_flags;
			fd_set rfd, wfd;
			char sinkbuf[8192];
			ssize_t read_ret;

			FD_ZERO(&rfd);
			FD_ZERO(&wfd);
			FD_SET(fd, &rfd);
			FD_SET(fd, &wfd);

			socket_flags = fcntl(fd, F_GETFL);
			fcntl(fd, F_SETFL, socket_flags | O_NONBLOCK);
#endif

			filed_log_msg("SEND_START FILE_FD=%i FD=%i BYTES=%llu OFFSET=%llu",
				fileinfo->fd,
				fd,
				(unsigned long long) request->headers.range.length,
				(unsigned long long) request->headers.range.offset
			);

			sendfile_offset = request->headers.range.offset;
			sendfile_len = request->headers.range.length;
			sendfile_sent = 0;
			while (1) {
				if (sendfile_len > FILED_SENDFILE_MAX) {
					sendfile_size = FILED_SENDFILE_MAX;
				} else {
					sendfile_size = sendfile_len;
				}

				sendfile_ret = sendfile(fd, fileinfo->fd, &sendfile_offset, sendfile_size);
				if (sendfile_ret <= 0) {
#ifdef FILED_NONBLOCK_HTTP
					if (errno == EAGAIN) {
						sendfile_ret = 0;

						while (1) {
							select(fd + 1, &rfd, &wfd, NULL, NULL);
							if (FD_ISSET(fd, &rfd)) {
								read_ret = read(fd, sinkbuf, sizeof(sinkbuf));

								if (read_ret <= 0) {
									break;
								}
							}

							if (FD_ISSET(fd, &wfd)) {
								read_ret = 1;

								break;
							}
						}

						if (read_ret <= 0) {
							break;
						}
					} else {
						break;
					}
#else
					break;
#endif
				}

				sendfile_len -= sendfile_ret;
				sendfile_sent += sendfile_ret;
				if (sendfile_len == 0) {
					break;
				}
			}

			filed_log_msg("SEND_COMPLETE STATUS=%s FILE_FD=%i FD=%i BYTES=%llu BYTES_SENT=%llu",
				"<unknown>",
				fileinfo->fd,
				fd,
				(unsigned long long) request->headers.range.length,
				(unsigned long long) sendfile_sent
			);
		}

		close(fileinfo->fd);

		filed_log_msg("CLOSE_FILE FD=%i", fd);
	}

	filed_log_msg("CLOSE_CONNECTION FD=%i", fd);

	fclose(fp);

	return;
}

/* Handle incoming connections */
static void *filed_worker_thread(void *arg_v) {
	struct filed_worker_thread_args *arg;
	struct filed_http_request request;
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
		filed_log_msg("NEW_CONNECTION SRC_ADDR=... SRC_PORT=... FD=%i", fd);

		/* Reset failure count*/
		failure_count = 0;

		/* Handle socket */
		filed_handle_client(fd, &request);
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

/* Display help */
static void filed_print_help(FILE *output, int long_help, const char *extra) {
	if (extra) {
		fprintf(output, "%s\n", extra);
	}

	fprintf(output, "Usage: filed [<options>]\n");
	fprintf(output, "  Options:\n");
	fprintf(output, "      -h, --help\n");
	fprintf(output, "      -d, --daemon\n");
	fprintf(output, "      -b <address>, --bind <address>\n");
	fprintf(output, "      -p <port>, --port <port>\n");
	fprintf(output, "      -t <count>, --threads <count>\n");
	fprintf(output, "      -c <entries>, --cache <entries>\n");
	fprintf(output, "      -u <user>, --user <user>\n");
	fprintf(output, "      -r <directory>, --root <directory>\n");

	if (long_help) {
		fprintf(output, "\n");
		fprintf(output, "  Usage:\n");
		fprintf(output, "      -h (or --help) prints this usage information\n");
		fprintf(output, "\n");
		fprintf(output, "      -d (or --daemon) instructs filed to become a daemon after initializing\n");
		fprintf(output, "                       the listening TCP socket and log files.\n");
		fprintf(output, "\n");
		fprintf(output, "      -b (or --bind) specifies the address to listen for incoming HTTP\n");
		fprintf(output, "                     requests on.  The default value is \"%s\".\n", BIND_ADDR);
		fprintf(output, "\n");
		fprintf(output, "      -p (or --port) specifies the TCP port number to listen for incoming HTTP\n");
		fprintf(output, "                     requests on.  The default is %u.\n", (unsigned int) PORT);
		fprintf(output, "\n");
		fprintf(output, "      -t (or --threads) specifies the number of worker threads to create. Each\n");
		fprintf(output, "                        worker thread can service one concurrent HTTP session.\n");
		fprintf(output, "                        Thus the number of threads created will determine how\n");
		fprintf(output, "                        many simultaneous transfers will be possible. The\n");
		fprintf(output, "                        default is %lu.\n", (unsigned long) THREAD_COUNT);
		fprintf(output, "\n");
		fprintf(output, "      -c (or --cache) specifies the number of file information cache entries\n");
		fprintf(output, "                      to allocate.  Each cache entry holds file information as\n");
		fprintf(output, "                      well as an open file descriptor to the file, so resource\n");
		fprintf(output, "                      limits (i.e., ulimit) should be considered.  This should\n");
		fprintf(output, "                      be a prime number for ideal use with the lookup method.\n");
		fprintf(output, "                      The default is %lu.\n", (unsigned long) CACHE_SIZE);
		fprintf(output, "\n");
		fprintf(output, "      -u (or --user) specifies the user to switch user IDs to before servicing\n");
		fprintf(output, "                     requests.  The default is not change user IDs.\n");
		fprintf(output, "\n");
		fprintf(output, "      -r (or --root) specifies the directory to act as the root directory for\n");
		fprintf(output, "                     the file server.  If this option is specified, chroot(2)\n");
		fprintf(output, "                     is called.  The default is not change root directories,\n");
		fprintf(output, "                     that is, the \"/\" directory is shared out.  This will\n");
		fprintf(output, "                     likely be a security issue, so this option should always\n");
		fprintf(output, "                     be used.\n");
	}

	return;
}

/* Add a getopt option */
static void filed_getopt_long_setopt(struct option *opt, const char *name, int has_arg, int val) {
	opt->name     = name;
	opt->has_arg  = has_arg;
	opt->flag     = NULL;
	opt->val      = val;

	return;
}

/* Resolve a username to a UID */
static int filed_user_lookup(const char *user, uid_t *user_id) {
	char *next;
	uid_t user_id_check;
#ifndef FILED_NO_GETPWNAM
	struct passwd *ent;

	ent = getpwnam(user);
	if (ent != NULL) {
		*user_id = ent->pw_uid;

		return(0);
	}
#endif

	user_id_check = strtoull(user, &next, 10);
	if (next == NULL) {
		return(1);
	}

	if (next[0] != '\0') {
		return(1);
	}

	*user_id = user_id_check;

	return(0);
}

/* Daemonize */
static int filed_daemonize(void) {
	pid_t setsid_ret, fork_ret;
	int chdir_ret, dup2_ret;
	int fd_in, fd_out;

	chdir_ret = chdir("/");
	if (chdir_ret != 0) {
		return(1);
	}

	fork_ret = fork();
	if (fork_ret < 0) {
		return(1);
	}

	if (fork_ret > 0) {
		/* Parent */
		waitpid(fork_ret, NULL, 0);

		exit(EXIT_SUCCESS);
	}

	/* Child */
	if (fork() != 0) {
		/* Child */
		exit(EXIT_SUCCESS);
	}

	/* Grand child */
	setsid_ret = setsid();
	if (setsid_ret == ((pid_t) -1)) {
		return(1);
	}

	fd_in = open("/dev/null", O_RDONLY);
	fd_out = open("/dev/null", O_WRONLY);
	if (fd_in < 0 || fd_out < 0) {
		return(1);
	}

	dup2_ret = dup2(fd_in, STDIN_FILENO);
	if (dup2_ret != STDIN_FILENO) {
		return(1);
	}

	dup2_ret = dup2(fd_out, STDOUT_FILENO);
	if (dup2_ret != STDOUT_FILENO) {
		return(1);
	}

	dup2_ret = dup2(fd_out, STDERR_FILENO);
	if (dup2_ret != STDERR_FILENO) {
		return(1);
	}

	close(fd_in);
	close(fd_out);

	return(0);
}

/* Run process */
int main(int argc, char **argv) {
	struct option options[9];
	const char *bind_addr = BIND_ADDR, *newroot = NULL;
	uid_t user = 0;
	int port = PORT, thread_count = THREAD_COUNT;
	int cache_size = CACHE_SIZE;
	int init_ret, chroot_ret, setuid_ret, lookup_ret, chdir_ret;
	int setuid_enabled = 0, daemon_enabled = 0;
	int ch;
	int fd;

	/* Process arguments */
	filed_getopt_long_setopt(&options[0], "port", required_argument, 'p');
	filed_getopt_long_setopt(&options[1], "threads", required_argument, 't');
	filed_getopt_long_setopt(&options[2], "cache", required_argument, 'c');
	filed_getopt_long_setopt(&options[3], "bind", required_argument, 'b');
	filed_getopt_long_setopt(&options[4], "user", required_argument, 'u');
	filed_getopt_long_setopt(&options[5], "root", required_argument, 'r');
	filed_getopt_long_setopt(&options[6], "help", no_argument, 'h');
	filed_getopt_long_setopt(&options[7], "daemon", no_argument, 'd');
	filed_getopt_long_setopt(&options[8], NULL, 0, 0);
	while ((ch = getopt_long(argc, argv, "p:t:c:b:u:r:hd", options, NULL)) != -1) {
		switch(ch) {
			case 'p':
				port = atoi(optarg);
				break;
			case 't':
				thread_count = atoi(optarg);
				break;
			case 'c':
				cache_size = atoi(optarg);
				break;
			case 'b':
				bind_addr = strdup(optarg);
				break;
			case 'u':
				setuid_enabled = 1;
				lookup_ret = filed_user_lookup(optarg, &user);
				if (lookup_ret != 0) {
					filed_print_help(stderr, 0, "Invalid username specified");

					return(1);
				}
				break;
			case 'r':
				newroot = strdup(optarg);
				break;
			case 'd':
				daemon_enabled = 1;
				break;
			case '?':
			case ':':
				filed_print_help(stderr, 0, NULL);

				return(1);
			case 'h':
				filed_print_help(stdout, 1, NULL);

				return(0);
		}
	}

	/* Create listening socket */
	fd = filed_listen(bind_addr, port);
	if (fd < 0) {
		perror("filed_listen");

		return(1);
	}

	/* Chroot, if appropriate */
	if (newroot) {
		chdir_ret = chdir(newroot);
		if (chdir_ret != 0) {
			perror("chdir");

			return(1);
		}

		chroot_ret = chroot(".");
		if (chroot_ret != 0) {
			perror("chroot");

			return(1);
		}
	}

	/* Drop privileges, if appropriate */
	if (setuid_enabled) {
		setuid_ret = setuid(user);
		if (setuid_ret != 0) {
			perror("setuid");

			return(1);
		}
	}

	/* Become a daemon */
	if (daemon_enabled) {
		filed_daemonize();
	}

	/* Initialize */
	init_ret = filed_init(cache_size);
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
