#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

/* Default values */
#define MAX_FAILURE_COUNT 30
#define PORT 8080
#define THREAD_COUNT 10
#define BIND_ADDR "::"

/* Arguments for worker threads */
struct filed_worker_thread_args {
	int fd;
};

static void filed_init(void) {
	mlockall(MCL_CURRENT | MCL_FUTURE);
}

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

static int filed_logging_thread_init(void) {
	/* XXX:TODO: Unimplemented */
	return(0);
}

static void filed_handle_client(int fd) {
	/* XXX:TODO: Unimplemented */
	fd = fd;
	return;
}

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
			failure_count++;

			continue;
		}

		/* Reset failure count*/
		failure_count = 0;

		/* Handle socket */
		filed_handle_client(fd);

		/* Cleanup */
		close(fd);
	}

	/* XXX:TODO: Report error */
	return(NULL);
}

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

int main(int argc, char **argv) {
	int port = PORT, thread_count = THREAD_COUNT;
	const char *bind_addr = BIND_ADDR;
	int fd;

	/* Ignore */
	argc = argc;
	argv = argv;

	/* Create listening socket */
	fd = filed_listen(bind_addr, port);
	if (fd < 0) {
		return(1);
	}

	/* Become a daemon */
	/* XXX:TODO: Become a daemon */

	/* Initialize */
	filed_init();

	/* Create logging thread */
	/* XXX:TODO: Check for errors */
	filed_logging_thread_init();

	/* Create worker threads */
	/* XXX:TODO: Check for errors */
	filed_worker_threads_init(fd, thread_count);

	/* Wait for threads to exit */
	/* XXX:TODO: Monitor thread usage */
	while (1) {
		sleep(60);
	}

	/* Return in failure */
	return(2);
}
