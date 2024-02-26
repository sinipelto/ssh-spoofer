#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <unistd.h>	 // read(), write(), close()
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define ARGC 7
#define MAXCON 1
#define MAXTRIES 3

#define LEN_SUPP_PROTOS 2
#define SUPP_PROTOS \
	{               \
		"HTTP"      \
	}

#define LEN_SIGNALS 2
#define SIGNALS         \
	{                   \
		SIGINT, SIGTERM \
	}

#define SA struct sockaddr
#define SAI struct sockaddr_in

enum Mode
{
	MODE_NONE = 0,
	SPOOFER,
	DESPOOFER
};

enum Proto
{
	PROTO_NONE = 0,
	HTTP,
	FTP
};

// LONGEST HEADER LENGTH
#define LEN_HEADER_MAX 64

const char http_header_format[] = "GET / HTTP/2\r\nContent-Length: %8ld\r\n\r\n";

volatile bool RUNNING = true;

static void sigh()
{
#ifdef DEBUG
	printf("Caught signal.\n");
#endif
	RUNNING = false;
}

void cleanup(int argc, ...)
{
#ifdef DEBUG
	printf("cleaning up..\n");
#endif
	va_list args;
	va_start(args, argc);

	int *s;
	for (int i = 0; i < argc; i++)
	{
		s = va_arg(args, int *);
		if (s != NULL && *s >= 0)
		{
			shutdown(*s, SHUT_RDWR);
#ifdef DEBUG
			printf("shutdown: %d.\n", *s);
#endif
			close(*s);
#ifdef DEBUG
			printf("closed: %d.\n", *s);
#endif
			*s = -1;
		}
	}

	va_end(args);
}

void help(char *name)
{
	printf("Usage instructions:\n");
	printf("Usage: %s <LISTEN_HOST> <LISTEN_PORT> <TARGET_HOST> <TARGET_PORT> <OPERATION_MODE> <SPOOF_PROTOCOL>\n", name);
	// printf("\n");
	printf("First instance: listener, listens real client, spoofs packets, and sends to forwarder instance. Second instance: Forwarder, listens for listener instance, decodes spoofing, communicates with the real server.\n");
	printf("\n");
	printf("LISTEN_HOST: IPv4 address or hostname to listen for incoming client connection. For second instance, should be e.g. internet iface address or 0.0.0.0. Recommended for listener instance: 127.0.0.1.\n");
	// printf("\n");
	printf("LISTEN_PORT: Port to listen incoming client from. Avoid privileged ports 1-1023, prefer unused ports between 1024-49151. Same applies for both listener and forwarder instances.\n");
	// printf("\n");
	printf("CONNECT_HOST: Target server IPv4 address or hostname to forward packets from incoming client connection. ");
	printf("Should be the second spoofer instance host listening for the spoofed packets or the final target server for forwarder instance. ");
	printf("E.g. server.com for first instance, or 127.0.0.1 for second instance.\n");
	// printf("\n");
	printf("CONNECT_PORT: Port to forward traffic to, or the final destination server for the second instance. Depends on what port the second spoofer instance or final target server is listening to. E.g. 5678 for listener or 22 for forwarder.\n");
	// printf("\n");
	printf("OPERATION_MODE: Which operation mode: spoofing or unspoofing? If in client device, we are spoofing, in the receiver end we are de-spoofing. Allowed values: SPOOFER | DESPOOFER\n");
	printf("SPOOF_PROTOCOL: Protocol to use for spoofing, into which the transferred packets will be spoofed into. Currently supported: HTTP\n");
	// printf("\n");
}

#define HANDLE_READ                                                     \
	if (readlen < 0)                                                    \
	{                                                                   \
		perror("read_client_failed");                                   \
		break;                                                          \
	}                                                                   \
	if (readlen == 0)                                                   \
	{                                                                   \
		printf("client is done sending. closing client and target.\n"); \
		break;                                                          \
	}

static ssize_t read_until(int fd, char *buf, ssize_t len)
{
	ssize_t readlen;
	ssize_t readsz = 0;
	do
	{
		// We need to peak for the header
		// So we dont drop any bytes after the content length
		readlen = read(fd, buf + readsz, len - readsz);
		if (readlen < 0)
		{
			perror("read_client_failed");
			return readlen;
		}
		if (readlen == 0)
		{
#ifdef DEBUG
			printf("client %d is done sending.\n", fd);
#endif
			return readlen;
		}
		readsz += readlen;
	} while (readsz < len);

	return readsz;
}

int main(int argc, char **argv)
{
	printf("SSH spoofer utility:\n");
	printf("VERSION 0.0.1\n(c) Sinipelto 2024\n");
	printf("\n");

	if (argc != ARGC)
	{
		printf("ERROR: Wrong arg count provided. (act: %d != exp: %d)\n", argc, ARGC);
		help(argv[0]);
		return 3;
	}

	char *lhost = argv[1];
	uint16_t lport = atoi(argv[2]);
	char *thost = argv[3];
	uint16_t tport = atoi(argv[4]);
	char *modestr = argv[5];
	char *protostr = argv[6];

	enum Mode mode = MODE_NONE;
	if (strcmp(modestr, "SPOOFER") == 0)
	{
		mode = SPOOFER;
	}
	if (strcmp(modestr, "DESPOOFER") == 0)
	{
		mode = DESPOOFER;
	}
	if (mode == MODE_NONE)
	{
		printf("ERROR: Unrecognized operation mode provided.\n");
		help(argv[0]);
		return 3;
	}

	int cmp = 0;
	char *supp_protos[] = SUPP_PROTOS;
	for (; cmp < LEN_SUPP_PROTOS; cmp++)
	{
		if (strcmp(protostr, supp_protos[cmp]) == 0)
			break;
	}
	if (cmp >= LEN_SUPP_PROTOS)
	{
		printf("ERROR: requested spoof protocol not supported.\n");
		help(argv[0]);
		return 3;
	}

	enum Proto proto = PROTO_NONE;

	if (strcmp(protostr, "HTTP") == 0)
	{
		proto = HTTP;
	}

	if (proto == PROTO_NONE)
	{
		printf("ERROR: Unrecognized spoof protocol provided.\n");
		help(argv[0]);
		return 3;
	}

// init signal handlers
#define SIGC 2
	struct sigaction sigs[LEN_SIGNALS];
	int signals[] = SIGNALS;
	for (unsigned long i = 0; i < sizeof(signals) / sizeof(*signals); i++)
	{
		bzero(&sigs[i], sizeof(*sigs));
		sigs[i].sa_handler = sigh;
		sigs[i].sa_flags = 0;

		sigaction(signals[i], &sigs[i], NULL);
	}
#ifdef DEBUG
	printf("Configuration:\n");
	printf("Mode: %s\n", modestr);
	printf("Local Addr: %s\n", lhost);
	printf("Local Port: %d\n", lport);
	printf("Remote Addr: %s\n", thost);
	printf("Remote Port: %d\n", tport);
	printf("Spoof protocol: %s\n", protostr);
	printf("Http header: '");
	printf(http_header_format, (long int)99999999);
	printf("'\n");
#endif
	char bufin[BUFSIZ + LEN_HEADER_MAX], buf[BUFSIZ + LEN_HEADER_MAX];
	SAI serv, client, sclient;
	int socks = -1, sockc = -1, conn = -1, status = -1;
	ssize_t readlen, writelen, headerlen, contentlen;
	socklen_t lens;

	if (proto == HTTP)
	{
		headerlen = strlen(http_header_format) + 4;
	}

	// socket create and verification
	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (socks == -1)
	{
		perror("ERROR: server_socket_create_failed");
		return socks;
	}
#ifdef DEBUG
	printf("Socket successfully created: %d.\n", socks);
#endif

	// assign IP, PORT
	bzero(&serv, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(lhost);
	serv.sin_port = htons(lport);

	// connect the client socket to server socket
	status = bind(socks, (SA *)&serv, sizeof(serv));
	if (status != 0)
	{
		perror("ERROR: server_bind_failed");
		cleanup(1, &socks);
		return status;
	}
#ifdef DEBUG
	printf("server bind ok.\n");
#endif

	// Allow only one connection at a time
	status = listen(socks, MAXCON);
	if (status != 0)
	{
		perror("ERROR: server_listen_failed");
		cleanup(1, &socks);
		return status;
	}
#ifdef DEBUG
	printf("socket listen configured.\n");
#endif
	// init client struct
	bzero(&sclient, sizeof(sclient));
	sclient.sin_family = AF_INET;
	sclient.sin_addr.s_addr = inet_addr(thost);
	sclient.sin_port = htons(tport);

	short tries;
	while (RUNNING)
	{
		cleanup(2, &conn, &sockc);
#ifdef DEBUG
		printf("waiting for connections..\n");
#endif
		lens = sizeof(client);
		bzero(&client, lens);
		conn = accept(socks, (SA *)&client, &lens);

		if (conn == -1)
		{
			perror("ERROR: accept_client_failed");
			sleep(1);
			continue;
		}
#ifdef DEBUG
		printf("client connected: %d.\n", conn);
		printf("addr: %s\n", inet_ntoa(client.sin_addr));
		printf("port: %hu\n", ntohs(client.sin_port));
#endif
		// Init target server socket
		sockc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (sockc == -1)
		{
			perror("ERROR: client_socket_failed");
			break;
		}
#ifdef DEBUG
		printf("target server socket successfully created: %d.\n", sockc);
#endif
		tries = 0;
		while (tries < MAXTRIES)
		{
			status = connect(sockc, (SA *)&sclient, sizeof(sclient));
			if (status != 0)
			{
				perror("ERROR: connect_target_failed");
				if (++tries < MAXTRIES)
				{
					sleep(2);
				}
				continue;
			}
			break;
		}
		if (tries >= MAXTRIES)
		{
			printf("tries exceeded. failed to connect to target server.\n");
			continue;
		}
#ifdef DEBUG
		printf("target server connected.\n");
#endif
		// Empty all buffers before start exchanging data
		// bzero(bufout, sizeof(bufout));

		// HANDLING SENDING AND RECEIVING HERE
		while (RUNNING)
		{
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(conn, &rfds);
			FD_SET(sockc, &rfds);

			status = select(MAX(conn, sockc) + 1, &rfds, NULL, NULL, NULL);

			if (status == -1)
			{
				perror("select_rfds_failed");
				break;
			}

			if (FD_ISSET(conn, &rfds))
			{
				bzero(bufin, sizeof(bufin));
				bzero(buf, sizeof(buf));

				// if spoofing, we need to add the custom header
				// to the data before sending to the despoofer
				if (mode == SPOOFER)
				{
					readlen = read(conn, bufin, BUFSIZ);
					HANDLE_READ
#ifdef DEBUG
					printf("spoofing from real client to despoofer.\n");
#endif
					if (proto == HTTP)
					{
						// Put to buffer header, and set content length as read content len
						sprintf(buf, http_header_format, readlen);
#ifdef DEBUG
						printf("DATA IN BUFFER: '%.*s'.\n", BUFSIZ, buf);
#endif
					}
					memcpy(buf + headerlen, bufin, readlen);
#ifdef DEBUG
					printf("DATA IN BUFFER: '%.*s'.\n", BUFSIZ, buf);
#endif
					readlen = headerlen + readlen;
				}
				else if (mode == DESPOOFER)
				{
#ifdef DEBUG
					printf("de-spoofing from spoofer to real server.\n");
#endif
					// Read until header read
					readlen = read_until(conn, bufin, headerlen);
					HANDLE_READ

					if (proto == HTTP)
					{
						// Try to scan the header and content length
						if (sscanf(bufin, http_header_format, &contentlen) > 0)
						{
#ifdef DEBUG
							printf("FOUND HEADER!\n");
#endif
							// Read the content length amount from the buffer
							// readlen <= contentlen, should be readlen == contentlen
							readlen = read_until(conn, buf, contentlen);
							HANDLE_READ
						}
						else
						{
							printf("ERROR: Could not find the HTTP header.\n");
							break;
						}
					}
				}
#ifdef DEBUG
				printf("received from client: '%.*s'.\n", BUFSIZ, bufin);
#endif
#ifdef DEBUG
				printf("DATA IN BUFFER: '%.*s'.\n", BUFSIZ, buf);
#endif
				// SEND FROM CLIENT TO TARGET
				// REAL CLIENT TO DESPOOFER
				// DESPOOFER TO REAL SERVER
				writelen = write(sockc, buf, readlen);

				// Can be == 0 if transmitting a quit
				if (writelen < 0)
				{
					perror("ERROR: target_write_failed");
					break;
				}
#ifdef DEBUG
				printf("sent to target: '%.*s'\n", (int)writelen, buf);
#endif
			}

			if (FD_ISSET(sockc, &rfds))
			{
				bzero(bufin, sizeof(bufin));
				bzero(buf, sizeof(buf));

				// If we are spoofer and receiving from client = despoofer
				// We need to remove the header
				// if spoofing, we send the reply from recipient
				// we need to remove the custom header from the data
				if (mode == SPOOFER)
				{
#ifdef DEBUG
					printf("de-spoofing back from remote target to real client.\n");
#endif
					readlen = read_until(sockc, bufin, headerlen);
					HANDLE_READ

					if (proto == HTTP)
					{
						// Try to scan the header and content length
						if (sscanf(bufin, http_header_format, &contentlen) > 0)
						{
							printf("FOUND HEADER!\n");
							// Read the next content length from the socket buffer
							readlen = read_until(sockc, buf, contentlen);
							HANDLE_READ
						}
						else
						{
							printf("ERROR: Could not find the HTTP header.\n");
							break;
						}
					}
				}
				// If we are despoofer, we get normal data from client = real server
				// Just chunk whatever it sends and move on
				// if despoofing, we need to re-add custom header
				// before replying back to client
				else if (mode == DESPOOFER)
				{
#ifdef DEBUG
					printf("spoofing back from real server to remote client.\n");
#endif
					// readlen = len(DATA)
					readlen = read(sockc, bufin, BUFSIZ);
					HANDLE_READ

					// readlen = len(DATA)
					if (proto == HTTP)
					{
						// Copy http header to buffer
						sprintf(buf, http_header_format, readlen);
#ifdef DEBUG
						printf("DATA IN BUFFER: '%.*s'.\n", BUFSIZ, buf);
#endif
					}
					// Else if other proto header

					// Copy src buffer data after header
					memcpy(buf + headerlen, bufin, readlen);
#ifdef DEBUG
					printf("DATA IN BUFFER: '%.*s'.\n", BUFSIZ, buf);
#endif
					// total: header + data
					readlen = headerlen + readlen;
				}
#ifdef DEBUG
				printf("received from target: '%.*s'.\n", BUFSIZ, bufin);
#endif
#ifdef DEBUG
				printf("DATA IN BUFFER: '%.*s'.\n", BUFSIZ, buf);
#endif
				writelen = write(conn, buf, readlen);

				if (writelen < 0)
				{
					perror("ERROR: target_write_failed");
					break;
				}
#ifdef DEBUG
				printf("sent to client: '%.*s'.\n", (int)writelen, buf);
#endif
			}
		}
		cleanup(2, &conn, &sockc);
	}
#ifdef DEBUG
	printf("spoofer closing.\n");
#endif
	cleanup(3, &conn, &socks, &sockc);

	return 0;
}