#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ERR_GENERAL 1
#define ERR_SOCKET 2
#define ERR_GETADDRINFO 3
#define ERR_CONNECT 4
#define ERR_SEND 5
#define ERR_USAGE 6

int get_http_respcode(const char *buf) {
  int i, code = 0;
  while (*buf && *buf != ' ') buf++;
  while (*buf == ' ') buf++;
  for (i = 0; i < 3 && *buf >= '0' && *buf <= '9'; i++)
    code = code * 10 + (*buf++ - '0');
  return code ? code : -1;
}

static char *bufcat(char *dst, const char *src) {
  while (*src) *dst++ = *src++;
  return dst;
}

int download(int writefd, char *hostname, char *uri, int port) {
  struct hostent *he = gethostbyname(hostname);
  if (!he)
    return ERR_GETADDRINFO;

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    return ERR_SOCKET;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  memcpy(&addr.sin_addr, he->h_addr, he->h_length);

  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(s);
    return ERR_CONNECT;
  }

  char buf[4096];
  char *p = bufcat(buf, "GET /");
  if (uri)
    p = bufcat(p, uri);
  p = bufcat(p, " HTTP/1.0\r\nHost: ");
  p = bufcat(p, hostname);
  if (port != 80) {
    char portstr[8];
    char *q = portstr;
    int len = 0, v = port;
    while (v) {
      portstr[len++] = '0' + v % 10;
      v /= 10;
    }
    while (len > 0) *q++ = portstr[--len];
    *q = 0;
    p = bufcat(p, ":");
    p = bufcat(p, portstr);
  }
  p = bufcat(p, "\r\n\r\n");
  int tosent = p - buf;
  int nsent = send(s, buf, tosent, 0);
  if (nsent != tosent)
    return ERR_SEND;

  int header = 1;
  int nrecvd;
  while ((nrecvd = recv(s, buf, sizeof(buf), 0))) {
    char *ptr = buf;
    if (header) {
      ptr = strstr(buf, "\r\n\r\n");
      if (!ptr)
        continue;

      int rcode = get_http_respcode(buf);
      if (rcode / 100 != 2)
        return rcode / 100 * 10 + rcode % 10;

      header = 0;
      ptr += 4;
      nrecvd -= ptr - buf;
    }
    write(writefd, ptr, nrecvd);
  }

  return 0;
}

static const char usage_text[] =
    "uget - minimal HTTP downloader for embedded Linux (HTTP/1.0 only)\n"
    "\n"
    "usage: uget [options] HOST[:PORT][/PATH]\n"
    "       uget [options] run HOST[:PORT][/PATH]\n"
    "\n"
    "options:\n"
    "  -p, --port PORT   connect to PORT (1-65535, default 80), overrides HOST:PORT\n"
    "  -h, --help        show this help and exit\n"
    "\n"
    "host may be written as host, host:port or http://host:port; the path is\n"
    "appended to GET. The response body is copied to stdout, headers dropped.\n"
    "\n"
    "output:\n"
    "  uget never creates files in the current directory: the body goes to\n"
    "  stdout, so save it with your shell:  uget host/file > file\n"
    "  run mode is the exception: it writes /tmp/ugetXXXXXX (mkstemp), chmod\n"
    "  +x, forks and executes it, then unlinks the temp file.\n"
    "\n"
    "exit codes: 0 ok, 1 general, 2 socket, 3 dns, 4 connect, 5 send, 6 usage;\n"
    "HTTP 4xx/5xx are folded to two digits (404 -> 44, 502 -> 52).\n";

static int usage_error(void) {
  write(STDERR_FILENO, "uget: try --help\n", 17);
  return ERR_USAGE;
}

static int parse_port(const char *s, int *out) {
  char *end;
  long p;
  if (!s || !*s)
    return 0;
  p = strtol(s, &end, 10);
  if (*end || p <= 0 || p > 65535)
    return 0;
  *out = (int)p;
  return 1;
}

int main(int argc, char **argv) {
  int port = 80;
  int port_set = 0;
  int run_program = 0;
  int i = 1;

  for (; i < argc; i++) {
    char *a = argv[i];
    if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      write(STDOUT_FILENO, usage_text, sizeof(usage_text) - 1);
      return 0;
    }
    if (!strcmp(a, "-p") || !strcmp(a, "--port")) {
      if (i + 1 >= argc || !parse_port(argv[i + 1], &port))
        return usage_error();
      port_set = 1;
      i++;
      continue;
    }
    if (!strncmp(a, "--port=", 7)) {
      if (!parse_port(a + 7, &port))
        return usage_error();
      port_set = 1;
      continue;
    }
    break;
  }

  if (i < argc && strcmp(argv[i], "run") == 0) {
    run_program = 1;
    i++;
  }
  if (argc - i != 1)
    return usage_error();

  char *hostname = argv[i];
  char *uri = NULL;

  if (strncmp(hostname, "http://", 7) == 0)
    hostname += 7;

  char *url = hostname;
  while (*url) {
    if (*url == '/') {
      *url++ = 0;
      uri = url;
      break;
    }
    url++;
  }

  char *colon = strrchr(hostname, ':');
  if (colon) {
    char *end;
    long p = strtol(colon + 1, &end, 10);
    if (*end == 0 && p > 0 && p < 65536) {
      *colon = 0;
      if (!port_set)
        port = (int)p;
    }
  }

  int fd = STDOUT_FILENO;
  char temfname[] = "/tmp/ugetXXXXXX";
  if (run_program) {
    fd = mkstemp(temfname);
  }

  int ret = download(fd, hostname, uri, port);
  if (ret)
    goto cleanup;

  if (run_program) {
    fchmod(fd, S_IRUSR | S_IXUSR);
    close(fd);
    int child = fork();
    if (child) {
      int wstatus;

      wait(&wstatus);
      ret = WEXITSTATUS(wstatus);
    } else {
      execl(temfname, temfname, (char *)NULL);
      return EXIT_FAILURE;
    }
  }

cleanup:
  if (run_program)
    unlink(temfname);

  return ret;
}
