#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

/* 状态信息统一走 stderr，不影响重定向；不用 stdio，省体积 */
static int quiet;

static void ew(const char *s) {
  if (!quiet)
    write(STDERR_FILENO, s, strlen(s));
}

static void ew_num(unsigned long v) {
  char b[24];
  int i = 0;
  if (quiet)
    return;
  if (!v) {
    write(STDERR_FILENO, "0", 1);
    return;
  }
  while (v) {
    b[i++] = (char)('0' + v % 10);
    v /= 10;
  }
  while (i)
    write(STDERR_FILENO, &b[--i], 1);
}

int download(int writefd, char *hostname, char *uri, int port,
             unsigned long *nbytes, int *http_code) {
  struct hostent *he = gethostbyname(hostname);
  *nbytes = 0;
  *http_code = 0;
  if (!he) {
    ew("uget: cannot resolve ");
    ew(hostname);
    ew("\n");
    return ERR_GETADDRINFO;
  }

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    ew("uget: socket() failed\n");
    return ERR_SOCKET;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  memcpy(&addr.sin_addr, he->h_addr, he->h_length);

  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(s);
    ew("uget: connect ");
    ew(hostname);
    ew(":");
    ew_num((unsigned long)port);
    ew(" failed\n");
    return ERR_CONNECT;
  }

  char buf[4096];
  /* 请求行 + Host 头拼进 4096 栈缓冲：超长 URL 会撑爆栈，先做长度校验 */
  if (5 + (uri ? strlen(uri) : 0) + strlen(hostname) + 40 > sizeof(buf)) {
    write(STDERR_FILENO, "uget: url too long\n", 19);
    return ERR_USAGE;
  }
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
  if (nsent != tosent) {
    close(s);
    ew("uget: send failed\n");
    return ERR_SEND;
  }

  int header = 1;
  int nrecvd;
  while ((nrecvd = recv(s, buf, sizeof(buf), 0)) > 0) {
    char *ptr = buf;
    if (header) {
      ptr = strstr(buf, "\r\n\r\n");
      if (!ptr)
        continue;

      int rcode = get_http_respcode(buf);
      if (rcode / 100 != 2) {
        ew("uget: HTTP ");
        ew_num((unsigned long)rcode);
        ew("\n");
        close(s);
        return rcode / 100 * 10 + rcode % 10;
      }
      *http_code = rcode;

      header = 0;
      ptr += 4;
      nrecvd -= ptr - buf;
    }
    if (nrecvd > 0) {
      if (write(writefd, ptr, nrecvd) != nrecvd) {
        ew("uget: write failed\n");
        close(s);
        return ERR_GENERAL;
      }
      *nbytes += (unsigned long)nrecvd;
    }
  }
  close(s);
  if (nrecvd < 0) {
    ew("uget: recv failed\n");
    return ERR_GENERAL;
  }

  return 0;
}

static const char usage_text[] =
    "uget [-q] [-o FILE] [-P DIR] HOST[:PORT][/PATH]\n"
    "\n"
    "  -o FILE  save as FILE (path allowed, renames)\n"
    "  -P DIR   save into DIR, keep URL name (mkdir if missing)\n"
    "  -q       no status lines (stderr)\n"
    "  -h       this help\n"
    "\n"
    "out: ./<URL tail> or index.html; port: HOST[:PORT] (80); http only.\n"
    "status goes to stderr, the body is written straight to the file.\n"
    "\n"
    "eg: uget 10.0.0.1/a.tgz | uget 10.0.0.1:8000/a.tgz | uget -o /tmp/ug 10.0.0.1/ug\n"
    "    uget -P /tmp/dl 10.0.0.1/ug\n"
    "exit: 0 ok, 1 general, 2 socket, 3 dns, 4 connect, 5 send, 6 usage;\n"
    "4xx/5xx -> two digits (404 -> 44).\n";

static int usage_error(void) {
  write(STDERR_FILENO, "uget: try --help\n", 17);
  return ERR_USAGE;
}

int main(int argc, char **argv) {
  int port = 80;
  char *out_name = NULL;
  char *out_dir = NULL;
  int i = 1;

  for (; i < argc; i++) {
    char *a = argv[i];
    if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      write(STDOUT_FILENO, usage_text, sizeof(usage_text) - 1);
      return 0;
    }
    if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
      quiet = 1;
      continue;
    }
    if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
      if (i + 1 >= argc || !*argv[i + 1])
        return usage_error();
      out_name = argv[++i];
      continue;
    }
    if (!strcmp(a, "-P") || !strcmp(a, "--directory")) {
      if (i + 1 >= argc || !*argv[i + 1])
        return usage_error();
      out_dir = argv[++i];
      continue;
    }
    break;
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
      port = (int)p;
    }
  }

  /* 输出路径：-o 直接用（可含目录、可改名）；-P 指定目录并保留 URL 尾名；
     都不给则落在当前目录、文件名取 URL 尾名（裸主机/目录结尾 -> index.html） */
  char *tail;
  if (uri && *uri && uri[strlen(uri) - 1] != '/') {
    char *slash = strrchr(uri, '/');
    tail = slash ? slash + 1 : uri;
  } else {
    tail = "index.html";
  }

  static char out_path[4096];
  if (out_name) {
    /* 原样使用 */
  } else if (out_dir) {
    size_t dl = strlen(out_dir), tl = strlen(tail);
    int sep = (dl && out_dir[dl - 1] == '/') ? 0 : 1;
    if (dl + (size_t)sep + tl + 1 > sizeof(out_path)) {
      write(STDERR_FILENO, "uget: path too long\n", 20);
      return ERR_GENERAL;
    }
    memcpy(out_path, out_dir, dl);
    if (sep)
      out_path[dl++] = '/';
    memcpy(out_path + dl, tail, tl + 1);
    mkdir(out_dir, 0755); /* 已存在则整调用失败，忽略 */ 
    out_name = out_path;
  } else {
    out_name = tail;
  }

  int fd = STDOUT_FILENO;
  int out_fd = -1;
  char part[4096];
  part[0] = 0;
  {
    /* 先写 FILE.part，成功后 rename，失败则删掉 .part：
       既不破坏同名旧文件，也不留下残缺文件 */
    size_t nl = strlen(out_name);
    if (nl + 6 > sizeof(part)) {
      write(STDERR_FILENO, "uget: filename too long\n", 24);
      return ERR_GENERAL;
    }
    memcpy(part, out_name, nl);
    memcpy(part + nl, ".part", 6);
    fd = open(part, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      write(STDERR_FILENO, "uget: cannot open output file\n", 30);
      return ERR_GENERAL;
    }
    out_fd = fd;
  }

  unsigned long nbytes = 0;
  int hcode = 0;
  ew("uget: GET http://");
  ew(hostname);
  if (port != 80) {
    ew(":");
    ew_num((unsigned long)port);
  }
  if (uri) {
    ew("/");
    ew(uri);
  }
  ew("\n");

  int ret = download(fd, hostname, uri, port, &nbytes, &hcode);
  if (out_fd >= 0) {
    close(out_fd);
    if (ret)
      unlink(part);
    else if (rename(part, out_name) != 0) {
      ew("uget: cannot rename to ");
      ew(out_name);
      ew("\n");
      unlink(part);
      ret = ERR_GENERAL;
    }
  }
  if (!ret) {
    ew("uget: ");
    ew_num((unsigned long)hcode);
    ew(" OK, ");
    ew_num(nbytes);
    ew(" bytes -> ");
    ew(out_name);
    ew("\n");
  }

  return ret;
}
