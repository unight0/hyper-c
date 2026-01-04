// For accept4
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <glob.h>

/*
 * TODO
 * + DONE _Allow blacklisting directories (file wildcards?)_
 * + DONE _Pre-load files and re-load them if changed -> will reduce load_
 * + NOT NEEDED _Poll in a smarter way -- do not re-create the pollfd structure (?)_
 * + DONE _Return 405 Method Not Allowed instead of empty response_
 * + DONE _HTTPS Serving. Use OpenSSL_
 * + Allow a config file that can be used to specify command-line options, e.g.
 *   dir=/bla/bla/bla
 *   key=mykey.key
 *   cert=mycert.crt
 *   port=4380
 *   sport=4330
 *   ...
 * Additionals (*)
 * + Allow routing methods through CGIs
 * + FastCGI support
 * */

#define SERVER_NAME "HyperC"
#define DEFAULT_DIRECTORY_SERVE "index.html"

#define LOG_DEBUG 2
#define LOG_INFO  1
#define LOG_ERROR 0
#define LOG_NONE  -1

int enforce_loglevel = LOG_INFO;

const char*
loglevel_tostr(int loglevel) {
    switch (loglevel) {
        case LOG_DEBUG:
            return "DEBUG";
        case LOG_INFO:
            return "INFO";
        case LOG_ERROR:
            return "ERROR";
    }

    assert(0 && "Invalid log level specified");
}

char *
timestr(void) {
    static char timebuf[256];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(timebuf, 256, "%T", tm);
    return timebuf;
}

void
message(int loglevel, const char *fmt, ...) {
    if (loglevel > enforce_loglevel) return;
    va_list vl;
    va_start(vl, fmt);
    printf("[%s %s] ", timestr(), loglevel_tostr(loglevel));
    vprintf(fmt, vl);
    putchar('\n');
    va_end(vl);
}

//uint64_t
//milliseconds(void) {
//    static struct timespec ts;
//    clock_gettime(CLOCK_MONOTONIC, &ts);
//    return (uint64_t)ts.tv_sec * 1000
//        +  (uint64_t)ts.tv_nsec / 1000000;
//}


char **blacklist = NULL;
size_t blacklist_len = 0;

char *
resource_abspath(const char *resource, const char *dir) {
    size_t relpath_sz = strlen(dir) + strlen(resource) + 2;
    char relpath[relpath_sz];
    snprintf(relpath, relpath_sz, "%s/%s", dir, resource);

    char *path = realpath(relpath, NULL);
    if (path == NULL) {
        printf("Could not find the absolute path of '%s'\n", relpath);
        perror("realpath()");
        return NULL;
    }

    return path;
}

int
is_blacklisted(const char *str, const char *dir) {
    char *strpath = resource_abspath(str, dir);
    if (strpath == NULL) return 0;

    for (size_t i = 0; i < blacklist_len; i++) {
        if (!strcmp(blacklist[i], strpath)) {
            free(strpath);
            return 1;
        }
    }
    free(strpath);
    return 0;
}

void
blacklist_append(char *path) {
    blacklist_len++;
    blacklist = realloc(blacklist, blacklist_len * sizeof(char*));
    blacklist[blacklist_len - 1] = path;
}

struct file_cache {
    char *filepath;
    char *file_contents;
    time_t last_edit;
};

struct file_cache *filecache = NULL;
size_t filecache_size = 0;

void
free_filecache(void) {
    for (size_t i = 0; i < filecache_size; i++) {
        if (filecache[i].file_contents != NULL) free(filecache[i].file_contents);
        if (filecache[i].filepath != NULL) free(filecache[i].filepath);
    }
    free(filecache);
}

struct file_cache*
filecache_find(const char *filepath) {
    for (size_t i = 0; i < filecache_size; i++) {
        if (!strcmp(filepath, filecache[i].filepath))
            return &filecache[i];
    }
    return NULL;
}

void
file_cache_append(const char *filepath, char *file, time_t last_edit) {
    char *filepath_alloc = malloc(strlen(filepath) + 1);
    strcpy(filepath_alloc, filepath);
    filecache_size++;
    filecache = realloc(filecache, filecache_size * sizeof(struct file_cache));
    filecache[filecache_size - 1] = 
        (struct file_cache){
            filepath_alloc, file, last_edit
        };
}

int
resource_glob(glob_t *glb, const char *resource, const char *dir) {
    size_t relpath_sz = strlen(dir) + strlen(resource) + 2;
    char relpath[relpath_sz];
    snprintf(relpath, relpath_sz, "%s/%s", dir, resource);

    if (glob(relpath, GLOB_NOSORT|GLOB_TILDE, NULL, glb) == GLOB_NOMATCH) {
        perror("glob()");
        return 1;
    }

    return 0;
}

void
parse_blacklist(char *str, const char *dir) {
    char *tok = strtok(str, ":");
    if (tok == NULL) {
        printf("Could not parse the blacklist!\n");
        exit(1);
    }
    do {
        glob_t glob;
        if (resource_glob(&glob, tok, dir)) return;
        for (size_t i = 0; i < glob.gl_pathc; i++) {
            blacklist_append(realpath(glob.gl_pathv[i], NULL));
        }
        globfree(&glob);
    } while((tok = strtok(NULL, ":")) != NULL);
}

void
free_blacklist(void) {
    for (size_t i = 0; i < blacklist_len; i++) {
        free(blacklist[i]);
    }
}


void
snprintf_ip(char *str, size_t n, long ip) {
    snprintf(str, n, "%ld.%ld.%ld.%ld",
            (ip & 0xFF000000) >> 24,
            (ip & 0xFF0000) >> 16,
            (ip & 0xFF00) >> 8,
            ip & 0xFF);
}

const char*
ipstr(long ip) {
    static char buffer[16];
    snprintf_ip(buffer, 16, ip);
    return buffer;
}

struct peer {
    pid_t sock;
    SSL *ssl;
    long ip;
    short port;
    int secure;
    int closed;
};

struct peer
accept_conn(pid_t sock) {
    assert(sock != -1);
    struct sockaddr_in peer_addr;
    socklen_t peer_socklen = sizeof(struct sockaddr_in);
    int peer = accept4(sock,
            (struct sockaddr*) &peer_addr,
            &peer_socklen, SOCK_NONBLOCK);

    if (peer == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return (struct peer){-1,NULL,0,0,0,0};
        if (errno == ECONNABORTED) {
            message(LOG_INFO, "connection was aborted");
        }
        perror("accept()");
        exit(1);
    }

    message(LOG_INFO,
            "accepted peer %s:%hu",
            ipstr(peer_addr.sin_addr.s_addr),
            peer_addr.sin_port);

    return (struct peer) {
        peer, 
        NULL,
        htonl(peer_addr.sin_addr.s_addr), 
        htons(peer_addr.sin_port),
        0,
        0
    };
}

struct peer
accept_secure_conn(SSL_CTX *ctx, pid_t sock) {
    assert(sock != -1);
    assert(ctx != NULL);

    struct peer peer = accept_conn(sock);
    //printf("Here1\n");
    if (peer.sock == -1) return peer;

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, peer.sock);
    
    int ret;
try_again:
    if ((ret = SSL_accept(ssl)) <= 0) {
        if (SSL_get_error(ssl, ret) == SSL_ERROR_WANT_READ) goto try_again;
        ERR_print_errors_fp(stdout);
        close(peer.sock);
        return (struct peer) {-1,NULL,0,0,0,0};
    }

    message(LOG_DEBUG, "connection with %s is secure", ipstr(peer.ip));
    peer.ssl = ssl;
    peer.secure = 1;
    return peer;
}

struct peer*
accept_conns(pid_t sock, struct peer *peers, size_t *peers_len) {
    while(1) {
        struct peer peer = accept_conn(sock);
        if (peer.sock == -1) break;
    
        (*peers_len)++;
        peers = realloc(peers, sizeof(struct peer) * *peers_len);
        assert(peers != NULL);
        peers[*peers_len-1] = peer;
    }
    return peers;
}

struct peer*
accept_secure_conns(SSL_CTX *ctx, pid_t sock, struct peer *peers, size_t *peers_len) {
    while(1) {
        struct peer peer = accept_secure_conn(ctx, sock);
        if (peer.sock == -1) break;
    
        (*peers_len)++;
        peers = realloc(peers, sizeof(struct peer) * *peers_len);
        assert(peers != NULL);
        peers[*peers_len-1] = peer;
    }
    return peers;
}
/*
 * Removes the peers that have closed=1 property set
 * */
struct peer*
cleanup_peers(struct peer *peers, size_t *peers_len) {
    if (!peers_len) return peers;
    struct peer *new_peers = malloc(sizeof(struct peer) * *peers_len);
    size_t new_peers_len = 0;
    for (size_t i = 0; i < *peers_len; i++) {
        if (peers[i].closed) {
            close(peers[i].sock);
            continue;
        }
        new_peers_len++;
        new_peers = realloc(new_peers, sizeof(struct peer) * new_peers_len);
        assert(new_peers != NULL);
        new_peers[new_peers_len-1] = peers[i];
    }
    free(peers);
    *peers_len = new_peers_len;
    return new_peers;
}

int
is_prefix(const char *str, const char *prfx) {
    if (strlen(str) < strlen(prfx)) return 0;
    return !strncmp(str, prfx, strlen(prfx));
}

char*
read_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
        message(LOG_DEBUG, "fopen(): %s", strerror(errno));
        return NULL;
    }

    char *file = NULL;
    size_t file_size = 0;

    while (!ferror(f) && !feof(f)) {
        int ch = getc(f);
        file_size++;
        file = realloc(file, file_size);
        file[file_size - 1] = (char) ch;
    }

    file[file_size - 1] = 0;

    fclose(f);

    return file;
}

time_t
last_edit_time(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == -1) return 0;
    return st.st_mtime;
}

char *
get_file(const char *filepath) {
    time_t last_edit = last_edit_time(filepath);
    struct file_cache *cache = filecache_find(filepath);

    if (cache != NULL) {
        if (last_edit <= cache->last_edit) return cache->file_contents;

        cache->last_edit = last_edit;
        free(cache->file_contents);
        cache->file_contents = read_file(filepath);
        return cache->file_contents;
    }

    char *file = read_file(filepath);
    file_cache_append(filepath, file, last_edit);
    return file;
}


char *
get_extension(char *filepath) {
    char *pos = filepath + strlen(filepath);
    for (; pos > filepath && *pos != '.'; pos--);
    return pos;
}

const char *
get_content_type(const char *extension) {
    if (!strcmp(extension, ".css")) {
        return "text/css";
    }
    if (!strcmp(extension, ".html")) {
        return "text/html";
    }
    if (!strcmp(extension, ".php")) {
        return "text/html";
    }
    return "text/plain";
}

char *
get_header(int code, const char *method, const char *content, char *filepath) {
    char *extra_headers = "";
    if (!strcmp(method, "OPTIONS") || code == 405) {
        extra_headers = "Allow: OPTIONS, GET, HEAD, POST\r\n";
    }

    char content_info[512] = "";
    if (content != NULL && filepath != NULL) {
        char *extension = get_extension(filepath);
        const char *content_type = get_content_type(extension);
        snprintf(content_info, 512,
                "Content-Type: %s; charset=UTF-8\r\n"
                "Content-Length: %ld\r\n",
                 content_type, strlen(content));
    }

    static char buffer[1025];    
    buffer[1024] = 0;
    snprintf(buffer, 1024,
    //"Connection: close\r\n"
    "%s"
    "Server: "SERVER_NAME"\r\n"
    //"Date: Fri, 1 Jan 1999 12:00:00 GMT\r\n"
    //"Last-Modified: Fri, 1 Jan 1998 11:00:00 GMT\r\n"
    "%s",
    extra_headers, content_info);
    return buffer;
}

#include <ctype.h>

char*
trim_left(char *str) {
    while (isspace(*str)) str++;
    return str;
}

char*
trim_right(char *str) {
    char *end = strlen(str) + str - 1;
    while (end > str && isspace(*end)) end--;
    if (end != str) *(end + 1) = '\0';
    return str;
}

char*
strip(char *str) {
    return trim_right(trim_left(str));
}

struct request_header {
    char *name;
    char *value;
};
struct request {
    int valid;
    char *method;
    char *target;
    char *query;
    char *ver;
    char *content;
    struct request_header *headers;
    size_t num_headers;
};

struct request
parse_request(char *rqstr, const struct peer *who) {
    assert(rqstr != NULL);
    const char *ip_str = ipstr(who->ip);
    struct request req;
    req.valid = 0;
    req.headers = NULL;

    req.content = strstr(rqstr, "\r\n\r\n");
    if (req.content != NULL) {
        *req.content = '\0';
        req.content += 4;
    }

    req.method = strtok(rqstr, " \r\n");
    if (req.method == NULL) {
        message(LOG_ERROR, "malformed request from %s -- no method", ip_str);
        return req;
    }

    req.target = strtok(NULL, " \r\n");
    if (req.target == NULL) {
        message(LOG_ERROR, "malformed '%s' request from %s -- no target", req.method, ip_str);
        return req;
    }

    req.query = strchr(req.target, '?');
    if (req.query != NULL) {
        *req.query = 0;
        req.query++;
    }

    req.ver = strtok(NULL, " \r\n");
    if (req.ver == NULL) {
        message(LOG_ERROR, "malformed '%s' request from %s -- no version", req.method, ip_str);
        return req;
    }

    req.num_headers = 0;
    req.headers = NULL;
    char *tok;
    while ((tok = strtok(NULL, ":")) != NULL) {
        req.num_headers++;
        req.headers = realloc(req.headers, req.num_headers * sizeof(struct request_header));
        struct request_header *hdr = &req.headers[req.num_headers - 1];
        hdr->name = strip(tok);
        hdr->value = strtok(NULL, "\r\n");
        if (hdr->value == NULL) {
            message(LOG_ERROR,
              "malformed '%s' request from %s -- header '%s' has no value",
              req.method, ip_str, hdr->name);
            free(req.headers);
            return req;
        }
        hdr->value = strip(hdr->value);
    }
    req.valid = 1;
    return req;
}

char*
header_by_name(struct request req, const char *name) {
    if (req.headers == NULL) return NULL;
    for (size_t i = 0; i < req.num_headers; i++) {
        if (!strcmp(req.headers[i].name, name))
            return req.headers[i].value;
    }
    return NULL;
}

const char*
response_by_code(int response_code) {
    switch (response_code) {
        case 404:
            return "404 Not Found";
        case 405:
            return "405 Method Not Allowed";
        case 200:
            return "200 OK";
        case 204:
            return "204 No Content";
    }
    message(LOG_ERROR, "Invalid response code %d", response_code);
    return "404 Not Found";
}

void
reply(struct peer *peer,
      int response_code,
      const char *method,
      const char *ver,
      const char *content,
      char *filepath,
      int send_content) {
    const char *response = response_by_code(response_code);
    const char *header = get_header(response_code, method, content, filepath);

    size_t content_len = 0;
    if (content != NULL) content_len = strlen(content);
    size_t total_len = strlen(response) + strlen(header) + content_len + 16;
    char buffer[total_len];

    snprintf(buffer, total_len, "%s %s\r\n%s\r\n%s", ver, response, header, send_content ? content : "");

    message(LOG_INFO, "sending %d response to %s", response_code, ipstr(peer->ip));

    if (peer->secure) {
        if (SSL_write(peer->ssl, buffer, strlen(buffer)) <= 0) {
            ERR_print_errors_fp(stdout);
            peer->closed = 1;
        }
    }
    else {
        if (send(peer->sock, buffer, strlen(buffer), 0) < 0) {
            perror("send()");
            peer->closed = 1;
        }
    }
}

void
serve_head_request(struct request req, struct peer *peer, const char *rootdir) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts to access (HEAD) '%s', ver = '%s'", ip_str, req.target, req.ver);
    
    char filepath[strlen(req.target) + strlen(rootdir) + 2];
    snprintf(filepath, strlen(req.target) + strlen(rootdir) + 2, "%s/%s", rootdir, req.target);
    char *file = get_file(filepath);

    if (file == NULL) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        return;
    }

    reply(peer, 200, req.method, req.ver, file, filepath, 0);
}

void
serve_get_request(struct request req, struct peer *peer, const char *rootdir) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts to access '%s', ver = '%s'", ip_str, req.target, req.ver);

    char filepath[strlen(req.target) + strlen(rootdir) + 2];
    snprintf(filepath, strlen(req.target) + strlen(rootdir) + 2, "%s/%s", rootdir, req.target);
    char *file = get_file(filepath);

    if (file == NULL) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        return;
    }

    reply(peer, 200, req.method, req.ver, file, filepath, 1);
}

void
serve_post_request(struct request req, struct peer *peer, const char *rootdir) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts to POST at '%s', ver = '%s'", ip_str, req.target, req.ver);

    char filepath[strlen(req.target) + strlen(rootdir) + 2];
    snprintf(filepath, strlen(req.target) + strlen(rootdir) + 2, "%s/%s", rootdir, req.target);
    char *file = get_file(filepath);

    if (file == NULL) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        return;
    }

    reply(peer, 200, req.method, req.ver, file, filepath, 1);

    message(LOG_INFO, "%s POSTed '%s' at %s", ip_str, req.content, req.target);
}

void
serve_options_request(struct request req, struct peer *peer) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts OPTIONS at '%s' (will answer for * regardless), ver = '%s'", ip_str, req.target, req.ver);

    reply(peer, 204, req.method, req.ver, NULL, NULL, 0);
}

int
is_dir(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == -1) {
        perror("stat()");
        return 0;
    }
    return S_ISDIR(st.st_mode);
}

void
serve_peer(struct peer *peer, const char *rootdir)  {
    assert(peer->sock != -1);
    //TODO: re-write this so there's no possible message cutoff
    //NOTE: why would a HTTP request be more that 4096 bytes, though?
    static char buffer[4096];
    memset(buffer, 0, 4096);
    ssize_t got;

    if (peer->secure)
        got = SSL_read(peer->ssl, buffer, 4096);
    else
        got = recv(peer->sock, buffer, 4096, 0);

    if (!got) {
        peer->closed = 1;
        return;
    }
    if (!peer->secure && got == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        if (errno == ECONNRESET) {
            peer->closed = 1;
            return;
        }
        perror("recv()");
        peer->closed = 1;
        return;
    }
    if (peer->secure && got <= 0) {
        if (SSL_get_error(peer->ssl, got) == SSL_ERROR_WANT_READ) return;
        ERR_print_errors_fp(stdout);
        peer->closed = 1;
        return;
    }
    struct request req = parse_request(buffer, peer);
    if (!req.valid) {
        peer->closed = 1;
        return;
    }
    //printf("Successfully parsed request, m=%s, t=%s, v=%s\n",
    //        req.method, req.target, req.ver);
    //for (size_t i = 0; i < req.num_headers; i++) {
    //    printf("    '%s' -> '%s'\n",
    //            req.headers[i].name,
    //            req.headers[i].value);
    //}
    
    if (req.query != NULL) {
        message(LOG_INFO, "Query is %s\n", req.query);
    }

    // E.g. serve /index.html instead of /
    // Or serve /test/index.html instead of /test/
    size_t target_len = strlen(req.target)
                      + strlen(DEFAULT_DIRECTORY_SERVE)
                      + strlen(rootdir)
                      + 2;
    char target[target_len];
    snprintf(target, target_len, "%s/%s", rootdir, req.target);
    if (is_dir(target)) {
        snprintf(target, target_len, "%s/%s", req.target, DEFAULT_DIRECTORY_SERVE);
        req.target = target;
    }

    if (is_blacklisted(req.target, rootdir)) {
        message(LOG_DEBUG, "'%s' is blacklisted; replying 404", req.target);
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
    }

    else if (!strcmp(req.method, "GET")) {
        message(LOG_DEBUG, "Serving GET '%s' to %s", req.target, ipstr(peer->ip));
        serve_get_request(req, peer, rootdir);
    }

    else if (!strcmp(req.method, "HEAD")) {
        message(LOG_DEBUG, "Serving HEAD '%s' to %s", req.target, ipstr(peer->ip));
        serve_head_request(req, peer, rootdir);
    }

    else if (!strcmp(req.method, "POST")) {
        message(LOG_DEBUG, "Serving POST '%s' to %s", req.target, ipstr(peer->ip));
        serve_post_request(req, peer, rootdir);
    }

    else if (!strcmp(req.method, "OPTIONS")) {
        message(LOG_DEBUG, "Serving OPTIONS '%s' to %s", req.target, ipstr(peer->ip));
        serve_options_request(req, peer);
    }

    else {
        message(LOG_ERROR, "unknown HTTP request received, method = '%s'", req.method);
        reply(peer, 405, req.method, req.ver, NULL, NULL, 0);
        peer->closed = 1;
    }

    char *keepalive = header_by_name(req, "Connect");
    if (keepalive == NULL) {
        peer->closed = 1;
    }
    else if (strcmp(keepalive, "keep-alive")) {
        peer->closed = 1;
    }
    free(req.headers);
}

void
serve_peers(struct peer *peers, size_t peers_len, const char *rootdir) {
    struct pollfd poll_fds[peers_len];

    if (peers_len == 0) return;

    for (size_t i = 0; i < peers_len; i++) {
        poll_fds[i].fd = peers[i].sock;
        poll_fds[i].events = POLLIN;
        poll_fds[i].revents = 0;
    }

    poll(poll_fds, peers_len, 20);
    
    for (size_t i = 0; i < peers_len; i++) {
        if (poll_fds[i].revents & POLLIN)
            serve_peer(&peers[i], rootdir);
    }
}

void
usage(const char *me) {
    printf("USAGE: %s d DIR [p PORT] [s SPORT c CERTFILE k KEYFILE] [h|v|q|qq|b /page1:/page2:...]\n", me);
    printf("Server directory DIR at insecure port PORT and/or\n"
           "at secure port SPORT with certificate file CERTFILE and\n"
           "key file KEYFILE.\n"
           "Options:\n"
           "    h  | help|usage  Print the USAGE page\n"
           "    q  | quiet       Only log errors\n"
           "    qq | silent      Don't log anything\n"
           "    v  | verbose     Be verbose: debug loglevel\n"
           "    b  | blacklist   Blacklist certain resources. Examples:\n"
           "                     %s dir . port 4380 blacklist /main.c:/secret_dat.txt\n"
           "                     %s die . port 4380 blacklist /*.secret:/secret_directory/*\n"
           "    k  | key         Path to the private key PEM file\n"
           "    c  | cert        Path to the server certificate file\n", me, me);
}

pid_t
init_socket(int port, int listen_queue) {
    pid_t sock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0); 
    if (sock == -1) {
        perror("socket()");
        exit(1);
    }
    message(LOG_DEBUG, "acquired a socket with pid %d", sock);
    int reusable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reusable, sizeof(int))) {
        perror("setsockopt()");
        exit(1);
    }
    message(LOG_DEBUG, "set SO_REUSEADDR on the socket");
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in))) {
        perror("bind()");
        exit(1);
    }
    message(LOG_DEBUG, "bound port %d", port);
    if (listen(sock, listen_queue)) {
        perror("listen()");
        exit(1);
    }
    message(LOG_INFO, "listening on port %d", port);
    return sock;
}

SSL_CTX *
create_ssl_context(void) {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    return ctx;
}

void
configure_ssl_context(SSL_CTX *ctx, const char *crt, const char *key) {
    if (SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
}

#include <signal.h>

int
main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        exit(0);
    }
    char *dir = NULL;
    int port = 0, sport = 0;
    char *certfile = NULL, *keyfile = NULL;
    char *blacklist_str = NULL;

    int next_dir = 0,
        next_port = 0,
        next_sport = 0,
        next_blacklist = 0,
        next_cert = 0,
        next_key = 0;
    for (int i = 1; i < argc; i++) {
        if (next_dir) {
            next_dir = 0;
            dir = argv[i];
            continue;
        }
        if (next_port) {
            next_port = 0;
            port = atoi(argv[i]);
            continue;
        }
        if (next_sport) {
            next_sport = 0;
            sport = atoi(argv[i]);
            continue;
        }
        if (next_cert) {
            next_cert = 0;
            certfile = argv[i];
            continue;
        }
        if (next_key) {
            next_key = 0;
            keyfile = argv[i];
            continue;
        }
        if (next_blacklist) {
            next_blacklist = 0;
            sport = atoi(argv[i]);
            continue;
        }
        if (!strcmp(argv[i], "dir")
          ||!strcmp(argv[i], "d")) next_dir = 1;
        else if (!strcmp(argv[i], "port")
          ||!strcmp(argv[i], "p")) next_port = 1;
        else if (!strcmp(argv[i], "sport")
          ||!strcmp(argv[i], "s")) next_sport = 1;
        else if (!strcmp(argv[i], "blacklist")
          ||!strcmp(argv[i], "b")) next_blacklist = 1;
        else if (!strcmp(argv[i], "cert")
          ||!strcmp(argv[i], "c")) next_cert = 1;
        else if (!strcmp(argv[i], "key")
          ||!strcmp(argv[i], "k")) next_key = 1;
        else if (!strcmp(argv[i], "verbose")
          ||!strcmp(argv[i], "v"))
            enforce_loglevel = LOG_DEBUG;
        else if (!strcmp(argv[i], "quiet")
          ||!strcmp(argv[i], "q"))
            enforce_loglevel = LOG_ERROR;
        else if (!strcmp(argv[i], "silent")
          ||!strcmp(argv[i], "qq"))
            enforce_loglevel = LOG_ERROR;
        else if (!strcmp(argv[i], "help") || !strcmp(argv[i], "usage")
          ||!strcmp(argv[i], "h")) {
            usage(argv[0]);
            exit(0);
        }
        else {
            printf("Uknown option '%s'\n", argv[i]);
            usage(argv[0]);
            exit(1);
        }
    }

    if (dir == NULL) {
        printf("You must specify the directory to serve\n");
        usage(argv[0]);
        exit(1);
    }

    if (port == 0 && sport == 0) {
        printf("You must specify the insecure or secure port to serve at\n");
        usage(argv[0]);
        exit(1);
    }

    if (sport && (certfile == NULL || keyfile == NULL)) {
        printf("You must specify the keyfile and certfile if you are using the secure connection over HTTPS\n");
        usage(argv[0]);
        exit(1);
    }

    if (!sport && (certfile != NULL || keyfile != NULL)) {
        printf("You have specified either certfile or keyfile, but not the secure port\n");
        usage(argv[0]);
        exit(1);
    }
    
    if (blacklist_str != NULL)
        parse_blacklist(blacklist_str, dir);

    if (enforce_loglevel != LOG_NONE) {
        printf("HYPER-C HTTP/S SERVER VERSION 0.5\n"
               "---------------------------------\n");
        if (blacklist_len)
            printf("Blacklisted resources:\n");
        for (size_t i = 0; i < blacklist_len; i++) {
            printf("    %s\n", blacklist[i]);
        }
    }

    atexit(free_blacklist);
    atexit(free_filecache);
    signal(SIGPIPE, SIG_IGN);

    const int listen_queue = 1000;

    pid_t sock = -1;
    if (port)
        sock = init_socket(port, listen_queue);

    SSL_CTX *ctx = NULL;
    pid_t ssock = -1;
    if (sport) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ctx = create_ssl_context();
        configure_ssl_context(ctx, certfile, keyfile);
        ssock = init_socket(sport, listen_queue);
    }

    int running = 1;
    struct peer *peers = NULL;
    size_t peers_len = 0;
    while (running) {
        peers = cleanup_peers(peers, &peers_len);
        if (port) {
            peers = accept_conns(sock, peers, &peers_len);
        }
        if (sport) {
            peers = accept_secure_conns(ctx, ssock, peers, &peers_len);
        }
        serve_peers(peers, peers_len, dir);
    }

    if (close(sock)) {
        perror("close()");
        exit(1);
    }
    message(LOG_DEBUG, "closed socket");

    EVP_cleanup();
}
