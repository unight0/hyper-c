#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#define SERVER_NAME "HyperC"

#define LOG_DEBUG 2
#define LOG_INFO  1
#define LOG_ERROR 0

int enforce_loglevel = LOG_DEBUG;

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

void
message(int loglevel, const char *fmt, ...) {
    if (loglevel > enforce_loglevel) return;
    va_list vl;
    va_start(vl, fmt);
    printf("%s: ", loglevel_tostr(loglevel));
    vprintf(fmt, vl);
    putchar('\n');
    va_end(vl);
}

char **blacklist = NULL;
size_t blacklist_len = 0;

int
is_blacklisted(const char *str) {
    for (size_t i = 0; i < blacklist_len; i++) {
        if (!strcmp(blacklist[i], str)) return 1;
    }
    return 0;
}

void
parse_blacklist(char *str) {
    char *tok = strtok(str, ":");
    if (tok == NULL) {
        printf("Could not parse the blacklist!\n");
        exit(1);
    }
    do {
        blacklist_len++;
        blacklist = realloc(blacklist, blacklist_len * sizeof(char*));
        blacklist[blacklist_len - 1] = tok;
    } while((tok = strtok(NULL, ":")) != NULL);
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
    long ip;
    short port;
    int closed;
};

struct peer
accept_conns(pid_t sock) {
    assert(sock != -1);
    struct sockaddr_in peer_addr;
    socklen_t peer_socklen = sizeof(struct sockaddr_in);
    int peer = accept(sock,
            (struct sockaddr*) &peer_addr,
            &peer_socklen);

    if (peer == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return (struct peer){-1,0,0,0};
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
        htonl(peer_addr.sin_addr.s_addr), 
        htons(peer_addr.sin_port),
        0
    };
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
    if (f == NULL) return NULL;

    char *file = NULL;
    size_t file_size = 0;

    while (!ferror(f) && !feof(f)) {
        int ch = getc(f);
        file_size++;
        file = realloc(file, file_size);
        file[file_size - 1] = (char) ch;
    }

    file[file_size - 1] = 0;

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
get_header(const char *method, const char *content, char *filepath) {
    char *extra_headers = "";
    if (!strcmp(method, "OPTIONS")) {
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
    const char *header = get_header(method, content, filepath);

    size_t content_len = 0;
    if (content != NULL) content_len = strlen(content);
    size_t total_len = strlen(response) + strlen(header) + content_len + 16;
    char buffer[total_len];

    snprintf(buffer, total_len, "%s %s\r\n%s\r\n%s", ver, response, header, send_content ? content : "");

    message(LOG_INFO, "sending %d response to %s", response_code, ipstr(peer->ip));
    if (send(peer->sock, buffer, strlen(buffer), 0) < 0) {
        perror("send()");
        peer->closed = 1;
    }
}

void
serve_head_request(struct request req, struct peer *peer, const char *rootdir) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts to access (HEAD) '%s', ver = '%s'", ip_str, req.target, req.ver);
    
    char filepath[strlen(req.target) + strlen(rootdir) + 2];
    snprintf(filepath, strlen(req.target) + strlen(rootdir) + 2, "%s/%s", rootdir, req.target);
    char *file = read_file(filepath);

    if (file == NULL) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        return;
    }

    reply(peer, 200, req.method, req.ver, file, filepath, 0);

    free(file);
}

void
serve_get_request(struct request req, struct peer *peer, const char *rootdir) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts to access '%s', ver = '%s'", ip_str, req.target, req.ver);

    char filepath[strlen(req.target) + strlen(rootdir) + 2];
    snprintf(filepath, strlen(req.target) + strlen(rootdir) + 2, "%s/%s", rootdir, req.target);
    char *file = read_file(filepath);

    if (file == NULL) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        return;
    }

    reply(peer, 200, req.method, req.ver, file, filepath, 1);
    free(file);
}

void
serve_post_request(struct request req, struct peer *peer, const char *rootdir) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts to POST at '%s', ver = '%s'", ip_str, req.target, req.ver);

    char filepath[strlen(req.target) + strlen(rootdir) + 2];
    snprintf(filepath, strlen(req.target) + strlen(rootdir) + 2, "%s/%s", rootdir, req.target);
    char *file = read_file(filepath);

    if (file == NULL) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        return;
    }

    reply(peer, 200, req.method, req.ver, file, filepath, 1);
    free(file);

    message(LOG_INFO, "%s POSTed '%s' at %s", ip_str, req.content, req.target);
}

void
serve_options_request(struct request req, struct peer *peer) {
    const char *ip_str = ipstr(peer->ip);
    message(LOG_INFO, "%s attempts OPTIONS at '%s' (will answer for * regardless), ver = '%s'", ip_str, req.target, req.ver);

    reply(peer, 204, req.method, req.ver, NULL, NULL, 0);
}

void
serve_peer(struct peer *peer, const char *rootdir)  {
    assert(peer->sock != -1);
    //TODO: re-write this so there's no possible message cutoff
    static char buffer[4096];
    memset(buffer, 0, 4096);
    ssize_t got = recv(peer->sock, buffer, 4096, 0);
    if (!got) {
        peer->closed = 1;
        return;
    }
    if (got == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        if (errno == ECONNRESET) {
            peer->closed = 1;
            return;
        }
        perror("recv()");
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

    if (!strcmp(req.target, "/")) {
        if (is_blacklisted("/"))
            reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
        else 
            req.target = "/index.html";
    }

    if (is_blacklisted(req.target)) {
        reply(peer, 404, req.method, req.ver, NULL, NULL, 0);
    }

    else if (!strcmp(req.method, "GET")) {
        serve_get_request(req, peer, rootdir);
    }

    else if (!strcmp(req.method, "HEAD")) {
        serve_head_request(req, peer, rootdir);
    }

    else if (!strcmp(req.method, "POST")) {
        serve_post_request(req, peer, rootdir);
    }

    else if (!strcmp(req.method, "OPTIONS")) {
        serve_options_request(req, peer);
    }

    else {
        message(LOG_ERROR, "unknown HTTP request received, method = '%s'", req.method);
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
    printf("USAGE: %s DIR PORT [-hqQ] [-b /page1:/page2:...]\n", me);
    printf("Serves directory DIR at port PORT\n");
    printf("Options:\n");
    printf("    -h        Print USAGE\n");
    printf("    -q        Only log errors\n");
    printf("    -Q        Don't log anything\n");
    printf("    -b        Blacklist certain resources. Example:\n");
    printf("              %s . 4380 -b /main.c:/secret_data.txt\n", me);
}

int
main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
        exit(0);
    }
    const char *dir = argv[1];
    const int port = atoi(argv[2]);

    int quiet = 0;
    int next_blacklist = 0;
    for (int i = 3; i < argc; i++) {
        if (next_blacklist) {
            next_blacklist = 0;
            parse_blacklist(argv[i]);
            continue;
        }
        if (*argv[i] != '-' || strlen(argv[i]) < 2) {
            printf("Unknown option '%s'\n", argv[i]);
            usage(argv[0]);
            exit(1);
        }
        for (size_t j = 1; j < strlen(argv[i]); j++) {
            if (argv[i][j] == 'q') quiet = 1;
            else if (argv[i][j] == 'Q') quiet = 2;
            else if (argv[i][j] == 'h') {
                usage(argv[0]);
                exit(0);
            }
            else if (argv[i][j] == 'b') {
                next_blacklist = 1;
            }
        }
    }
    enforce_loglevel = LOG_ERROR + 1 - quiet;

    if (!quiet) {
        if (blacklist_len)
            printf("Blacklisted resources:\n");
        for (size_t i = 0; i < blacklist_len; i++) {
            printf("    %s\n", blacklist[i]);
        }
    }

    const int listen_queue = 1000;
    if (!quiet)
        printf("HYPER-C HTTP SERVER VERSION v0.2\n"
               "--------------------------------\n");
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
    int running = 1;
    struct peer *peers = NULL;
    size_t peers_len = 0;
    while (running) {
        peers = cleanup_peers(peers, &peers_len);
        struct peer peer = accept_conns(sock);
        if (peer.sock != -1)  {
            peers_len++;
            peers = realloc(peers, sizeof(struct peer) * peers_len);
            assert(peers != NULL);
            peers[peers_len-1] = peer;
        }
        serve_peers(peers, peers_len, dir);
    }

    if (close(sock)) {
        perror("close()");
        exit(1);
    }
    message(LOG_DEBUG, "closed socket");
}
