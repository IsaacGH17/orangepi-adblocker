/*
 * dnspark - DNS-based ad blocker para Orange Pi (Allwinner H3)
 *
 * Arquitectura: daemon DNS que escucha UDP :53, compara el nombre
 * consultado contra una blocklist cargada en memoria (hash).
 * - bloqueado -> responde 0.0.0.0
 * - permitido -> reenvía a upstream (8.8.8.8) y retransmite la respuesta
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdint.h>

#define DNS_PORT 53
#define UPSTREAM "8.8.8.8"
#define BUF_SIZE 1500
#define DNS_HDR_LEN 12


#define MAX_DOMAINS 65536
static char **table = NULL;
static size_t table_size = MAX_DOMAINS;
static size_t n_blocked = 0;

static volatile sig_atomic_t reload_requested = 0;
static volatile sig_atomic_t running = 1;

static const char *g_blocklist_path = "/etc/dnspark/blocklist";
static const char *g_upstream = UPSTREAM;

/* ------------------------------------------------ log */
static void logmsg(const char *fmt, ...)
{
    va_list ap;
    time_t t = time(NULL);
    struct tm tm;
    char ts[32];
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    va_start(ap, fmt);
    fprintf(stderr, "%s ", ts);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ------------------------------------------------ hash domain set */
static uint64_t fnv1a(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (unsigned char)(*s++);
        h *= 1099511628211ULL;
    }
    return h;
}

static void domain_add(const char *d)
{
    size_t i = fnv1a(d) % table_size;
    while (table[i]) {
        if (strcmp(table[i], d) == 0)
            return;  /* ya está */
        i = (i + 1) % table_size;
    }
    table[i] = strdup(d);
    n_blocked++;
}

static int domain_is_blocked(const char *d)
{
    size_t i = fnv1a(d) % table_size;
    while (table[i]) {
        if (strcmp(table[i], d) == 0)
            return 1;
        i = (i + 1) % table_size;
    }
    return 0;
}

static void domains_free(void)
{
    for (size_t i = 0; i < table_size; i++) {
        free(table[i]);
        table[i] = NULL;
    }
    n_blocked = 0;
}

/* Parser: acepta formato hosts ("0.0.0.0 doubleclick.net") o dominio simple */
static char *extract_domain(char *line)
{
    char *p = line;
    /* saltar prefijo tipo IP si lo hay */
    if (*p == '0' || *p == '1' || *p == '2') { /* "0.0.0.0 ", "127.0.0.1 " */
        while (*p && *p != ' ' && *p != '\t')
            p++;
        while (*p == ' ' || *p == '\t')
            p++;
    }
    /* terminar en primer espacio o '\n' */
    char *end = p;
    while (*end && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r')
        end++;
    *end = '\0';
    if (p == end || *p == '#')
        return NULL;
    return p;
}

static void load_blocklist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        logmsg("no puedo abrir %s: %s", path, strerror(errno));
        return;
    }
    domains_free();
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *d = extract_domain(line);
        if (d && *d)
            domain_add(d);
    }
    fclose(f);
    logmsg("blocklist cargada desde %s: %zu dominios", path, n_blocked);
}

/* ------------------------------------------------ DNS wire helpers */
/* Codifica nombre "a.b.c" a formato DNS: "\x03a\x01b\x01c\x00" */
static size_t encode_qname(const char *name, unsigned char *out, size_t max)
{
    size_t n = 0;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        if (len == 0 || len > 63 || n + len + 1 >= max)
            return 0;
        out[n++] = (unsigned char)len;
        memcpy(out + n, s, len);
        n += len;
        if (!dot) break;
        s = dot + 1;
    }
    out[n++] = 0;
    return n;
}

/* Decodifica qname (sin soportar compression pointers en preguntas nuevas) */
static void decode_qname(const unsigned char *wire, size_t max, char *out, size_t out_sz)
{
    size_t i = 0, o = 0;
    while (i < max) {
        unsigned char len = wire[i++];
        if (len == 0) break;
        if ((len & 0xc0) == 0xc0) break; /* puntero: no debería pasar en query */
        if (o + len + 1 >= out_sz) break;
        if (i + len > max) break;
        memcpy(out + o, wire + i, len);
        o += len;
        i += len;
        if (o + 1 < out_sz)
            out[o++] = '.';
        else
            break;
    }
    if (o > 0 && out[o - 1] == '.')
        o--;
    out[o] = '\0';
    for (char *p = out; *p; p++)
        *p = tolower((unsigned char)*p);
}

/* Construye respuesta A con NXDOMAIN o A=0.0.0.0 sobre la query original */
static size_t build_reply(const unsigned char *query, size_t qlen,
                          unsigned char *resp, size_t resp_max, int nx)
{
    if (qlen < DNS_HDR_LEN) return 0;
    if (qlen >= resp_max) return 0;
    memcpy(resp, query, qlen);
    resp[2] |= 0x80;  /* QR=1 */
    resp[3] |= 0x80;  /* RA=1 */
    resp[3] = (resp[3] & ~0x0F) | (nx ? 0x03 : 0x00);  /* rcode: NXDOMAIN o NOERROR */
    /* rcode ya quedó fijado arriba */
    return qlen;
}

/* Reenvía query a upstream y devuelve la respuesta */
static ssize_t forward_query(const unsigned char *query, size_t qlen,
                             unsigned char *resp, size_t resp_max)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in up = {0};
    up.sin_family = AF_INET;
    up.sin_port = htons(53);
    if (inet_pton(AF_INET, g_upstream, &up.sin_addr) != 1) {
        close(s);
        return -1;
    }
    if (sendto(s, query, qlen, 0, (struct sockaddr *)&up, sizeof(up)) < 0) {
        close(s);
        return -1;
    }
    struct sockaddr_in from = {0};
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(s, resp, resp_max, 0, (struct sockaddr *)&from, &fromlen);
    close(s);
    return n;
}

/* ------------------------------------------------ señales */
static void on_signal(int sig)
{
    if (sig == SIGHUP)
        reload_requested = 1;
    else
        running = 0;
}

static void install_signals(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/* ------------------------------------------------ daemonize (fork + setsid) */
static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);           /* padre sale */
    if (setsid() < 0) { perror("setsid"); exit(1); }
    pid = fork();                    /* doble fork: no capta tty */
    if (pid < 0) { perror("fork2"); exit(1); }
    if (pid > 0) exit(0);
    umask(027);
    chdir("/tmp");
    int fd0 = open("/dev/null", O_RDWR);
    int fd1 = dup(fd0), fd2 = dup(fd0);
    if (fd0 > 2 || fd1 > 2 || fd2 > 2) {
        dup2(fd0, 0); dup2(fd1, 1); dup2(fd2, 2);
        close(fd0); close(fd1); close(fd2);
    }
    /* syslog sería lo correcto aquí; stderr queda inerte tras daemonize */
}

/* ------------------------------------------------ main */
static void usage(const char *p)
{
    fprintf(stderr,
        "Uso: %s [opciones]\n"
        "  -b <path>   blocklist (default %s)\n"
        "  -u <ip>     upstream DNS (default %s)\n"
        "  -D          NO demonizar (run en foreground, útil para debug)\n"
        "  -h          esta ayuda\n", p, g_blocklist_path, g_upstream);
    exit(1);
}

int main(int argc, char **argv)
{
    int daemon_mode = 1;
    int ch;
    while ((ch = getopt(argc, argv, "b:u:Dh")) != -1) {
        switch (ch) {
        case 'b': g_blocklist_path = optarg; break;
        case 'u': g_upstream = optarg; break;
        case 'D': daemon_mode = 0; break;
        default: usage(argv[0]);
        }
    }

    table = calloc(table_size, sizeof(char *));
    if (!table) { perror("calloc"); return 1; }
    load_blocklist(g_blocklist_path);

    if (daemon_mode) daemonize();
    install_signals();

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind :53"); return 1;
    }
    logmsg("dnspark escuchando UDP/%d, upstream %s", DNS_PORT, g_upstream);

    unsigned char query[BUF_SIZE], resp[BUF_SIZE], up_resp[BUF_SIZE];
    char qname[256];

    while (running) {
        struct sockaddr_in cli = {0};
        socklen_t clilen = sizeof(cli);
        ssize_t qlen = recvfrom(sock, query, sizeof(query), 0,
                                (struct sockaddr *)&cli, &clilen);
        if (qlen < DNS_HDR_LEN) continue;

        if (reload_requested) {
            reload_requested = 0;
            load_blocklist(g_blocklist_path);
        }

        decode_qname(query + DNS_HDR_LEN,
                     (size_t)qlen - DNS_HDR_LEN, qname, sizeof(qname));
        if (!qname[0]) continue;

        if (domain_is_blocked(qname)) {
            /* responder 0.0.0.0 vía NXDOMAIN: los browsers lo tratan bien
             * y evitamos construir el record A a mano por el momento; a
             * futuro: responder A=0.0.0.0. */
            encode_qname(qname, resp + DNS_HDR_LEN, sizeof(resp) - DNS_HDR_LEN);
            size_t rl = build_reply(query, (size_t)qlen, resp, sizeof(resp), 1);
            sendto(sock, resp, rl, 0, (struct sockaddr *)&cli, clilen);
            continue;
        }

        ssize_t n = forward_query(query, (size_t)qlen, up_resp, sizeof(up_resp));
        if (n > 0)
            sendto(sock, up_resp, (size_t)n, 0, (struct sockaddr *)&cli, clilen);
    }

    logmsg("apagando");
    close(sock);
    domains_free();
    free(table);
    return 0;
}
