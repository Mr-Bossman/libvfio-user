/*
 * fdrelay: protocol-agnostic relay of a SOCK_STREAM unix socket (with
 * SCM_RIGHTS fds) over a plain byte stream such as ssh.
 *
 *   app A <-unix-> [listen] <== stdio/ssh ==> [connect] <-unix-> app B
 *
 * The relay never parses the application protocol. Bytes are forwarded
 * verbatim, keeping the boundaries at which fds were attached. Each passed fd
 * is classified and replaced by a local stand-in on the far side:
 *
 *   memfd / regular file -> a new local memfd of the same size. Both ends mmap
 *                           their copy; changed 4K pages are found by diffing
 *                           against a shadow copy and sent as MEM frames, so
 *                           the mappings stay coherent (see LIMITS).
 *   eventfd              -> a local eventfd. Whatever the far side writes to
 *                           its copy is replayed onto the original fd (one
 *                           way: copy -> original, like a server raising an
 *                           IRQ).
 *   socket / pipe        -> a socketpair, bytes pumped both ways.
 *   anything else        -> dropped with a warning.
 *
 * Ordering: pending memory changes are flushed (and queued ahead) before every
 * forwarded data chunk or eventfd signal, so a peer that sees a message also
 * sees the memory written before it was sent.
 *
 * LIMITS: change detection is a polled diff, not a trap, so each scan costs
 * O(mapped size). Tune -i, or use -F to scan only on the timer. If both sides
 * write the same page between syncs the later frame wins. Mappings are never
 * torn down (munmap/close on the far side is invisible). Both ends must have
 * the same endianness.
 *
 * Build: cc -O2 -Wall -pthread -o fdrelay fdrelay.c
 * Usage: fdrelay listen  <sock> [-i ms] [-F] -- <command...>
 *        fdrelay connect <sock> [-i ms] [-F]      (stdio is the stream)
 * Example:
 *   fdrelay listen /tmp/client.sock -- ssh -T host fdrelay connect /tmp/srv.sock
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define PAGE     4096
#define BLOCK    (1U << 20)
#define MAX_FDS  64
#define MAX_OBJS 4096
#define MAX_FRAME (64U << 20)

enum { T_DECLARE = 1, T_DATA, T_MEM, T_SIGNAL, T_STREAM };
enum { K_MEM = 1, K_EVENTFD, K_STREAM };

struct fhdr { uint8_t type; uint32_t len; } __attribute__((packed));
struct declare { uint32_t id; uint8_t kind; uint64_t size; }
    __attribute__((packed));

struct obj {
    uint32_t id;
    int kind;
    int origin;         /* fd came from our local app */
    int fd;             /* eventfd/stream: watched fd; mem copy: memfd */
    int hand;           /* stream copy: end handed to the app */
    size_t size;
    uint8_t *mm, *sh;   /* mem: live mapping, shadow */
    int writable;
    dev_t dev;
    ino_t ino;
};

static struct obj *objs[MAX_OBJS];
static int nobjs;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; /* objs + ordering */
static int epfd, sock, rfd, wfd;
static uint32_t next_id;
static unsigned interval_us = 5000;
static int flush_on_msg = 1;

/* writer queue */
struct qitem { struct qitem *next; size_t len; uint8_t buf[]; };
static struct qitem *qhead, *qtail;
static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcond = PTHREAD_COND_INITIALIZER;

static void
__attribute__((noreturn)) die(const char *m)
{
    fprintf(stderr, "fdrelay: %s%s%s\n", m, errno ? ": " : "",
            errno ? strerror(errno) : "");
    _exit(1);
}

static void
__attribute__((noreturn)) quit(const char *m)
{
    fprintf(stderr, "fdrelay: %s\n", m);
    _exit(0);
}

static int
read_full(int fd, void *b, size_t n)
{
    uint8_t *p = b;

    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        p += r;
        n -= r;
    }
    return 0;
}

static int
write_full(int fd, const void *b, size_t n)
{
    const uint8_t *p = b;

    while (n) {
        ssize_t r = write(fd, p, n);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        p += r;
        n -= r;
    }
    return 0;
}

/* Allocate a frame; caller fills *payload (plen bytes) then calls queue_put. */
static struct qitem *
frame_new(uint8_t type, size_t plen, uint8_t **payload)
{
    struct qitem *q = malloc(sizeof(*q) + sizeof(struct fhdr) + plen);
    struct fhdr h = { .type = type, .len = plen };

    if (q == NULL) {
        die("oom");
    }
    q->next = NULL;
    q->len = sizeof(h) + plen;
    memcpy(q->buf, &h, sizeof(h));
    *payload = q->buf + sizeof(h);
    return q;
}

static void
queue_put(struct qitem *q)
{
    pthread_mutex_lock(&qlock);
    if (qtail) {
        qtail->next = q;
    } else {
        qhead = q;
    }
    qtail = q;
    pthread_cond_signal(&qcond);
    pthread_mutex_unlock(&qlock);
}

static void
emit(uint8_t type, const void *a, size_t alen, const void *b, size_t blen)
{
    uint8_t *p;
    struct qitem *q = frame_new(type, alen + blen, &p);

    memcpy(p, a, alen);
    if (blen) {
        memcpy(p + alen, b, blen);
    }
    queue_put(q);
}

static void *
writer_thread(void *arg)
{
    (void)arg;
    for (;;) {
        struct qitem *q;

        pthread_mutex_lock(&qlock);
        while (!qhead) {
            pthread_cond_wait(&qcond, &qlock);
        }
        q = qhead;
        qhead = q->next;
        if (!qhead) {
            qtail = NULL;
        }
        pthread_mutex_unlock(&qlock);
        if (write_full(wfd, q->buf, q->len) < 0) {
            quit("stream closed");
        }
        free(q);
    }
    return NULL;
}

static struct obj *
find(uint32_t id)
{
    for (int i = 0; i < nobjs; i++) {
        if (objs[i]->id == id) {
            return objs[i];
        }
    }
    return NULL;
}

static struct obj *
obj_new(uint32_t id, int kind, int origin, size_t size)
{
    struct obj *o;

    if (nobjs >= MAX_OBJS) {
        return NULL;
    }
    o = calloc(1, sizeof(*o));
    o->id = id;
    o->kind = kind;
    o->origin = origin;
    o->size = size;
    o->fd = o->hand = -1;
    objs[nobjs++] = o;
    return o;
}

static void
watch(struct obj *o)
{
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = o };

    epoll_ctl(epfd, EPOLL_CTL_ADD, o->fd, &ev);
}

static int
map_mem(struct obj *o, int fd)
{
    o->writable = 1;
    o->mm = mmap(NULL, o->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (o->mm == MAP_FAILED) {
        o->writable = 0;
        o->mm = mmap(NULL, o->size, PROT_READ, MAP_SHARED, fd, 0);
    }
    o->sh = mmap(NULL, o->size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); /* starts zeroed */
    return (o->mm == MAP_FAILED || o->sh == MAP_FAILED) ? -1 : 0;
}

/* An fd arrived from our local app. Returns its object id, or 0 to drop. */
static uint32_t
adopt(int fd)
{
    struct stat st;
    char path[64], link[128] = "";
    struct declare d;
    struct obj *o;
    int kind = 0;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return 0;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (readlink(path, link, sizeof(link) - 1) < 0) {
        link[0] = 0;
    }
    if (strncmp(link, "anon_inode:[eventfd", 19) == 0) {
        kind = K_EVENTFD;
    } else if (S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode)) {
        kind = K_STREAM;
    } else if (S_ISREG(st.st_mode) && st.st_size > 0) {
        kind = K_MEM;
    }
    if (!kind) {
        fprintf(stderr, "fdrelay: dropping unsupported fd (%s)\n", link);
        close(fd);
        return 0;
    }
    if (kind == K_MEM) {
        for (int i = 0; i < nobjs; i++) {
            if (objs[i]->kind == K_MEM && objs[i]->origin &&
                objs[i]->dev == st.st_dev && objs[i]->ino == st.st_ino) {
                close(fd);
                return objs[i]->id;
            }
        }
    }
    o = obj_new(next_id, kind, 1, kind == K_MEM ? st.st_size : 0);
    if (o == NULL) {
        close(fd);
        return 0;
    }
    next_id += 2;
    if (kind == K_MEM) {
        o->dev = st.st_dev;
        o->ino = st.st_ino;
        if (map_mem(o, fd) < 0) {
            die("mmap");
        }
        close(fd);
    } else {
        o->fd = fd;
        if (kind == K_EVENTFD) {
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        } else {
            watch(o);
        }
    }
    d = (struct declare){ .id = o->id, .kind = kind, .size = o->size };
    emit(T_DECLARE, &d, sizeof(d), NULL, 0);
    return o->id;
}

/* The far side announced an object: build the local stand-in. */
static void
declare(const struct declare *d)
{
    struct obj *o = obj_new(d->id, d->kind, 0, d->size);
    int sv[2];

    if (o == NULL) {
        die("too many objects");
    }
    switch (d->kind) {
    case K_MEM:
        o->fd = memfd_create("fdrelay", MFD_CLOEXEC);
        if (o->fd < 0 || ftruncate(o->fd, o->size) < 0 ||
            map_mem(o, o->fd) < 0) {
            die("memfd");
        }
        break;
    case K_EVENTFD:
        o->fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        watch(o);
        break;
    case K_STREAM:
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
            die("socketpair");
        }
        o->fd = sv[0];
        o->hand = sv[1];
        watch(o);
        break;
    }
}

/* ----------------------------------------------------------------- memory */

static void
emit_run(struct obj *o, size_t a, size_t b)
{
    uint8_t *p;
    struct qitem *q = frame_new(T_MEM, 12 + (b - a), &p);
    uint32_t id = o->id;
    uint64_t off = a;

    memcpy(p, &id, 4);
    memcpy(p + 4, &off, 8);
    memcpy(p + 12, o->mm + a, b - a);       /* snapshot once ... */
    memcpy(o->sh + a, p + 12, b - a);       /* ... shadow matches what we send */
    queue_put(q);
}

static void
scan(struct obj *o)
{
    for (size_t b = 0; b < o->size; b += BLOCK) {
        size_t e = b + BLOCK < o->size ? b + BLOCK : o->size;
        size_t run = (size_t)-1;

        if (memcmp(o->mm + b, o->sh + b, e - b) == 0) {
            continue;
        }
        for (size_t p = b; p < e; p += PAGE) {
            size_t q = p + PAGE < e ? p + PAGE : e;

            if (memcmp(o->mm + p, o->sh + p, q - p) != 0) {
                if (run == (size_t)-1) {
                    run = p;
                }
            } else if (run != (size_t)-1) {
                emit_run(o, run, p);
                run = (size_t)-1;
            }
        }
        if (run != (size_t)-1) {
            emit_run(o, run, e);
        }
    }
}

/* Caller holds lock. */
static void
flush(void)
{
    for (int i = 0; i < nobjs; i++) {
        if (objs[i]->kind == K_MEM) {
            scan(objs[i]);
        }
    }
}

static void *
scanner_thread(void *arg)
{
    (void)arg;
    for (;;) {
        usleep(interval_us);
        pthread_mutex_lock(&lock);
        flush();
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

/* ---------------------------------------------------------------- threads */

/* eventfd copies and stream objects -> stream */
static void *
watcher_thread(void *arg)
{
    (void)arg;
    for (;;) {
        struct epoll_event ev;
        struct obj *o;
        int r = epoll_wait(epfd, &ev, 1, -1);

        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r < 0) {
            die("epoll_wait");
        }
        o = ev.data.ptr;
        if (o->kind == K_EVENTFD) {
            struct { uint32_t id; uint64_t v; } __attribute__((packed)) s;

            s.id = o->id;
            if (read(o->fd, &s.v, 8) != 8) {
                continue;
            }
            pthread_mutex_lock(&lock);
            if (flush_on_msg) {
                flush();
            }
            emit(T_SIGNAL, &s, sizeof(s), NULL, 0);
            pthread_mutex_unlock(&lock);
        } else {
            uint8_t buf[65536];
            ssize_t n = read(o->fd, buf, sizeof(buf));
            uint32_t id = o->id;

            if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            }
            if (n < 0) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, o->fd, NULL);
                continue;
            }
            pthread_mutex_lock(&lock);
            if (flush_on_msg) {
                flush();
            }
            emit(T_STREAM, &id, 4, buf, n);
            pthread_mutex_unlock(&lock);
            if (n == 0) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, o->fd, NULL);
            }
        }
    }
}

/* stream -> local app */
static void
deliver(const uint8_t *p, uint32_t len)
{
    uint16_t nf;
    uint32_t ids[MAX_FDS];
    int fds[MAX_FDS], n = 0;
    size_t off, dlen;
    const uint8_t *data;
    char cbuf[CMSG_SPACE(sizeof(int) * MAX_FDS)];
    struct iovec iov;
    struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
    ssize_t sent;

    if (len < 2) {
        return;
    }
    memcpy(&nf, p, 2);
    off = 2 + 4 * (size_t)nf;
    if (nf > MAX_FDS || len < off) {
        quit("bad DATA frame");
    }
    memcpy(ids, p + 2, 4 * (size_t)nf);
    data = p + off;
    dlen = len - off;

    pthread_mutex_lock(&lock);
    for (int i = 0; i < nf; i++) {
        struct obj *o = find(ids[i]);
        int fd = -1;

        if (o && !o->origin) {
            if (o->kind == K_STREAM) {
                fd = o->hand;
                o->hand = -1;
            } else {
                fd = dup(o->fd);
            }
        }
        if (fd >= 0) {
            fds[n++] = fd;
        }
    }
    pthread_mutex_unlock(&lock);

    iov.iov_base = (void *)data;
    iov.iov_len = dlen;
    if (n > 0) {
        struct cmsghdr *c;

        memset(cbuf, 0, sizeof(cbuf));
        mh.msg_control = cbuf;
        mh.msg_controllen = CMSG_SPACE(sizeof(int) * n);
        c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * n);
        memcpy(CMSG_DATA(c), fds, sizeof(int) * n);
    }
    do {
        sent = sendmsg(sock, &mh, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0 || write_full(sock, data + sent, dlen - sent) < 0) {
        quit("local socket closed");
    }
    while (n--) {
        close(fds[n]);
    }
}

static void *
stream_reader_thread(void *arg)
{
    (void)arg;
    for (;;) {
        struct fhdr h;
        uint8_t *p;

        if (read_full(rfd, &h, sizeof(h)) < 0) {
            quit("stream closed");
        }
        if (h.len > MAX_FRAME || !(p = malloc(h.len ? h.len : 1))) {
            quit("bad frame");
        }
        if (read_full(rfd, p, h.len) < 0) {
            quit("stream closed");
        }
        switch (h.type) {
        case T_DECLARE:
            if (h.len >= sizeof(struct declare)) {
                struct declare d;

                memcpy(&d, p, sizeof(d));
                pthread_mutex_lock(&lock);
                declare(&d);
                pthread_mutex_unlock(&lock);
            }
            break;
        case T_MEM:
            if (h.len >= 12) {
                uint32_t id;
                uint64_t off;
                struct obj *o;

                memcpy(&id, p, 4);
                memcpy(&off, p + 4, 8);
                pthread_mutex_lock(&lock);
                o = find(id);
                if (o && o->kind == K_MEM && off + (h.len - 12) <= o->size) {
                    if (o->writable) {
                        memcpy(o->mm + off, p + 12, h.len - 12);
                    }
                    memcpy(o->sh + off, p + 12, h.len - 12); /* no echo */
                }
                pthread_mutex_unlock(&lock);
            }
            break;
        case T_SIGNAL:
            if (h.len == 12) {
                uint32_t id;
                uint64_t v;
                struct obj *o;

                memcpy(&id, p, 4);
                memcpy(&v, p + 4, 8);
                pthread_mutex_lock(&lock);
                o = find(id);
                if (o && o->kind == K_EVENTFD && write(o->fd, &v, 8) < 0) {
                    /* counter full / nobody listening: harmless */
                }
                pthread_mutex_unlock(&lock);
            }
            break;
        case T_STREAM:
            if (h.len >= 4) {
                uint32_t id;
                struct obj *o;
                int fd = -1;

                memcpy(&id, p, 4);
                pthread_mutex_lock(&lock);
                o = find(id);
                if (o && o->kind == K_STREAM) {
                    fd = o->fd;
                }
                pthread_mutex_unlock(&lock);
                if (fd >= 0) {
                    if (h.len > 4) {
                        write_full(fd, p + 4, h.len - 4);
                    } else {
                        shutdown(fd, SHUT_WR);
                    }
                }
            }
            break;
        case T_DATA:
            deliver(p, h.len);
            break;
        }
        free(p);
    }
}

/* local app -> stream */
static void
local_reader(void)
{
    static uint8_t buf[65536];
    char cbuf[CMSG_SPACE(sizeof(int) * MAX_FDS)];

    for (;;) {
        struct iovec iov = { buf, sizeof(buf) };
        struct msghdr mh = {
            .msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = cbuf, .msg_controllen = sizeof(cbuf),
        };
        struct cmsghdr *c;
        uint32_t ids[MAX_FDS];
        uint16_t nids = 0;
        ssize_t n;
        int fds[MAX_FDS], nfds = 0;

        do {
            n = recvmsg(sock, &mh, MSG_CMSG_CLOEXEC);
        } while (n < 0 && errno == EINTR);
        for (c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                int k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                if (nfds + k > MAX_FDS) {
                    k = MAX_FDS - nfds;
                }
                memcpy(fds + nfds, CMSG_DATA(c), k * sizeof(int));
                nfds += k;
            }
        }
        if (n <= 0 && nfds == 0) {
            quit("local socket closed");
        }
        if (n < 0) {
            n = 0;
        }
        pthread_mutex_lock(&lock);
        for (int i = 0; i < nfds; i++) {
            uint32_t id = adopt(fds[i]);

            if (id) {
                ids[nids++] = id;
            }
        }
        if (flush_on_msg) {
            flush();
        }
        {
            uint8_t *p;
            struct qitem *q = frame_new(T_DATA, 2 + 4 * (size_t)nids + n, &p);

            memcpy(p, &nids, 2);
            memcpy(p + 2, ids, 4 * (size_t)nids);
            memcpy(p + 2 + 4 * (size_t)nids, buf, n);
            queue_put(q);
        }
        pthread_mutex_unlock(&lock);
    }
}

static void
usage(void)
{
    fprintf(stderr,
            "usage: fdrelay listen  <sock> [-i ms] [-F] -- <command...>\n"
            "       fdrelay connect <sock> [-i ms] [-F]\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int listening, opt;
    pthread_t t;

    if (argc < 3) {
        usage();
    }
    listening = strcmp(argv[1], "listen") == 0;
    if (!listening && strcmp(argv[1], "connect") != 0) {
        usage();
    }
    if (strlen(argv[2]) >= sizeof(addr.sun_path)) {
        die("socket path too long");
    }
    strcpy(addr.sun_path, argv[2]);
    optind = 3;
    while ((opt = getopt(argc, argv, "i:F")) != -1) {
        if (opt == 'i') {
            interval_us = atof(optarg) * 1000;
        } else if (opt == 'F') {
            flush_on_msg = 0;
        } else {
            usage();
        }
    }
    signal(SIGPIPE, SIG_IGN);

    if (listening) {
        int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int up[2], down[2];

        if (optind >= argc) {
            usage();
        }
        unlink(addr.sun_path);
        if (lfd < 0 || bind(lfd, (void *)&addr, sizeof(addr)) < 0 ||
            listen(lfd, 1) < 0) {
            die("listen");
        }
        if (pipe2(up, O_CLOEXEC) < 0 || pipe2(down, O_CLOEXEC) < 0) {
            die("pipe");
        }
        if (fork() == 0) {
            dup2(up[0], 0);
            dup2(down[1], 1);
            execvp(argv[optind], &argv[optind]);
            die("exec");
        }
        wfd = up[1];
        rfd = down[0];
        next_id = 2;
        fprintf(stderr, "fdrelay: waiting for client on %s\n", argv[2]);
        sock = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (sock < 0) {
            die("accept");
        }
    } else {
        sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0 || connect(sock, (void *)&addr, sizeof(addr)) < 0) {
            die("connect");
        }
        rfd = 0;
        wfd = 1;
        next_id = 1;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        die("epoll");
    }
    pthread_create(&t, NULL, writer_thread, NULL);
    pthread_create(&t, NULL, stream_reader_thread, NULL);
    pthread_create(&t, NULL, watcher_thread, NULL);
    pthread_create(&t, NULL, scanner_thread, NULL);
    local_reader();
    return 0;
}
