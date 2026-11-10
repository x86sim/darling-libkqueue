/*
 * Copyright (c) 2009 Mark Heily <mark@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "private.h"

#ifndef NDEBUG
static char *
inotify_mask_dump(uint32_t mask)
{
    static __thread char buf[1024];

#define INEVT_MASK_DUMP(attrib) \
    if (mask & attrib) \
       strcat(buf, #attrib" ");

    snprintf(buf, sizeof(buf), "mask = %d (", mask);
    INEVT_MASK_DUMP(IN_ACCESS);
    INEVT_MASK_DUMP(IN_MODIFY);
    INEVT_MASK_DUMP(IN_ATTRIB);
    INEVT_MASK_DUMP(IN_CLOSE_WRITE);
    INEVT_MASK_DUMP(IN_CLOSE_NOWRITE);
    INEVT_MASK_DUMP(IN_OPEN);
    INEVT_MASK_DUMP(IN_MOVED_FROM);
    INEVT_MASK_DUMP(IN_MOVED_TO);
    INEVT_MASK_DUMP(IN_CREATE);
    INEVT_MASK_DUMP(IN_DELETE);
    INEVT_MASK_DUMP(IN_DELETE_SELF);
    INEVT_MASK_DUMP(IN_MOVE_SELF);
    buf[strlen(buf) - 1] = ')';

    return (buf);
}

static char *
inotify_event_dump(struct inotify_event *evt)
{
    static __thread char buf[1024];

    snprintf(buf, sizeof(buf), "wd=%d mask=%s", 
            evt->wd,
            inotify_mask_dump(evt->mask));

    return (buf);
}

#endif /* !NDEBUG */


#ifdef DARLING
/*
 * x86Sim: one inotify instance per kqueue, not one per knote.
 *
 * Upstream libkqueue gave every EVFILT_VNODE knote its own inotify instance. Linux limits a user to
 * fs.inotify.max_user_instances (1024 here) for all of their processes, and every simulator process of every phone
 * runs as the same user: two booted phones held ~940 (UserEventAgent 165 each, MobileSafari 56, ...). When the limit
 * was reached inotify_init() failed with EMFILE, kn_create failed, kevent_copyin reported it as EBADF, and libdispatch
 * (LIBDISPATCH_STRICT) crashed the registering process: fileproviderd's LaunchServices vnode source ~90 s into a
 * boot, "BUG in libdispatch client: kevent vnode monitor [9: Bad file descriptor]". XNU has no such limit.
 *
 * Now the kqueue's vnode filter has one inotify instance with a watch per watched file (inotify gives a file one
 * watch descriptor per instance; IN_MASK_ADD grows its mask for every knote on it) in the kqueue's epoll set behind
 * a sentinel knote. When it is readable, copyout drains it, adds each event's mask to the pending masks of the knotes
 * on that watch and raises the knote's eventfd; the knote's own epoll entry then reports it (with EV_CLEAR
 * coalescing, as XNU's knote hint does). Disabling a knote only takes its eventfd out of the epoll set, so the watch
 * survives (a file deleted while an EV_DISPATCH source was disabled still reports NOTE_DELETE on re-enable).
 */
#include <sys/eventfd.h>

struct vn_watch {
    struct knote *kn;
    int wd;            /* inotify watch descriptor, -1 once inotify dropped it (IN_IGNORED) */
    uint32_t self;     /* pending inotify events on the file itself */
    uint32_t child;    /* pending events naming an entry of the watched directory */
};

struct evfilt_data {
    int ifd;
    struct knote sentinel;
    struct vn_watch *w;
    int nw, cap;
};

static struct evfilt_data *
vn_data(struct filter *filt)
{
    struct evfilt_data *d = filt->kf_data;
    struct epoll_event ev;
    int e;

    if (d != NULL)
        return (d);
    if ((d = calloc(1, sizeof(*d))) == NULL) {
        errno = ENOMEM;
        return (NULL);
    }
    d->ifd = inotify_init();
    if (d->ifd < 0) {
        e = errno;
        free(d);
        errno = e;
        return (NULL);
    }
    (void) fcntl(d->ifd, F_SETFL, O_NONBLOCK);
    d->sentinel.kev.filter = EVFILT_VNODE;
    d->sentinel.kn_kq = filt->kf_kqueue;
    d->sentinel.kdata.kn_eventfd = -1;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = &d->sentinel;
    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_ADD, d->ifd, &ev) < 0) {
        e = errno;
        (void) __close_for_kqueue(d->ifd);
        free(d);
        errno = e;
        return (NULL);
    }
    filt->kf_data = d;
    return (d);
}

static void
evfilt_vnode_destroy(struct filter *filt)
{
    struct evfilt_data *d = filt->kf_data;
    int i;

    if (d == NULL)
        return;
    for (i = 0; i < d->nw; i++) {
        if (d->w[i].kn->kdata.kn_eventfd >= 0) {
            (void) __close_for_kqueue(d->w[i].kn->kdata.kn_eventfd);
            d->w[i].kn->kdata.kn_eventfd = -1;
        }
    }
    (void) __close_for_kqueue(d->ifd);
    free(d->w);
    free(d);
    filt->kf_data = NULL;
}

static struct vn_watch *
vn_find(struct evfilt_data *d, struct knote *kn)
{
    int i;

    for (i = 0; d != NULL && i < d->nw; i++)
        if (d->w[i].kn == kn)
            return (&d->w[i]);
    return (NULL);
}

static uint32_t
vn_mask(struct knote *kn)
{
    struct stat dsb;
    uint32_t mask = 0;

    /* not IN_CLOSE: the watch is on the inode, so any process closing the file fired it; close() drops our knotes */
    if (kn->kev.fflags & NOTE_DELETE)
        mask |= IN_ATTRIB | IN_DELETE_SELF;
    if (kn->kev.fflags & (NOTE_WRITE | NOTE_EXTEND))
        mask |= IN_MODIFY | IN_ATTRIB;
    if (kn->kev.fflags & (NOTE_ATTRIB | NOTE_LINK))
        mask |= IN_ATTRIB;
    if (kn->kev.fflags & NOTE_RENAME)
        mask |= IN_MOVE_SELF;
    /* on a directory, XNU's NOTE_WRITE is an entry added, removed or renamed */
    if ((kn->kev.fflags & NOTE_WRITE) && fstat(kn->kev.ident, &dsb) == 0 && S_ISDIR(dsb.st_mode))
        mask |= IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
    /* inotify needs some event; copyout drops events no requested fflag covers. Always IN_DELETE_SELF: the watch
       is shared, and a file's last knote must still learn that it is gone. */
    return (mask | IN_DELETE_SELF);
}

/* the watch on the knote's open file (Linux's /proc/self/fd magic link: Darling's inotify_add_watch() would expand
   a path into the prefix); returns wd or -errno */
static long
vn_add_watch(struct evfilt_data *d, struct knote *kn)
{
    char fdpath[64];

    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", (int) kn->kev.ident);
    return (__linux_syscall(254 /* __NR_inotify_add_watch, x86-64 */, d->ifd, (long) fdpath,
            (long) (vn_mask(kn) | IN_MASK_ADD)));
}

static int
vn_epoll(struct filter *filt, struct knote *kn, int op)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = kn;
    if (epoll_ctl(filter_epfd(filt), op, kn->kdata.kn_eventfd, &ev) < 0
            && !(op == EPOLL_CTL_ADD && errno == EEXIST) && !(op == EPOLL_CTL_DEL && errno == ENOENT))
        return (-1);
    return (0);
}

/* drain the instance: pending masks for every knote on each event's watch, and raise their eventfds */
static void
vn_drain(struct evfilt_data *d)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    uint64_t one = 1;
    ssize_t n;
    int i;

    for (;;) {
        n = read(d->ifd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        for (char *p = buf; p + sizeof(struct inotify_event) <= buf + n; ) {
            struct inotify_event *ev = (struct inotify_event *) p;
            p += sizeof(*ev) + ev->len;
            dbg_printf("inotify event: %s", inotify_event_dump(ev));
            if (ev->wd < 0)  /* IN_Q_OVERFLOW */
                continue;
            for (i = 0; i < d->nw; i++) {
                struct vn_watch *w = &d->w[i];
                if (w->wd != ev->wd)
                    continue;
                if (ev->mask & IN_IGNORED) {
                    w->wd = -1;
                    continue;
                }
                if (ev->len > 0)
                    w->child |= ev->mask;
                else
                    w->self |= ev->mask;
                if (w->kn->kdata.kn_eventfd >= 0)
                    (void) !write(w->kn->kdata.kn_eventfd, &one, sizeof(one));
            }
        }
    }
}

int
evfilt_vnode_copyout(struct kevent64_s *dst, struct knote *src, void *ptr UNUSED)
{
    struct filter *filt = &src->kn_kq->kq_filt[~EVFILT_VNODE];
    struct evfilt_data *d = filt->kf_data;
    struct vn_watch *w;
    uint32_t self, child;
    uint64_t cnt;
    struct stat sb;

    if (d != NULL && src == &d->sentinel) {
        vn_drain(d);
        dst->filter = EVFILT_DROP;
        return (0);
    }
    if (src->kdata.kn_eventfd >= 0)
        (void) !read(src->kdata.kn_eventfd, &cnt, sizeof(cnt));
    w = vn_find(d, src);
    if (w == NULL || (w->self | w->child) == 0) {
        /* nothing pending (another thread's kevent() took it) */
        dst->filter = EVFILT_DROP;
        return (0);
    }
    self = w->self;
    child = w->child;
    w->self = w->child = 0;

    kevent_int_to_64(&src->kev, dst);
    dst->data = 0;
    dst->fflags = 0; /* what happened, not every requested flag */

    /* an entry of a watched directory added, removed or renamed is a write of the directory; a child's own data or
       attributes changing is not */
    if ((child & (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)) && (src->kev.fflags & NOTE_WRITE))
        dst->fflags |= NOTE_WRITE;

    if ((self & (IN_ATTRIB | IN_MODIFY)) && fstat(src->kev.ident, &sb) == 0) {
        if (sb.st_nlink == 0 && (src->kev.fflags & NOTE_DELETE))
            dst->fflags |= NOTE_DELETE;
        if (sb.st_nlink != src->data.vnode.nlink && (src->kev.fflags & NOTE_LINK))
            dst->fflags |= NOTE_LINK;
        if (sb.st_size > src->data.vnode.size && (src->kev.fflags & NOTE_EXTEND))
            dst->fflags |= NOTE_EXTEND;
        src->data.vnode.nlink = sb.st_nlink;
        src->data.vnode.size = sb.st_size;
    }
    if ((self & IN_MODIFY) && (src->kev.fflags & NOTE_WRITE))
        dst->fflags |= NOTE_WRITE;
    if ((self & IN_ATTRIB) && (src->kev.fflags & NOTE_ATTRIB))
        dst->fflags |= NOTE_ATTRIB;
    if ((self & IN_MOVE_SELF) && (src->kev.fflags & NOTE_RENAME))
        dst->fflags |= NOTE_RENAME;
    if ((self & IN_DELETE_SELF) && (src->kev.fflags & NOTE_DELETE))
        dst->fflags |= NOTE_DELETE;

    if (dst->fflags == 0)  /* an event none of the requested fflags cover (XNU wouldn't fire) */
        dst->filter = EVFILT_DROP;
    return (0);
}

int evfilt_vnode_knote_delete(struct filter *, struct knote *);

static int
vn_errno(long r)
{
    return (r == -ENOENT || r == -EACCES || r == -ENOSPC || r == -ENOMEM) ? (int) -r : EINVAL;
}

int
evfilt_vnode_knote_create(struct filter *filt, struct knote *kn)
{
    struct evfilt_data *d;
    struct vn_watch *w;
    struct stat sb;
    long wd;
    int e;

    kn->kdata.kn_eventfd = -1;
    if (fstat(kn->kev.ident, &sb) < 0)
        return (-EBADF);
    kn->data.vnode.nlink = sb.st_nlink;
    kn->data.vnode.size = sb.st_size;

    if ((d = vn_data(filt)) == NULL)
        return (-(errno ? errno : ENOMEM));
    if (d->nw == d->cap) {
        int cap = d->cap ? d->cap * 2 : 16;
        struct vn_watch *nwp = realloc(d->w, cap * sizeof(*nwp));
        if (nwp == NULL)
            return (-ENOMEM);
        d->w = nwp;
        d->cap = cap;
    }
    wd = vn_add_watch(d, kn);
    if (wd < 0) {
        dbg_printf("inotify_add_watch(2): %ld", wd);
        return (-vn_errno(wd));
    }
    kn->kdata.kn_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (kn->kdata.kn_eventfd < 0) {
        e = errno;
        kn->kdata.kn_eventfd = -1;
        return (-(e ? e : ENOMEM));
    }
    kn->kev.data = wd;
    w = &d->w[d->nw++];
    memset(w, 0, sizeof(*w));
    w->kn = kn;
    w->wd = (int) wd;
    if (vn_epoll(filt, kn, EPOLL_CTL_ADD) < 0) {
        e = errno;
        evfilt_vnode_knote_delete(filt, kn);
        return (-(e ? e : ENOMEM));
    }
    return (0);
}

int
evfilt_vnode_knote_modify(struct filter *filt, struct knote *kn, const struct kevent64_s *kev)
{
    /* EV_ADD on an existing vnode knote takes the new fflags (XNU's filt_vntouch) */
    struct evfilt_data *d = filt->kf_data;
    struct vn_watch *w = vn_find(d, kn);
    long wd;

    if (w == NULL)
        return (-1);
    if (kev->fflags == kn->kev.fflags)
        return (0);
    kn->kev.fflags = kev->fflags;
    wd = vn_add_watch(d, kn);
    if (wd < 0) {
        errno = vn_errno(wd);
        return (-1);
    }
    w->wd = (int) wd;
    kn->kev.data = wd;
    return (0);
}

int
evfilt_vnode_knote_delete(struct filter *filt, struct knote *kn)
{
    struct evfilt_data *d = filt->kf_data;
    struct vn_watch *w = vn_find(d, kn);
    int i, wd, shared = 0;

    if (kn->kdata.kn_eventfd >= 0) {
        (void) vn_epoll(filt, kn, EPOLL_CTL_DEL);
        (void) __close_for_kqueue(kn->kdata.kn_eventfd);
        kn->kdata.kn_eventfd = -1;
    }
    if (w == NULL)
        return (0);
    wd = w->wd;
    *w = d->w[--d->nw];
    for (i = 0; i < d->nw; i++)
        if (d->w[i].wd == wd)
            shared = 1;
    if (wd >= 0 && !shared)
        (void) __linux_syscall(255 /* __NR_inotify_rm_watch, x86-64 */, d->ifd, wd);
    return (0);
}

int
evfilt_vnode_knote_enable(struct filter *filt, struct knote *kn)
{
    if (kn->kdata.kn_eventfd < 0)
        return (-1);
    return (vn_epoll(filt, kn, EPOLL_CTL_ADD));
}

int
evfilt_vnode_knote_disable(struct filter *filt, struct knote *kn)
{
    if (kn->kdata.kn_eventfd < 0)
        return (0);
    return (vn_epoll(filt, kn, EPOLL_CTL_DEL));
}

const struct filter evfilt_vnode = {
    EVFILT_VNODE,
    NULL,
    evfilt_vnode_destroy,
    evfilt_vnode_copyout,
    evfilt_vnode_knote_create,
    evfilt_vnode_knote_modify,
    evfilt_vnode_knote_delete,
    evfilt_vnode_knote_enable,
    evfilt_vnode_knote_disable,
};

#else /* !DARLING */

/* TODO: USE this to get events with name field */
int
get_one_event(struct inotify_event *dst, int inofd)
{
    ssize_t n;

    dbg_puts("reading one inotify event");
    for (;;) {
        n = read(inofd, dst, sizeof(*dst) + 255 + 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            dbg_perror("read");
            return (-1);
        } else {
            break;
        }
    }
    dbg_printf("read(2) from inotify wd: %ld bytes", (long) n);

    return (0);
}

static int
add_watch(struct filter *filt, struct knote *kn)
{
    struct epoll_event ev;
    int ifd;
    char path[PATH_MAX];
    uint32_t mask;

    /* Convert the fd to a pathname */
    if (linux_fd_to_path(&path[0], sizeof(path), kn->kev.ident) < 0)
        return (-1);

    /* Convert the fflags to the inotify mask */
#ifdef DARLING
    /*
     * x86Sim: not IN_CLOSE. The watch is on the file (inode), so IN_CLOSE fired whenever any process closed it
     * (cfprefsd reading a plist), and copyout then deleted the knote. Darling's close() hook (kqueue_closed_fd)
     * already drops the knotes of a descriptor this process closes, as XNU does.
     */
    mask = 0;
#else
    mask = IN_CLOSE;
#endif
    if (kn->kev.fflags & NOTE_DELETE)
        mask |= IN_ATTRIB | IN_DELETE_SELF;
    if (kn->kev.fflags & NOTE_WRITE)      
        mask |= IN_MODIFY | IN_ATTRIB;
    if (kn->kev.fflags & NOTE_EXTEND)
        mask |= IN_MODIFY | IN_ATTRIB;
    if ((kn->kev.fflags & NOTE_ATTRIB) || 
            (kn->kev.fflags & NOTE_LINK))
        mask |= IN_ATTRIB;
    if (kn->kev.fflags & NOTE_RENAME)
        mask |= IN_MOVE_SELF;
#ifdef DARLING
    /*
     * x86Sim: on a directory, XNU's NOTE_WRITE means an entry was added, removed or renamed. inotify reports those as
     * IN_CREATE/IN_DELETE/IN_MOVED_FROM/IN_MOVED_TO on the directory's watch (IN_MODIFY there is a child's data
     * changing, which copyout now ignores). Without this, a directory watch never fired.
     */
    {
        struct stat dsb;
        if ((kn->kev.fflags & NOTE_WRITE) && fstat(kn->kev.ident, &dsb) == 0 && S_ISDIR(dsb.st_mode))
            mask |= IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
    }
    if (mask == 0) /* x86Sim: inotify needs some event; copyout drops events that map to no requested fflags */
        mask = IN_DELETE_SELF;
#endif
    if (kn->kev.flags & EV_ONESHOT)
        mask |= IN_ONESHOT;

    /* Create an inotify descriptor */
    ifd = inotify_init();
    if (ifd < 0) {
        dbg_perror("inotify_init(2)");
        return (-1);
    }
#ifdef DARLING
    /* x86Sim: non-blocking, so a copyout with nothing left to read can't hang the kevent caller */
    (void) fcntl(ifd, F_SETFL, O_NONBLOCK);
#endif

    /* Add the watch */
    dbg_printf("inotify_add_watch(2); inofd=%d, %s, path=%s", 
            ifd, inotify_mask_dump(mask), path);
#ifdef DARLING
    /*
     * x86Sim: the path read from /proc/<pid>/fd/<n> is a Linux path, and Darling's inotify_add_watch() expands every
     * path into the prefix: a file outside it (/home/... -> <prefix>/home/...) was never found, the kevent failed
     * and libdispatch crashed the process (fileproviderd: the simulator's memory-pressure source is a vnode watch on
     * $SIMULATOR_MEMORY_WARNINGS). Watch the open file itself, through Linux's /proc/self/fd/<n> magic link.
     */
    {
        char fdpath[64];
        long r;
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", (int) kn->kev.ident);
        r = __linux_syscall(254 /* __NR_inotify_add_watch, x86-64 */, ifd, (long) fdpath, mask);
        if (r < 0) {
            errno = (r == -2) ? ENOENT : (r == -13) ? EACCES : (r == -28) ? ENOSPC : EINVAL;
            kn->kev.data = -1;
        } else
            kn->kev.data = r;
    }
#else
    kn->kev.data = inotify_add_watch(ifd, path, mask);
#endif
    if (kn->kev.data < 0) {
        dbg_perror("inotify_add_watch(2)");
        goto errout;
    }

    /* Add the inotify fd to the epoll set */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = kn;
    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_ADD, ifd, &ev) < 0) {
        dbg_perror("epoll_ctl(2)");
        goto errout;
    }

    kn->kdata.kn_inotifyfd = ifd;

    return (0);

errout:
    kn->kdata.kn_inotifyfd = -1;
    (void) __close_for_kqueue(ifd);
    return (-1);
}

static int
delete_watch(struct filter *filt, struct knote *kn)
{
    int ifd = kn->kdata.kn_inotifyfd;

    if (ifd < 0)
        return (0);
    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_DEL, ifd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }
    (void) __close_for_kqueue(ifd);
    kn->kdata.kn_inotifyfd = -1;

    return (0);
}

int
evfilt_vnode_copyout(struct kevent64_s *dst, struct knote *src, void *ptr UNUSED)
{
    struct inotify_event* evt = (struct inotify_event*) __builtin_alloca(sizeof(struct inotify_event) + 255 + 1);
    struct stat sb;

    if (get_one_event(evt, src->kdata.kn_inotifyfd) < 0) {
#ifdef DARLING
        /* x86Sim: nothing to read (another thread took it; the descriptor is non-blocking): not an error, which
           would abort() in linux_kevent_copyout */
        dst->filter = EVFILT_DROP;
        return (0);
#else
        return (-1);
#endif
    }

    dbg_printf("inotify event: %s", inotify_event_dump(evt));
    if (evt->mask & IN_IGNORED) {
        /* TODO: possibly return error when fs is unmounted */
        dst->filter = EVFILT_DROP;
        return (0);
    }

    /* Check if the watched file has been closed, and 
       XXX-this may not exactly match the kevent() behavior if multiple file de
scriptors reference the same file.
    */
    if (evt->mask & IN_CLOSE_WRITE || evt->mask & IN_CLOSE_NOWRITE) {
        src->kn_flags |= EV_ONESHOT; /* KLUDGE: causes the knote to be deleted */
        dst->filter = EVFILT_DROP_POSTPROCESS; /* KLUDGE: causes the event to be discarded */
        return (0);
    }

    kevent_int_to_64(&src->kev, dst);
    dst->data = 0;
#ifdef DARLING
    dst->fflags = 0; /* x86Sim: report what happened, not every requested flag (filled in below) */
    if (evt->len > 0) {
        /* x86Sim: an event about an entry of a watched directory: only adding, removing or renaming one is a write
           of the directory (XNU's NOTE_WRITE); a child's own data or attributes changing is not */
        if ((evt->mask & (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)) && (src->kev.fflags & NOTE_WRITE))
            dst->fflags = NOTE_WRITE;
        else
            dst->filter = EVFILT_DROP;
        return (0);
    }
#endif

    /* No error checking because fstat(2) should rarely fail */
    //FIXME: EINTR
    if ((evt->mask & IN_ATTRIB || evt->mask & IN_MODIFY) 
        && fstat(src->kev.ident, &sb) == 0) {
        if (sb.st_nlink == 0 && src->kev.fflags & NOTE_DELETE) 
            dst->fflags |= NOTE_DELETE;
        if (sb.st_nlink != src->data.vnode.nlink && src->kev.fflags & NOTE_LINK) 
            dst->fflags |= NOTE_LINK;
#if HAVE_NOTE_TRUNCATE
        if (sb.st_nsize == 0 && src->kev.fflags & NOTE_TRUNCATE) 
            dst->fflags |= NOTE_TRUNCATE;
#endif
        if (sb.st_size > src->data.vnode.size && src->kev.fflags & NOTE_WRITE) 
            dst->fflags |= NOTE_EXTEND;
       src->data.vnode.nlink = sb.st_nlink;
       src->data.vnode.size = sb.st_size;
    }

    if (evt->mask & IN_MODIFY && src->kev.fflags & NOTE_WRITE) 
        dst->fflags |= NOTE_WRITE;
    if (evt->mask & IN_ATTRIB && src->kev.fflags & NOTE_ATTRIB) 
        dst->fflags |= NOTE_ATTRIB;
    if (evt->mask & IN_MOVE_SELF && src->kev.fflags & NOTE_RENAME) 
        dst->fflags |= NOTE_RENAME;
    if (evt->mask & IN_DELETE_SELF && src->kev.fflags & NOTE_DELETE) 
        dst->fflags |= NOTE_DELETE;

    if (evt->mask & IN_MODIFY && src->kev.fflags & NOTE_WRITE) 
        dst->fflags |= NOTE_WRITE;
    if (evt->mask & IN_ATTRIB && src->kev.fflags & NOTE_ATTRIB) 
        dst->fflags |= NOTE_ATTRIB;
    if (evt->mask & IN_MOVE_SELF && src->kev.fflags & NOTE_RENAME) 
        dst->fflags |= NOTE_RENAME;
    if (evt->mask & IN_DELETE_SELF && src->kev.fflags & NOTE_DELETE) 
        dst->fflags |= NOTE_DELETE;

#ifdef DARLING
    /* x86Sim: an event none of the requested fflags cover (XNU wouldn't fire) */
    if (dst->fflags == 0)
        dst->filter = EVFILT_DROP;
#endif
    return (0);
}

int
evfilt_vnode_knote_create(struct filter *filt, struct knote *kn)
{
    struct stat sb;

    if (fstat(kn->kev.ident, &sb) < 0) {
        dbg_puts("fstat failed");
        return (-1);
    }
    kn->data.vnode.nlink = sb.st_nlink;
    kn->data.vnode.size = sb.st_size;
    kn->kev.data = -1;
#ifdef DARLING
    kn->kdata.kn_inotifyfd = -1; /* x86Sim: no watch yet (see evfilt_vnode_knote_enable) */
#endif

    return (add_watch(filt, kn));
}

int
evfilt_vnode_knote_modify(struct filter *filt, struct knote *kn, 
        const struct kevent64_s *kev)
{
#ifdef DARLING
    /*
     * x86Sim: EV_ADD on an existing vnode knote takes the new fflags (XNU's filt_vntouch). It was a stub that
     * failed, so libdispatch saw the update as an error (LIBDISPATCH_STRICT processes such as fileproviderd crash on
     * any kevent error).
     */
    if (kev->fflags == kn->kev.fflags && kn->kdata.kn_inotifyfd >= 0)
        return (0);
    kn->kev.fflags = kev->fflags;
    if (kn->kev.flags & EV_DISABLE)
        return (0);
    if (delete_watch(filt, kn) < 0)
        return (-1);
    return (add_watch(filt, kn));
#else
    (void)filt;
    (void)kn;
    (void)kev;
    return (-1); /* FIXME - STUB */
#endif
}

int
evfilt_vnode_knote_delete(struct filter *filt, struct knote *kn)
{   
    return delete_watch(filt, kn);
}

int
evfilt_vnode_knote_enable(struct filter *filt, struct knote *kn)
{
#ifdef DARLING
    /*
     * x86Sim: EV_ENABLE on a knote that is already watching. add_watch() made a second inotify instance and lost
     * the first (still open, still in the epoll set): every re-enable leaked one, until inotify_init() failed with
     * EMFILE (the per-user instance limit) and the next vnode EV_ADD in any simulator process failed
     * (fileproviderd: "vnode add" EMFILE, crashed by LIBDISPATCH_STRICT).
     */
    if (kn->kdata.kn_inotifyfd >= 0)
        return (0);
#endif
    return add_watch(filt, kn);
}

int
evfilt_vnode_knote_disable(struct filter *filt, struct knote *kn)
{
    return delete_watch(filt, kn);
}

const struct filter evfilt_vnode = {
    EVFILT_VNODE,
    NULL,
    NULL,
    evfilt_vnode_copyout,
    evfilt_vnode_knote_create,
    evfilt_vnode_knote_modify,
    evfilt_vnode_knote_delete,
    evfilt_vnode_knote_enable,
    evfilt_vnode_knote_disable,        
};

#endif /* DARLING */
