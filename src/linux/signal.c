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
#include <fcntl.h>
#include <sched.h>

#if HAVE_SYS_SIGNALFD_H
# include <sys/signalfd.h>
#else
#define signalfd(a,b,c) syscall(SYS_signalfd, (a), (b), (c))
#define SFD_NONBLOCK 04000
struct signalfd_siginfo
{
  uint32_t ssi_signo;
  int32_t ssi_errno;
  int32_t ssi_code;
  uint32_t ssi_pid;
  uint32_t ssi_uid;
  int32_t ssi_fd;
  uint32_t ssi_tid;
  uint32_t ssi_band;
  uint32_t ssi_overrun;
  uint32_t ssi_trapno;
  int32_t ssi_status;
  int32_t ssi_int;
  uint64_t ssi_ptr;
  uint64_t ssi_utime;
  uint64_t ssi_stime;
  uint64_t ssi_addr;
  uint8_t __pad[48];
};
#endif

/*
 * Darling: signals are counted by a tap in libsystem_kernel's signal handler
 * (__darling_sigexc_add_tap), which sees every signal the process receives
 * whatever its disposition, as XNU's kqueue does. Each knote gets an eventfd
 * that the tap adds 1 to per signal: data is the real count. The signalfd path
 * below (block the signal on the registering thread, read it from a signalfd)
 * missed every process-directed signal Linux delivered to another thread, and
 * reported 1 for any number; it stays for SIGCHLD (not routed through the
 * handler) and when there is no tap.
 */
extern int __darling_sigexc_add_tap(void (*tap)(int)) __attribute__((weak_import));
static int signalfd_add(int epfd, int sigfd, void *ptr);

#define SIGTAP_MAX 128
static struct {
    volatile int sig;  /* 0: free */
    volatile int fd;
} sigtap[SIGTAP_MAX];
static volatile int sigtap_inflight;
static volatile int sigtap_ok = -1;

static void
sigtap_fire(int sig)
{
    __sync_fetch_and_add(&sigtap_inflight, 1);
    for (int i = 0; i < SIGTAP_MAX; i++) {
        if (sigtap[i].sig == sig) {
            int fd = sigtap[i].fd;
            uint64_t one = 1;
            if (fd >= 0 && write(fd, &one, sizeof(one)) < 0) {}
        }
    }
    __sync_fetch_and_sub(&sigtap_inflight, 1);
}

static int
sigtap_available(void)
{
    if (sigtap_ok < 0)
        sigtap_ok = (__darling_sigexc_add_tap != NULL && __darling_sigexc_add_tap(sigtap_fire) == 0) ? 1 : 0;
    return sigtap_ok;
}

static int
sigtap_slot(int fd)
{
    for (int i = 0; i < SIGTAP_MAX; i++)
        if (sigtap[i].sig != 0 && sigtap[i].fd == fd)
            return i;
    return -1;
}

/* an eventfd in the epoll set, counted by the tap; -1 when not possible */
static int
sigtap_create(int epfd, void *ptr, int signum)
{
    if (signum == 20 /* SIGCHLD */ || !sigtap_available())
        return -1;
    int fd = eventfd(0, 0);
    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    for (int i = 0; i < SIGTAP_MAX; i++) {
        if (__sync_bool_compare_and_swap(&sigtap[i].sig, 0, -1)) {  /* claimed, not yet live */
            sigtap[i].fd = fd;
            if (signalfd_add(epfd, fd, ptr) < 0) {
                sigtap[i].fd = -1;
                sigtap[i].sig = 0;
                break;
            }
            __sync_synchronize();
            sigtap[i].sig = signum;
            return fd;
        }
    }
    (void) __close_for_kqueue(fd);
    return -1;
}

static void
sigtap_release(int slot)
{
    sigtap[slot].sig = -1;  /* no new writes */
    __sync_synchronize();
    while (sigtap_inflight != 0)
        sched_yield();      /* a tap on another thread may still hold the fd */
    sigtap[slot].fd = -1;
    __sync_synchronize();
    sigtap[slot].sig = 0;
}

static void
signalfd_reset(int sigfd)
{
    struct signalfd_siginfo sig;
    ssize_t n;

    /* Discard any pending signal */
    n = read(sigfd, &sig, sizeof(sig));
    if (n < 0 || n != sizeof(sig)) {
        if (errno == EWOULDBLOCK)
            return;
        //FIXME: eintr?
        dbg_perror("read(2) from signalfd");
        abort();
    }
}

static int
signalfd_add(int epfd, int sigfd, void *ptr)
{
    struct epoll_event ev;
    int rv;

    /* Add the signalfd to the kqueue's epoll descriptor set */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = ptr;
    rv = epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev);
    if (rv < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }

    return (0);
}

static int
signalfd_create(int epfd, void *ptr, int signum)
{
    static int flags = SFD_NONBLOCK;
    sigset_t sigmask;
    int sigfd;

    /* Create a signalfd */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, signum);
    sigfd = signalfd(-1, &sigmask, flags);

    /* WORKAROUND: Flags are broken on kernels older than Linux 2.6.27 */
    if (sigfd < 0 && errno == EINVAL && flags != 0) {
        flags = 0;
        sigfd = signalfd(-1, &sigmask, flags);
    }
    if (sigfd < 0) {
        dbg_perror("signalfd(2)");
        goto errout;
    }
    fcntl(sigfd, F_SETFD, FD_CLOEXEC);

    /* Block the signal handler from being invoked */
    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
        dbg_perror("sigprocmask(2)");
        goto errout;
    }

    signalfd_reset(sigfd);

    if (signalfd_add(epfd, sigfd, ptr) < 0)
        goto errout;

    dbg_printf("added sigfd %d to epfd %d (signum=%d)", sigfd, epfd, signum);

    return (sigfd);

errout:
    (void) __close_for_kqueue(sigfd);
    return (-1);
}

int
evfilt_signal_copyout(struct kevent64_s *dst, struct knote *src, void *x UNUSED)
{
    int sigfd;

    sigfd = src->kdata.kn_signalfd;

    if (sigfd >= 0 && sigtap_slot(sigfd) >= 0) {
        uint64_t n = 0;
        if (read(sigfd, &n, sizeof(n)) != sizeof(n) || n == 0) {
            dst->filter = EVFILT_DROP;  /* consumed by another thread's copyout: no event */
            return (0);
        }
        kevent_int_to_64(&src->kev, dst);
        dst->data = (int64_t) n;
        return (0);
    }

    signalfd_reset(sigfd);

    kevent_int_to_64(&src->kev, dst);
    /* NOTE: dst->data should be the number of times the signal occurred,
       but that information is not available.
     */
    dst->data = 1;  

    return (0);
}

int
evfilt_signal_knote_create(struct filter *filt, struct knote *kn)
{
    int fd;

    fd = sigtap_create(filter_epfd(filt), kn, kn->kev.ident);
    if (fd < 0)
        fd = signalfd_create(filter_epfd(filt), kn, kn->kev.ident);
    if (fd > 0) {
        kn->kev.flags |= EV_CLEAR;
        kn->kdata.kn_signalfd = fd;
        return (0);
    } else {
        kn->kdata.kn_signalfd = -1;
        return (-1);
    }
}

int
evfilt_signal_knote_modify(struct filter *filt UNUSED, 
        struct knote *kn UNUSED, 
        const struct kevent64_s *kev UNUSED)
{
    /* Nothing to do since the signal number does not change. */

    return (0);
}

int
evfilt_signal_knote_delete(struct filter *filt, struct knote *kn)
{
    const int sigfd = kn->kdata.kn_signalfd;

    /* Needed so that delete() can be called after disable() */
    if (kn->kdata.kn_signalfd == -1)
        return (0);

    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_DEL, sigfd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }

    int slot = sigtap_slot(sigfd);
    if (slot >= 0)
        sigtap_release(slot);

    if (__close_for_kqueue(sigfd) < 0) {
        dbg_perror("close(2)");
        return (-1);
    }

    /* NOTE: This does not call sigprocmask(3) to unblock the signal. */
    kn->kdata.kn_signalfd = -1;

    return (0);
}

int
evfilt_signal_knote_enable(struct filter *filt, struct knote *kn)
{
    dbg_printf("enabling ident %u", (unsigned int) kn->kev.ident);
    return evfilt_signal_knote_create(filt, kn);
}

int
evfilt_signal_knote_disable(struct filter *filt, struct knote *kn)
{
    dbg_printf("disabling ident %u", (unsigned int) kn->kev.ident);
    return evfilt_signal_knote_delete(filt, kn);
}


const struct filter evfilt_signal = {
    EVFILT_SIGNAL,
    NULL,
    NULL,
    evfilt_signal_copyout,
    evfilt_signal_knote_create,
    evfilt_signal_knote_modify,
    evfilt_signal_knote_delete,
    evfilt_signal_knote_enable,
    evfilt_signal_knote_disable,         
};
