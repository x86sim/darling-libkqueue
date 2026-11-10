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

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

#include "private.h"

int
evfilt_socket_copyout(struct kevent64_s *dst, struct knote *src, void *ptr)
{
    struct epoll_event * const ev = (struct epoll_event *) ptr;

    epoll_event_dump(ev);
#ifdef DARLING
    /* x86Sim: Linux reports a stream socket that was never connected as writable and hung up (TCP_CLOSE); XNU's
     * sowriteable() is false for it (PR_CONNREQUIRED, not connected, no error). Network.framework took that EV_EOF as
     * the flow failing (ENETDOWN). Dropped, as EVFILT_READ's (read.c). */
    if ((ev->events & EPOLLHUP) && !(ev->events & EPOLLERR)) {
        struct socket_state_4libkqueue st;
        /* the event may also be stale: epoll_wait() took it before connect() and the connection is up by now
         * (the socket no longer hangs up): that EOF is dropped too */
        struct pollfd now = { .fd = src->kdata.kn_dupfd, .events = POLLIN | POLLOUT };
        int stale = poll(&now, 1, 0) == 1 && !(now.revents & (POLLHUP | POLLERR));
        if (_socket_state_4libkqueue(src->kdata.kn_dupfd, &st) == 0
                && (stale || ((st.state & ~SOSTATE_EVCONNINFO) == 0 && st.error == 0))) {
            dst->filter = EVFILT_DROP;
            /* EV_DISPATCH/EV_ONESHOT (EPOLLONESHOT): epoll disarmed the descriptor for this event, which the program
             * never sees, so it never re-enables it: arm it again, edge-triggered, so the hang-up doesn't fire again
             * but the connection's readiness does (the program's EV_ENABLE restores the knote's own events) */
            if (src->data.events & EPOLLONESHOT) {
                struct epoll_event rearm;
                memset(&rearm, 0, sizeof(rearm));
                rearm.events = src->data.events | EPOLLET;
                rearm.data.ptr = src;
                (void) epoll_ctl(src->kn_epollfd, EPOLL_CTL_MOD, src->kdata.kn_dupfd, &rearm);
            }
            return (0);
        }
    }
#endif
    kevent_int_to_64(&src->kev, dst);
#if defined(HAVE_EPOLLRDHUP)
    if (ev->events & EPOLLRDHUP || ev->events & EPOLLHUP)
        dst->flags |= EV_EOF;
#else
    if (ev->events & EPOLLHUP)
        dst->flags |= EV_EOF;
#endif
    dst->fflags = linux_socket_eof_error(src, ev->events);
          
    /* On return, data contains the the amount of space remaining in the write buffer.
     * x86Sim: TIOCOUTQ is the bytes queued, not the space left (XNU's sbspace()), so an idle socket reported 0 and
     * Network.framework never wrote (an NSURLSession TLS handshake stalled after connect). The space is SO_SNDBUF less
     * what is queued, at least 1 while epoll says writable. */
    {
        int queued = 0, sndbuf = 0;
        socklen_t len = sizeof(sndbuf);
        if (ioctl(src->kdata.kn_dupfd, TIOCOUTQ, &queued) < 0)
            queued = 0;
        if (getsockopt(src->kdata.kn_dupfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len) < 0)
            sndbuf = 0;
        dst->data = sndbuf > queued ? sndbuf - queued : 1;
    }

    return (0);
}

int
evfilt_socket_knote_create(struct filter *filt, struct knote *kn)
{
    struct epoll_event ev;

    if (linux_get_descriptor_type(kn) < 0)
        return (-1);

    /* TODO: return EBADF? */
    if (kn->kn_flags & KNFL_REGULAR_FILE)
        return (-1);

    /* Convert the kevent into an epoll_event */
    kn->data.events = EPOLLOUT;
    if (kn->kev.flags & EV_ONESHOT || kn->kev.flags & EV_DISPATCH)
        kn->data.events |= EPOLLONESHOT;
    if (kn->kev.flags & EV_CLEAR)
        kn->data.events |= EPOLLET;
	kn->kn_epollfd = filter_epfd(filt);

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

    /* Duplicate the fd to workaround epoll's poor design */
	kn->kdata.kn_dupfd = _dup_4libkqueue(kn->kev.ident);

	if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, kn->kdata.kn_dupfd, &ev) < 0) {
		dbg_printf("epoll_ctl(2): %s", strerror(errno));
		return (-1);
	}
    return 0;
}

int
evfilt_socket_knote_modify(struct filter *filt, struct knote *kn, 
        const struct kevent64_s *kev)
{
    struct epoll_event ev;

    /* Convert the kevent into an epoll_event */
    kn->data.events = EPOLLOUT;
    if (kn->kev.flags & EV_ONESHOT || kn->kev.flags & EV_DISPATCH)
        kn->data.events |= EPOLLONESHOT;
    if (kn->kev.flags & EV_CLEAR)
        kn->data.events |= EPOLLET;
	kn->kn_epollfd = filter_epfd(filt);

    /* Disabled registrations are added by the enable callback, not MOD. */
    if (kn->kev.flags & EV_DISABLE)
        return (0);

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

	if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_MOD, kn->kdata.kn_dupfd, &ev) < 0) {
		dbg_printf("epoll_ctl(2): %s", strerror(errno));
		return (-1);
	}
    return 0;
}

int
evfilt_socket_knote_delete(struct filter *filt, struct knote *kn)
{
    if (kn->kev.flags & EV_DISABLE)
    {
        (void) __close_for_kqueue(kn->kdata.kn_dupfd);
        kn->kdata.kn_dupfd = -1;
        return (0);
    }
    else {
        if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL) < 0) {
            dbg_perror("epoll_ctl(2)");
            return (-1);
        }
        (void) __close_for_kqueue(kn->kdata.kn_dupfd);
        kn->kdata.kn_dupfd = -1;
		return 0;
	}
}

int
evfilt_socket_knote_enable(struct filter *filt, struct knote *kn)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

	if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, kn->kdata.kn_dupfd, &ev) < 0) {
		dbg_perror("epoll_ctl(2)");
		return (-1);
	}
	return (0);
}

int
evfilt_socket_knote_disable(struct filter *filt, struct knote *kn)
{
	if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL) < 0) {
		dbg_perror("epoll_ctl(2)");
		return (-1);
	}
	return (0);
}

const struct filter evfilt_write = {
    EVFILT_WRITE,
    NULL,
    NULL,
    evfilt_socket_copyout,
    evfilt_socket_knote_create,
    evfilt_socket_knote_modify,
    evfilt_socket_knote_delete,
    evfilt_socket_knote_enable,
    evfilt_socket_knote_disable,         
};
