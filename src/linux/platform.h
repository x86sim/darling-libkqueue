/*
 * Copyright (c) 2011 Mark Heily <mark@heily.com>
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

#ifndef  _KQUEUE_LINUX_PLATFORM_H
#define  _KQUEUE_LINUX_PLATFORM_H

struct filter;

#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/inotify.h>
#if HAVE_SYS_EVENTFD_H
# include <sys/eventfd.h>
#else
# define eventfd(a,b) syscall(SYS_eventfd, (a), (b))

  static inline int eventfd_write(int fd, uint64_t val) {
      if (write(fd, &val, sizeof(val)) < (ssize_t) sizeof(val))
          return (-1);
      else
          return (0);
  }
#endif
#if HAVE_SYS_TIMERFD_H
# include <sys/timerfd.h>
#endif

/*
 * Get the current thread ID
 */
#ifdef DARLING
#include <darling/emulation/common/base.h>
# define syscall __linux_syscall
#else
# define _GNU_SOURCE
# include <linux/unistd.h>
# include <unistd.h>
#ifndef __ANDROID__

extern long int syscall (long int __sysno, ...);
#endif
#endif /* DARLING */
 
/* Convenience macros to access the epoll descriptor for the kqueue */
#define kqueue_epfd(kq)     ((kq)->kq_id)
#define filter_epfd(filt)   ((filt)->kf_kqueue->kq_id)

/*
 * Additional members of struct filter
 */
#undef FILTER_PLATFORM_SPECIFIC 

struct linux_machport_event;

/* EVFILT_MACHPORT state of a knote (see machport.c) */
/* a thread waiting in kevent (one per thread; kevent calls do not nest) */
struct linux_machport_waiter {
    LIST_ENTRY(linux_machport_waiter) entries;
    int tid;
};

struct linux_machport_state {
    /* shared with darlingserver as a dserver_kqchan_mach_port_shared_t: keep these four first, in this order */
    volatile uint32_t armed;
    volatile uint32_t sequence;
    volatile uint32_t wanted;
    volatile int32_t thread;
    uint32_t consumed;  /* sequence number of the last event received from the server */
    uint32_t arming;    /* the last nonzero value of `armed` */
    unsigned int flags;
    struct linux_machport_event *pending; /* events received but not delivered yet */
    struct linux_machport_event **pending_tail;
    LIST_ENTRY(knote) entries;  /* in kq_machports */
};

/*
 * Additional members of struct knote
 */
#define KNOTE_PLATFORM_SPECIFIC \
    int kn_epollfd; /* A copy of filter->epfd */      \
    union { \
        char *kn_extra_buffer; /* EVFILT_MACHPORT: messages received with the event (MACHPORT_RECEIVE_BUFFER_SIZE) */ \
    }; \
    union { \
        int kn_timerfd; \
        int kn_signalfd; \
        int kn_inotifyfd; \
        int kn_eventfd; \
        int kn_dupfd; \
    } kdata; \
    struct linux_machport_state kn_mp

/*
 * Additional members of struct kqueue
 */
#define KQUEUE_PLATFORM_SPECIFIC \
    struct epoll_event kq_plist[MAX_KEVENT]; \
    size_t kq_nplist; \
    /* counts linux_kevent_copyout() calls: a knote with two epoll entries reports once per call (socket.c) */ \
    unsigned int kq_copyout_gen; \
    LIST_HEAD(, knote) kq_machports; /* EVFILT_MACHPORT knotes, incl. deleted ones with undelivered events */ \
    int kq_mp_wakefd; /* eventfd in the epoll set; raised when such knotes have events to deliver */ \
    int kq_mp_wake_raised; \
    LIST_HEAD(, linux_machport_waiter) kq_mp_waiters /* the threads waiting in kevent */

int     linux_kqueue_init(struct kqueue *);
void    linux_kqueue_free(struct kqueue *);
void    linux_kqueue_atfork(struct kqueue *);

int     linux_kevent_wait(struct kqueue *, int, const struct timespec *);
int     linux_kevent_copyout(struct kqueue *, int, struct kevent64_s *, int);
struct epoll_event *linux_kevent_epevt(void);

int     linux_knote_copyout(struct kevent64_s *, struct knote *);

/* EVFILT_MACHPORT hooks (machport.c) */
int     linux_machport_wait_enter(struct kqueue *);
int     linux_machport_wait_exit(struct kqueue *, int, int);
int     linux_machport_deliverable(struct knote *);
void    linux_machport_delivered(struct knote *);
void    linux_machport_after_copyout(struct kqueue *);
int     linux_machport_is_wake_event(struct kqueue *, struct epoll_event *);

int     linux_eventfd_init(struct eventfd *);
void    linux_eventfd_close(struct eventfd *);
int     linux_eventfd_raise(struct eventfd *);
int     linux_eventfd_lower(struct eventfd *);
int     linux_eventfd_descriptor(struct eventfd *);

/* utility functions */

int     linux_get_descriptor_type(struct knote *);
int     linux_fd_to_path(char *, size_t, int);
/* EVFILT_READ's and EVFILT_WRITE's fflags for a socket knote whose epoll events are events (platform.c) */
uint32_t linux_socket_eof_error(struct knote *, uint32_t events);
#ifdef DARLING
/* x86Sim: EVFILT_READ/WRITE dropped a socket's hang-up (read.c, write.c); idle: the socket was never connected and
 * still hangs up. Parks the knote (platform.c) */
void    linux_socket_hup_dropped(struct knote *, int idle);
/* The knote's epoll entry is being set anew (modify, enable, disable, delete): it is no longer parked */
void    linux_socket_unparked(struct knote *);
/* connect() or listen() on the knote's socket (kqueue_socket_unpark()): a parked knote is armed again */
void    linux_socket_unpark(struct knote *);
#endif

/* epoll-related functions */

int     epoll_update(int, struct filter *, struct knote *, struct epoll_event *);
char *  epoll_event_dump(struct epoll_event *);

#endif  /* ! _KQUEUE_LINUX_PLATFORM_H */
