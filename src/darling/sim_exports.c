/*
 * Entry points for processes running a foreign libSystem (the iOS simulator
 * runtime's). Darling's libSystem links libkqueue in and overrides weak hooks
 * in libsystem_kernel; a foreign libSystem does not, so libsystem_kernel looks
 * these up by name instead. The names differ from the hooks themselves so the
 * lookup cannot find libsystem_kernel's own weak stubs.
 */

#include <stdint.h>

struct kevent;
struct kevent64_s;
struct timespec;

int kqueue_impl(void);
int kevent_impl(int kqfd, const struct kevent* changelist, int nchanges,
	struct kevent* eventlist, int nevents, const struct timespec* timeout);
int kevent64_impl(int kqfd, const struct kevent64_s* changelist, int nchanges,
	struct kevent64_s* eventlist, int nevents, unsigned int flags, const struct timespec* timeout);
int kqueue_close(int kqfd);
void kqueue_closed_fd(int fd);
void kqueue_dup(int oldfd, int newfd);
void __darling_kqueue_register_listen(int fd);

#define EXPORT __attribute__((visibility("default")))

EXPORT int __darling_sim_kqueue_impl(void)
{
	return kqueue_impl();
}

EXPORT int __darling_sim_kevent_impl(int kqfd, const struct kevent* changelist, int nchanges,
	struct kevent* eventlist, int nevents, const struct timespec* timeout)
{
	return kevent_impl(kqfd, changelist, nchanges, eventlist, nevents, timeout);
}

EXPORT int __darling_sim_kevent64_impl(int kqfd, const struct kevent64_s* changelist, int nchanges,
	struct kevent64_s* eventlist, int nevents, unsigned int flags, const struct timespec* timeout)
{
	return kevent64_impl(kqfd, changelist, nchanges, eventlist, nevents, flags, timeout);
}

EXPORT int __darling_sim_kqueue_close(int kqfd)
{
	return kqueue_close(kqfd);
}

EXPORT void __darling_sim_kqueue_closed_fd(int fd)
{
	kqueue_closed_fd(fd);
}

EXPORT void __darling_sim_kqueue_dup(int oldfd, int newfd)
{
	kqueue_dup(oldfd, newfd);
}

EXPORT void __darling_sim_kqueue_register_listen(int fd)
{
	__darling_kqueue_register_listen(fd);
}

// x86Sim: willi/darling-libkqueue#5 (EVFILT_SOCK): libsystem_kernel's connect()/shutdown() hook
void kqueue_socket_changed(int fd);
EXPORT void __darling_sim_kqueue_socket_changed(int fd)
{
	kqueue_socket_changed(fd);
}
