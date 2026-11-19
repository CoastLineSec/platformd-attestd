/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attestd.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>
#include <systemd/sd-varlink.h>

#define VERIFY_SOCKET "/run/platformd-verifyd/io.platformd.Verify"
#define TRUST_SOCKET "/run/platformd-trustd/io.platformd.Trust"
#define USEC_PER_SEC UINT64_C(1000000)
#define LOCAL_TIMEOUT (3 * USEC_PER_SEC)
#define QUOTE_TIMEOUT (25 * USEC_PER_SEC)
#define POLL_INTERVAL (USEC_PER_SEC / 4)
#define TOKEN_MAX (16U * 1024U * 1024U)
#define CONNECTOR_FD 3
#define CONNECTOR_EXE_FD 4

static void freep(void *p) {
        free(*(void **) p);
}

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static void strv_freep(char ***list) {
        if (!*list)
                return;

        for (char **p = *list; *p; p++)
                free(*p);
        free(*list);
}

static bool streq(const char *a, const char *b) {
        return a && b && strcmp(a, b) == 0;
}

static uint64_t usec_min(uint64_t a, uint64_t b) {
        return a < b ? a : b;
}

static uint64_t deadline_limit(uint64_t deadline, uint64_t usec) {
        uint64_t now = attest_now();

        if (now >= deadline)
                return deadline;
        return now + usec_min(deadline - now, usec);
}

static int time_left(AttestCheck check, void *userdata, uint64_t deadline, uint64_t *ret) {
        uint64_t now;
        int r;

        r = check(userdata);
        if (r < 0)
                return r;

        now = attest_now();
        if (now >= deadline)
                return -ETIMEDOUT;
        if (ret)
                *ret = deadline - now;
        return 0;
}

static bool session_id_valid(const char *id) {
        if (!id || !*id || strlen(id) > 256)
                return false;
        return id[strspn(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")] == 0;
}

int local_session_check(const char *session, uid_t uid) {
        __attribute__((cleanup(sd_bus_unrefp))) sd_bus *bus = NULL;
        __attribute__((cleanup(freep))) char *type = NULL, *class = NULL, *state = NULL, *path = NULL;
        uid_t owner;
        int r, locked;

        if (!session_id_valid(session) || uid == 0 || uid == (uid_t) -1)
                return -EINVAL;

        r = sd_session_get_uid(session, &owner);
        if (r < 0)
                return r;
        if (owner != uid)
                return -EACCES;

        r = sd_session_is_remote(session);
        if (r < 0)
                return r;
        if (r > 0)
                return -EACCES;

        r = sd_session_is_active(session);
        if (r < 0)
                return r;
        if (r == 0)
                return -EACCES;

        if ((r = sd_session_get_type(session, &type)) < 0 ||
            (r = sd_session_get_class(session, &class)) < 0 ||
            (r = sd_session_get_state(session, &state)) < 0)
                return r;
        if ((!streq(type, "wayland") && !streq(type, "x11")) ||
            (!streq(class, "user") && !streq(class, "user-early") &&
             !streq(class, "user-light") && !streq(class, "user-early-light")) ||
            !streq(state, "active"))
                return -EACCES;

        if ((r = sd_bus_path_encode("/org/freedesktop/login1/session", session, &path)) < 0 ||
            (r = sd_bus_open_system(&bus)) < 0 ||
            (r = sd_bus_set_method_call_timeout(bus, USEC_PER_SEC)) < 0 ||
            (r = sd_bus_get_property_trivial(bus, "org.freedesktop.login1", path,
                                           "org.freedesktop.login1.Session", "LockedHint", NULL, 'b', &locked)) < 0)
                return r;

        return locked ? -EACCES : 0;
}

int local_session_get(int pidfd, uid_t uid, char **ret) {
        __attribute__((cleanup(strv_freep))) char **sessions = NULL;
        __attribute__((cleanup(freep))) char *session = NULL;
        const char *selected = NULL;
        uid_t owner;
        int r;

        if (pidfd < 0 || uid == 0 || uid == (uid_t) -1 || !ret)
                return -EINVAL;

        r = sd_pidfd_get_session(pidfd, &session);
        if (r >= 0) {
                r = local_session_check(session, uid);
                if (r < 0)
                        return r;

                *ret = session;
                session = NULL;
                return 0;
        }
        if (r != -ENODATA)
                return r;

        r = sd_pidfd_get_owner_uid(pidfd, &owner);
        if (r < 0)
                return r;
        if (owner != uid)
                return -EACCES;

        r = sd_uid_get_sessions(uid, 0, &sessions);
        if (r < 0)
                return r;
        if (r == 0 || r > 16)
                return -EACCES;

        for (char **p = sessions; *p; p++) {
                r = local_session_check(*p, uid);
                if (r == -EACCES)
                        continue;
                if (r < 0)
                        return r;
                if (selected)
                        return -ENOTUNIQ;
                selected = *p;
        }
        if (!selected)
                return -EACCES;

        *ret = strdup(selected);
        return *ret ? 0 : -ENOMEM;
}

static int checked_socket(const char *path) {
        __attribute__((cleanup(closep))) int fd = -1;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct ucred credentials;
        socklen_t size = sizeof(credentials);
        size_t n = strlen(path);
        int result;

        if (n >= sizeof(sa.sun_path))
                return -ENAMETOOLONG;
        memcpy(sa.sun_path, path, n + 1);

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;
        if (connect(fd, (const struct sockaddr *) &sa, sizeof(sa)) < 0 ||
            getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) < 0)
                return -errno;
        if (size != sizeof(credentials) || credentials.pid <= 0 || credentials.uid != 0)
                return -EACCES;

        result = fd;
        fd = -1;
        return result;
}

static int socket_peer_check(int fd, const char *path) {
        struct sockaddr_un address = {};
        socklen_t size = sizeof(address), type_size = sizeof(int);
        int type;

        if (getpeername(fd, (struct sockaddr *) &address, &size) < 0 ||
            getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0)
                return -errno;
        if (type_size != sizeof(type) || type != SOCK_STREAM || address.sun_family != AF_UNIX ||
            size != offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1 ||
            memcmp(address.sun_path, path, strlen(path) + 1) != 0)
                return -EACCES;
        return 0;
}

static int socket_trusted(const char *directory, const char *endpoint) {
        struct stat parent, socket_stat;

        if (lstat(directory, &parent) < 0 || lstat(endpoint, &socket_stat) < 0)
                return -errno;
        if (!S_ISDIR(parent.st_mode) || parent.st_uid != 0 || (parent.st_mode & 022) ||
            !S_ISSOCK(socket_stat.st_mode) || socket_stat.st_uid != 0)
                return -EACCES;
        return 0;
}

static int fd_send(int control, int fd) {
        union {
                struct cmsghdr header;
                char data[CMSG_SPACE(sizeof(int))];
        } ancillary = {};
        char byte = 'V';
        struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
        struct msghdr msg = {
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = ancillary.data, .msg_controllen = sizeof(ancillary.data),
        };
        struct cmsghdr *header = CMSG_FIRSTHDR(&msg);
        ssize_t n;

        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(fd));
        memcpy(CMSG_DATA(header), &fd, sizeof(fd));

        do
                n = sendmsg(control, &msg, MSG_NOSIGNAL);
        while (n < 0 && errno == EINTR);
        return n < 0 ? -errno : n != 1 ? -EIO : 0;
}

int local_connect_verify(int control) {
        __attribute__((cleanup(closep))) int verify = -1;
        uid_t uid, effective_uid, saved_uid;
        gid_t gid, effective_gid, saved_gid;
        struct ucred peer;
        socklen_t size = sizeof(peer);
        struct pollfd p = { .fd = control, .events = POLLIN };
        char byte;
        int r;

        if (getresuid(&uid, &effective_uid, &saved_uid) < 0 ||
            getresgid(&gid, &effective_gid, &saved_gid) < 0)
                return -errno;
        if (control != CONNECTOR_FD || uid == 0 || uid != effective_uid || uid != saved_uid ||
            gid == 0 || gid != effective_gid || gid != saved_gid || getgroups(0, NULL) != 0)
                return -EACCES;
        if (getsockopt(control, SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0)
                return -errno;
        if (size != sizeof(peer) || peer.uid != 0 || peer.pid <= 1 || peer.pid != getppid())
                return -EACCES;
        if (prctl(PR_SET_DUMPABLE, 0) < 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
                return -errno;
        if (peer.pid != getppid())
                return -ECHILD;

        r = socket_trusted("/run/platformd-verifyd", VERIFY_SOCKET);
        if (r < 0)
                return r;
        verify = checked_socket(VERIFY_SOCKET);
        if (verify < 0)
                return verify;

        r = fd_send(control, verify);
        if (r < 0)
                return r;
        close(verify);
        verify = -1;

        r = poll(&p, 1, (int) (ATTEST_TIMEOUT_USEC / 1000 + 3000));
        if (r < 0)
                return -errno;
        if (r == 0)
                return -ETIMEDOUT;
        return recv(control, &byte, 1, MSG_DONTWAIT) == 0 ? 0 : -EBADMSG;
}

static void connector_exec(int control, int executable, uid_t uid, gid_t gid, pid_t parent) {
        char *const argv[] = { "platformd-attestd", "--connect-verify", "3", NULL };
        char *const environment[] = { NULL };

        /* Pass only the private control socket into the unprivileged executable. */
        if (dup3(control, CONNECTOR_FD, 0) < 0 ||
            dup3(executable, CONNECTOR_EXE_FD, O_CLOEXEC) < 0 ||
            close_range(5, UINT_MAX, 0) < 0 ||
            close_range(0, 2, 0) < 0 ||
            prctl(PR_SET_DUMPABLE, 0) < 0 ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
            setgroups(0, NULL) < 0 ||
            setresgid(gid, gid, gid) < 0 ||
            setresuid(uid, uid, uid) < 0 ||
            prctl(PR_SET_DUMPABLE, 0) < 0 ||
            prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 ||
            parent <= 1 || getppid() != parent)
                _exit(EXIT_FAILURE);

        fexecve(CONNECTOR_EXE_FD, argv, environment);
        _exit(EXIT_FAILURE);
}

static int fd_receive(int control, AttestCheck check, void *userdata, uint64_t deadline) {
        union {
                struct cmsghdr header;
                char data[CMSG_SPACE(sizeof(int))];
        } ancillary = {};
        char byte;
        struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
        struct msghdr msg = {
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = ancillary.data, .msg_controllen = sizeof(ancillary.data),
        };
        struct pollfd p = { .fd = control, .events = POLLIN };
        int fd = -1, r, n_fds = 0;
        uint64_t left;
        ssize_t n;

        for (;;) {
                r = time_left(check, userdata, deadline, &left);
                if (r < 0)
                        return r;
                r = poll(&p, 1, (int) ((usec_min(left, POLL_INTERVAL) + 999) / 1000));
                if (r > 0)
                        break;
                if (r < 0 && errno != EINTR)
                        return -errno;
        }

        n = recvmsg(control, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (n < 0)
                return -errno;
        for (struct cmsghdr *header = CMSG_FIRSTHDR(&msg); header; header = CMSG_NXTHDR(&msg, header)) {
                if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
                    header->cmsg_len < CMSG_LEN(0))
                        continue;
                size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; i++) {
                        int received;

                        memcpy(&received, CMSG_DATA(header) + i * sizeof(int), sizeof(int));
                        if (++n_fds == 1)
                                fd = received;
                        else
                                close(received);
                }
        }
        if (n != 1 || byte != 'V' || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || n_fds != 1 || fd < 0) {
                if (fd >= 0)
                        close(fd);
                return -EBADMSG;
        }
        return fd;
}

static int verify_connector(uid_t uid, AttestCheck check, void *userdata, uint64_t deadline,
                            int *ret_control, pid_t *ret_pid) {
        __attribute__((cleanup(closep))) int executable = -1, source_fd = -1, child_fd = -1;
        struct passwd *account;
        int pair[2], fd;
        pid_t parent = getpid(), pid;

        account = getpwuid(uid);
        if (!account || account->pw_uid != uid || account->pw_gid == 0 || account->pw_gid == (gid_t) -1)
                return -ESRCH;

        source_fd = open("/proc/self/exe", O_PATH | O_CLOEXEC);
        if (source_fd < 0)
                return -errno;
        executable = fcntl(source_fd, F_DUPFD_CLOEXEC, 5);
        if (executable < 0)
                return -errno;
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) < 0)
                return -errno;
        child_fd = fcntl(pair[1], F_DUPFD_CLOEXEC, 5);
        close(pair[1]);
        if (child_fd < 0) {
                int r = -errno;

                close(pair[0]);
                return r;
        }

        pid = fork();
        if (pid == 0)
                connector_exec(child_fd, executable, uid, account->pw_gid, parent);
        if (pid < 0) {
                int r = -errno;

                close(pair[0]);
                return r;
        }
        close(child_fd);
        child_fd = -1;

        *ret_control = pair[0];
        *ret_pid = pid;
        fd = fd_receive(pair[0], check, userdata, deadline_limit(deadline, LOCAL_TIMEOUT));
        return fd;
}

static int root_peer_check(sd_varlink *link) {
        uid_t uid;
        int r;

        r = sd_varlink_get_peer_uid(link, &uid);
        return r < 0 ? r : uid == 0 ? 0 : -EACCES;
}

static bool json_string_equal(sd_json_variant *object, const char *key, const char *value) {
        return streq(sd_json_variant_string(sd_json_variant_by_key(object, key)), value);
}

static bool json_true(sd_json_variant *object, const char *key) {
        sd_json_variant *value = sd_json_variant_by_key(object, key);

        return sd_json_variant_is_boolean(value) && sd_json_variant_boolean(value) > 0;
}

static bool json_positive(sd_json_variant *object, const char *key) {
        sd_json_variant *value = sd_json_variant_by_key(object, key);

        return sd_json_variant_is_unsigned(value) && sd_json_variant_unsigned(value) > 0;
}

static bool json_hex(sd_json_variant *object, const char *key, bool mixed_case) {
        const char *value = sd_json_variant_string(sd_json_variant_by_key(object, key));

        return value && strlen(value) == 64 &&
               strspn(value, mixed_case ? "0123456789abcdefABCDEF" : "0123456789abcdef") == 64;
}

static bool printable(const char *text) {
        size_t n = 0;

        if (!text || !*text)
                return false;
        for (const unsigned char *p = (const unsigned char *) text; *p; p++)
                if (*p < ' ' || *p == 0x7f || ++n > 1024)
                        return false;
        return true;
}

typedef struct LocalReply {
        AttestNotify notify;
        AttestCheck check;
        void *userdata;
        sd_json_variant *value;
        int status;
        unsigned n_messages;
        bool done;
} LocalReply;

static int on_local_reply(sd_varlink *link, sd_json_variant *parameters, const char *error,
                          sd_varlink_reply_flags_t flags, void *userdata) {
        LocalReply *reply = userdata;
        sd_json_variant *message, *result;
        const char *style, *text;
        int r = -EBADMSG;

        (void) link;
        if (reply->done)
                return -EBADMSG;
        if (error) {
                r = -EACCES;
                goto finish;
        }
        if (!sd_json_variant_is_object(parameters))
                goto finish;

        if (!reply->notify) {
                if (flags & SD_VARLINK_REPLY_CONTINUES)
                        goto finish;
                reply->value = sd_json_variant_ref(parameters);
                r = 0;
                goto finish;
        }

        if (flags & SD_VARLINK_REPLY_CONTINUES) {
                message = sd_json_variant_by_key(parameters, "message");
                if (sd_json_variant_elements(parameters) != 2 || !sd_json_variant_is_object(message) ||
                    sd_json_variant_elements(message) != 4 || ++reply->n_messages > 32)
                        goto finish;

                style = sd_json_variant_string(sd_json_variant_by_key(message, "style"));
                text = sd_json_variant_string(sd_json_variant_by_key(message, "text"));
                if ((!streq(style, "info") && !streq(style, "error")) || !printable(text))
                        goto finish;

                r = reply->check(reply->userdata);
                if (r >= 0 && streq(style, "info"))
                        r = reply->notify(text, reply->userdata);
                if (r >= 0)
                        return 0;
                goto finish;
        }

        result = sd_json_variant_by_key(parameters, "result");
        if (sd_json_variant_elements(parameters) != 2 || !sd_json_variant_is_object(result) ||
            sd_json_variant_elements(result) != 6 || !json_string_equal(result, "method", "platformd-verify") ||
            !json_positive(result, "realtimeUSec"))
                goto finish;
        r = json_true(result, "verified") ? 0 : -EACCES;

finish:
        reply->status = r;
        reply->done = true;
        return 0;
}

static int local_call(sd_varlink *link, const char *method, sd_json_variant *parameters, AttestNotify notify,
                      AttestCheck check, void *userdata, uint64_t deadline, sd_json_variant **ret) {
        LocalReply reply = { .notify = notify, .check = check, .userdata = userdata };
        uint64_t left;
        int r;

        r = time_left(check, userdata, deadline, &left);
        if (r < 0)
                return r;
        if ((r = sd_varlink_set_relative_timeout(link, left)) < 0 ||
            (r = sd_varlink_bind_reply(link, on_local_reply)) < 0)
                return r;
        sd_varlink_set_userdata(link, &reply);

        r = notify ? sd_varlink_observe(link, method, parameters) : sd_varlink_invoke(link, method, parameters);
        while (r >= 0 && !reply.done) {
                r = time_left(check, userdata, deadline, &left);
                if (r < 0)
                        break;
                r = sd_varlink_process(link);
                if (r == 0 && !reply.done)
                        r = sd_varlink_wait(link, usec_min(left, POLL_INTERVAL));
        }
        sd_varlink_set_userdata(link, NULL);
        (void) sd_varlink_bind_reply(link, NULL);

        if (r >= 0)
                r = reply.status;
        if (r >= 0)
                r = time_left(check, userdata, deadline, NULL);
        if (r < 0 || !ret)
                sd_json_variant_unref(reply.value);
        else
                *ret = reply.value;
        return r;
}

int local_verify(uid_t uid, const char *session, const char *label, sd_json_variant *context,
                 AttestNotify notify, AttestCheck check, void *userdata, uint64_t deadline) {
        __attribute__((cleanup(sd_json_variant_unrefp))) sd_json_variant *parameters = NULL;
        __attribute__((cleanup(sd_varlink_close_unrefp))) sd_varlink *link = NULL;
        __attribute__((cleanup(freep))) char *reason = NULL;
        int control = -1, fd, r;
        pid_t pid = -1;

        if (!notify || !check || !session || !label || uid == 0 || uid == (uid_t) -1 ||
            !sd_json_variant_is_object(context))
                return -EINVAL;

        if (asprintf(&reason, "Read protected file from %s", label) < 0)
                return -ENOMEM;
        r = sd_json_buildo(&parameters,
                          SD_JSON_BUILD_PAIR_STRING("sessionId", session),
                          SD_JSON_BUILD_PAIR_STRING("reason", reason),
                          SD_JSON_BUILD_PAIR_VARIANT("context", context));
        if (r < 0)
                return r;

        fd = verify_connector(uid, check, userdata, deadline, &control, &pid);
        if (fd < 0) {
                r = fd;
                goto finish;
        }
        r = socket_peer_check(fd, VERIFY_SOCKET);
        if (r < 0) {
                close(fd);
                goto finish;
        }
        r = sd_varlink_connect_fd(&link, fd);
        if (r < 0) {
                close(fd);
                goto finish;
        }
        r = root_peer_check(link);
        if (r >= 0)
                r = local_call(link, "io.platformd.Verify.VerifyUserWithContext", parameters,
                                notify, check, userdata, deadline, NULL);

finish:
        link = sd_varlink_close_unref(link);
        if (control >= 0)
                close(control);
        if (pid > 0) {
                (void) kill(pid, SIGKILL);
                while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
                        ;
        }
        return r;
}

static bool event_matches(sd_json_variant *record, sd_json_variant *request) {
        sd_json_variant *payload, *peer, *uid;

        payload = sd_json_variant_by_key(record, "payload");
        peer = sd_json_variant_by_key(payload, "peerUid");
        uid = sd_json_variant_by_key(payload, "uid");

        return json_string_equal(record, "format", "io.platformd.Trust.RuntimeEvent.v2") &&
               json_string_equal(record, "type", "authentication") &&
               json_string_equal(record, "source", "io.platformd.Trust.SubmitVerificationEvent") &&
               json_string_equal(record, "evidenceQuality", "declared") &&
               sd_json_variant_is_object(payload) &&
               sd_json_variant_is_unsigned(uid) &&
               sd_json_variant_equal(uid, sd_json_variant_by_key(request, "uid")) > 0 &&
               sd_json_variant_equal(sd_json_variant_by_key(payload, "sessionId"),
                                     sd_json_variant_by_key(request, "sessionId")) > 0 &&
               sd_json_variant_equal(sd_json_variant_by_key(payload, "context"),
                                     sd_json_variant_by_key(request, "context")) > 0 &&
               json_string_equal(payload, "result", "success") &&
               json_string_equal(payload, "pamService", "platformd-verify") &&
               json_string_equal(payload, "declaredMethod", "platformd-verify") &&
               json_string_equal(payload, "phase", "verify") &&
               json_string_equal(payload, "evidenceQuality", "declared") &&
               json_true(payload, "qualifiesForFreshness") &&
               sd_json_variant_is_unsigned(peer) && sd_json_variant_unsigned(peer) == 0 &&
               json_positive(payload, "verificationBoottimeUSec") && json_positive(payload, "verificationRealtimeUSec");
}

static int events_match(sd_json_variant *events, sd_json_variant *request) {
        size_t n = sd_json_variant_elements(events);
        bool matched = false;

        if (!sd_json_variant_is_array(events) || n > 1024)
                return -EBADMSG;
        for (size_t i = 0; i < n; i++) {
                __attribute__((cleanup(sd_json_variant_unrefp))) sd_json_variant *record = NULL;
                sd_json_variant *event = sd_json_variant_by_index(events, i);
                const char *description = sd_json_variant_string(sd_json_variant_by_key(event, "description"));
                int r;

                if (!sd_json_variant_is_object(event) || !description || strlen(description) > 8192 ||
                    !json_hex(event, "digest", true))
                        return -EBADMSG;
                r = sd_json_parse(description, SD_JSON_PARSE_SENSITIVE, &record, NULL, NULL);
                if (r < 0)
                        return r;
                if (!sd_json_variant_is_object(record))
                        return -EBADMSG;
                if (!event_matches(record, request))
                        continue;
                if (matched)
                        return -EBADMSG;
                matched = true;
        }
        return matched;
}

static int measure_match(sd_json_variant *runtime, sd_json_variant *request) {
        sd_json_variant *events = sd_json_variant_by_key(runtime, "events");

        if (!json_string_equal(runtime, "format", "io.platformd.Trust.RuntimeLog.v2") ||
            !sd_json_variant_is_array(events) || !json_true(runtime, "complete"))
                return -EBADMSG;
        if (sd_json_variant_elements(events) == 0 && json_string_equal(runtime, "evidenceQuality", "observed"))
                return 0;
        if (!json_string_equal(runtime, "evidenceQuality", "measured"))
                return -EBADMSG;

        return events_match(events, request);
}

static int token_match(sd_json_variant *token, sd_json_variant *request) {
        sd_json_variant *measurements = sd_json_variant_by_key(token, "measurements"), *events = NULL;
        size_t n = sd_json_variant_elements(measurements);

        if (!sd_json_variant_is_array(measurements) || n > 16)
                return -EBADMSG;
        for (size_t i = 0; i < n; i++) {
                sd_json_variant *measurement = sd_json_variant_by_index(measurements, i);

                if (!sd_json_variant_is_object(measurement))
                        return -EBADMSG;
                if (!json_string_equal(measurement, "type", "nv-runtime-log"))
                        continue;
                if (events || !json_string_equal(measurement, "format", "io.platformd.Trust.RuntimeLog.v2"))
                        return -EBADMSG;
                events = sd_json_variant_by_key(measurement, "events");
                if (!sd_json_variant_is_array(events))
                        return -EBADMSG;
        }

        return events_match(events, request);
}

int local_evidence(sd_json_variant *request, AttestCheck check, void *userdata, uint64_t deadline,
                   sd_json_variant **ret) {
        __attribute__((cleanup(sd_varlink_close_unrefp))) sd_varlink *link = NULL;
        __attribute__((cleanup(sd_json_variant_unrefp))) sd_json_variant *response = NULL, *parameters = NULL, *token = NULL;
        sd_json_variant *context;
        const char *nonce, *raw;
        int fd, r;

        if (!request || !check || !ret)
                return -EINVAL;
        context = sd_json_variant_by_key(request, "context");
        if (!json_hex(context, "challengeHex", false))
                return -EINVAL;
        nonce = sd_json_variant_string(sd_json_variant_by_key(context, "challengeHex"));

        if ((r = time_left(check, userdata, deadline, NULL)) < 0 ||
            (r = socket_trusted("/run/platformd-trustd", TRUST_SOCKET)) < 0)
                return r;
        fd = checked_socket(TRUST_SOCKET);
        if (fd < 0)
                return fd;
        r = sd_varlink_connect_fd(&link, fd);
        if (r < 0) {
                close(fd);
                return r;
        }
        if ((r = root_peer_check(link)) < 0 ||
            (r = sd_varlink_set_input_sensitive(link)) < 0)
                return r;

        for (;;) {
                __attribute__((cleanup(sd_json_variant_unrefp))) sd_json_variant *runtime = NULL;
                uint64_t left;

                r = local_call(link, "io.platformd.Trust.GetRuntimeLog", NULL, NULL, check, userdata,
                               deadline_limit(deadline, LOCAL_TIMEOUT), &runtime);
                if (r < 0)
                        return r;
                r = measure_match(runtime, request);
                if (r < 0)
                        return r;
                if (r > 0)
                        break;
                r = time_left(check, userdata, deadline, &left);
                if (r < 0)
                        return r;
                useconds_t delay = (useconds_t) usec_min(left, POLL_INTERVAL);
                if (usleep(delay) < 0 && errno != EINTR)
                        return -errno;
        }

        r = sd_json_buildo(&parameters, SD_JSON_BUILD_PAIR_STRING("nonceHex", nonce));
        if (r < 0)
                return r;
        r = local_call(link, "io.platformd.Trust.GetAttestationToken", parameters, NULL, check, userdata,
                        deadline_limit(deadline, QUOTE_TIMEOUT), &response);
        if (r < 0)
                return r;
        raw = sd_json_variant_string(sd_json_variant_by_key(response, "eat"));
        if (!json_string_equal(response, "format", "application/vnd.platformd.attestation+json") ||
            !json_string_equal(response, "evidenceQuality", "measured") ||
            !raw || !*raw || strlen(raw) > TOKEN_MAX)
                return -EBADMSG;

        r = sd_json_parse(raw, SD_JSON_PARSE_SENSITIVE, &token, NULL, NULL);
        if (r < 0)
                return r;
        if (!sd_json_variant_is_object(token) ||
            !json_string_equal(token, "profile", "io.platformd.Trust.Attestation.v2") ||
            !json_string_equal(token, "nonceHex", nonce))
                return -EBADMSG;
        r = token_match(token, request);
        if (r <= 0)
                return r < 0 ? r : -ENODATA;

        *ret = token;
        token = NULL;
        return 0;
}
