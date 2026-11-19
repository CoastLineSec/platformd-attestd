/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-varlink-idl.h>
#include <systemd/sd-varlink.h>

#include "attestd.h"

#define USEC_PER_SEC UINT64_C(1000000)
#define INITIAL_TIMEOUT_USEC (3 * USEC_PER_SEC)
#define OUTPUT_TIMEOUT_USEC (2 * USEC_PER_SEC)
#define ATTEST_METHOD "io.platformd.Attest.Read"
#define ATTEST_DENIED "io.platformd.Attest.Denied"
#define _cleanup_(f) __attribute__((cleanup(f)))

static SD_VARLINK_DEFINE_METHOD_FULL(Read, SD_VARLINK_SUPPORTS_MORE,
        SD_VARLINK_DEFINE_INPUT(profile, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(message, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
        SD_VARLINK_DEFINE_OUTPUT(status, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
        SD_VARLINK_DEFINE_OUTPUT(dataBase64, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(Denied);

static SD_VARLINK_DEFINE_INTERFACE(
                io_platformd_Attest,
                "io.platformd.Attest",
                &vl_method_Read,
                &vl_error_Denied);

typedef struct Broker {
        Profile profile;
        bool profile_valid;
        sd_event *event;
        timer_t timer;
} Broker;

typedef struct Transaction {
        Broker *broker;
        sd_varlink *link;
        uid_t uid;
        int pidfd;
        char *session;
        uint64_t deadline;
} Transaction;

static int arm_timer(timer_t timer, uint64_t deadline) {
        struct itimerspec value = {
                .it_value = {
                        .tv_sec = deadline / USEC_PER_SEC,
                        .tv_nsec = (deadline % USEC_PER_SEC) * 1000,
                },
        };

        return timer_settime(timer, TIMER_ABSTIME, &value, NULL) < 0 ? -errno : 0;
}

static int flush_reply(Transaction *t) {
        uint64_t now = attest_now(), deadline;
        int r, k;

        if (now == UINT64_MAX)
                return -EIO;
        deadline = now + OUTPUT_TIMEOUT_USEC;
        if (t->deadline && t->deadline < deadline)
                deadline = t->deadline;
        if (now >= deadline)
                return -ETIMEDOUT;

        /* Varlink flush may block while the client is not reading. */
        r = arm_timer(t->broker->timer, deadline);
        if (r < 0)
                return r;
        r = sd_varlink_flush(t->link);
        if (!t->deadline)
                return r;
        k = arm_timer(t->broker->timer, t->deadline);
        return r < 0 ? r : k;
}

static int check_peer(const Transaction *t) {
        struct pollfd fds[2] = {
                { .fd = t->pidfd, .events = POLLIN },
                { .fd = sd_varlink_get_fd(t->link), .events = POLLIN | POLLRDHUP },
        };
        int r;

        if (attest_now() >= t->deadline)
                return -ETIMEDOUT;
        if (fds[0].fd < 0 || fds[1].fd < 0)
                return -ENOTCONN;
        r = poll(fds, 2, 0);
        if (r < 0)
                return -errno;
        if (r > 0)
                return -ECANCELED;
        return 0;
}

static int transaction_check(void *userdata) {
        Transaction *t = userdata;
        char *session = NULL;
        int r;

        r = check_peer(t);
        if (r < 0)
                return r;
        r = local_session_get(t->pidfd, t->uid, &session);
        if (r < 0)
                return r;
        bool identical = session && strcmp(session, t->session) == 0;
        free(session);
        if (!identical)
                return -ECANCELED;
        return check_peer(t);
}

static int transaction_notify(const char *message, void *userdata) {
        Transaction *t = userdata;
        int r;

        r = transaction_check(t);
        if (r < 0)
                return r;
        r = sd_varlink_notifybo(t->link, SD_JSON_BUILD_PAIR_STRING("message", message));
        if (r < 0)
                return r;
        return flush_reply(t);
}

static bool has_fields(sd_json_variant *v, size_t n) {
        return sd_json_variant_is_object(v) && sd_json_variant_elements(v) == 2 * n;
}

static bool field_is(sd_json_variant *v, const char *name, const char *value) {
        const char *field = sd_json_variant_string(sd_json_variant_by_key(v, name));

        return field && value && strcmp(field, value) == 0;
}

static bool valid_digest(const char *s) {
        return s && strlen(s) == 64 && strspn(s, "0123456789abcdef") == 64;
}

static int validate_challenge(
                const Transaction *t,
                sd_json_variant *issued,
                sd_json_variant **ret_request,
                sd_json_variant **ret_context) {
        sd_json_variant *request, *context, *uid;
        const char *nonce;

        if (!has_fields(issued, 4) ||
            !field_is(issued, "format", "io.platformd.Trust.AuthenticationRequest.v1") ||
            !field_is(issued, "keyId", t->broker->profile.key_id))
                return -EBADMSG;

        nonce = sd_json_variant_string(sd_json_variant_by_key(issued, "requestId"));
        request = sd_json_variant_by_key(issued, "request");
        if (!valid_digest(nonce) || !has_fields(request, 3) || !field_is(request, "sessionId", t->session))
                return -EBADMSG;
        uid = sd_json_variant_by_key(request, "uid");
        if (!sd_json_variant_is_unsigned(uid) || sd_json_variant_unsigned(uid) != t->uid)
                return -EBADMSG;

        context = sd_json_variant_by_key(request, "context");
        if (!has_fields(context, 3) ||
            !field_is(context, "challengeHex", nonce) ||
            !field_is(context, "audience", t->broker->profile.audience) ||
            !valid_digest(sd_json_variant_string(sd_json_variant_by_key(context, "operationDigestHex"))))
                return -EBADMSG;

        *ret_request = request;
        *ret_context = context;
        return 0;
}

static int read_resource(Transaction *t, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *issued = NULL, *token = NULL;
        sd_json_variant *request, *context;
        const char *stage = "resolve the requester session";
        Remote *remote = NULL;
        void *data = NULL;
        size_t size = 0;
        int r;

        r = local_session_get(t->pidfd, t->uid, &t->session);
        if (r < 0)
                goto finish;
        if (!t->session) {
                r = -ENODATA;
                goto finish;
        }

        stage = "acquire a verifier challenge";
        if ((r = transaction_check(t)) < 0 ||
            (r = remote_open(&t->broker->profile, transaction_check, t, t->deadline, &remote)) < 0 ||
            (r = remote_begin(remote, &issued)) < 0 ||
            (r = validate_challenge(t, issued, &request, &context)) < 0)
                goto finish;

        stage = "verify user presence";
        if ((r = transaction_check(t)) < 0 ||
            (r = local_verify(t->uid, t->session, t->broker->profile.label, context,
                              transaction_notify, transaction_check, t, t->deadline)) < 0)
                goto finish;

        stage = "acquire attestation evidence";
        if ((r = transaction_check(t)) < 0 ||
            (r = local_evidence(request, transaction_check, t, t->deadline, &token)) < 0)
                goto finish;
        if (token)
                sd_json_variant_sensitive(token);
        if (!sd_json_variant_is_object(token) ||
            !field_is(token, "profile", "io.platformd.Trust.Attestation.v2") ||
            !field_is(token, "nonceHex", sd_json_variant_string(sd_json_variant_by_key(context, "challengeHex")))) {
                r = -EBADMSG;
                goto finish;
        }

        stage = "redeem the verifier challenge";
        if ((r = transaction_check(t)) < 0 ||
            (r = remote_complete(remote, token, &data, &size)) < 0 ||
            (r = transaction_check(t)) < 0)
                goto finish;
        if (!data || size == 0 || size > ATTEST_RESOURCE_MAX) {
                r = -EBADMSG;
                goto finish;
        }
        r = sd_json_buildo(ret,
                           SD_JSON_BUILD_PAIR_STRING("status", "granted"),
                           SD_JSON_BUILD_PAIR_BASE64("dataBase64", data, size));
        if (r >= 0)
                sd_json_variant_sensitive(*ret);

finish:
        if (r < 0)
                (void) sd_journal_print(LOG_DEBUG, "Failed to %s: %s", stage, strerror(-r));
        remote_free(remote);
        if (data) {
                explicit_bzero(data, size);
                free(data);
        }
        return r;
}

static int method_read(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        Broker *broker = userdata;
        Transaction t = { .broker = broker, .link = link, .pidfd = -1 };
        int r;

        if (flags != SD_VARLINK_METHOD_MORE ||
            !broker->profile_valid || !broker->profile.allow_retained_history ||
            !has_fields(parameters, 1) || !field_is(parameters, "profile", ATTEST_PROFILE) ||
            sd_varlink_get_peer_uid(link, &t.uid) < 0 || t.uid != broker->profile.uid)
                goto deny;
        r = sd_varlink_get_peer_pidfd(link);
        if (r < 0) {
                (void) sd_journal_print(LOG_DEBUG, "Failed to acquire the requester process: %s", strerror(-r));
                goto deny;
        }
        t.pidfd = r;

        uint64_t now = attest_now();
        if (now == UINT64_MAX)
                goto deny;
        t.deadline = now + ATTEST_TIMEOUT_USEC;
        if ((r = arm_timer(broker->timer, t.deadline)) < 0 ||
            (r = check_peer(&t)) < 0 ||
            (r = read_resource(&t, &reply)) < 0 ||
            (r = transaction_check(&t)) < 0)
                goto deny;
        r = sd_varlink_reply(link, reply);
        goto finish;

deny:
        r = sd_varlink_error(link, ATTEST_DENIED, NULL);
finish:
        if (r >= 0)
                (void) flush_reply(&t);
        free(t.session);
        return sd_event_exit(broker->event, 0);
}

static void on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Broker *broker = userdata;

        (void) server;
        (void) link;
        (void) sd_event_exit(broker->event, 0);
}

static int on_timeout(sd_event_source *source, uint64_t usec, void *userdata) {
        Broker *broker = userdata;

        (void) source;
        (void) usec;
        return sd_event_exit(broker->event, 0);
}

static int run(const char *path) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *connection = NULL;
        Broker broker = {};
        sigset_t alarms;
        int fd, r;

        r = sd_is_socket(STDIN_FILENO, AF_UNIX, SOCK_STREAM, false);
        if (r <= 0)
                return r < 0 ? r : -ENOTSOCK;
        if (setrlimit(RLIMIT_CORE, &(struct rlimit) {}) < 0)
                return -errno;

        if (sigemptyset(&alarms) < 0 || sigaddset(&alarms, SIGALRM) < 0 ||
            sigaction(SIGALRM, &(struct sigaction) { .sa_handler = SIG_DFL }, NULL) < 0 ||
            sigprocmask(SIG_UNBLOCK, &alarms, NULL) < 0 ||
            timer_create(CLOCK_BOOTTIME, NULL, &broker.timer) < 0)
                return -errno;
        uint64_t now = attest_now();
        if (now == UINT64_MAX) {
                r = -EIO;
                goto finish;
        }
        if ((r = arm_timer(broker.timer, now + INITIAL_TIMEOUT_USEC + OUTPUT_TIMEOUT_USEC)) < 0 ||
            (r = sd_event_new(&event)) < 0 ||
            (r = sd_varlink_server_new(&server, SD_VARLINK_SERVER_INHERIT_USERDATA)) < 0)
                goto finish;
        broker.event = event;
        r = profile_load(path, &broker.profile);
        broker.profile_valid = r >= 0;
        if (r < 0)
                (void) sd_journal_print(LOG_DEBUG, "Failed to load the verifier profile: %s", strerror(-r));
        (void) sd_varlink_server_set_description(server, "platformd-attestd");
        sd_varlink_server_set_userdata(server, &broker);
        if ((r = sd_varlink_server_bind_disconnect(server, on_disconnect)) < 0 ||
            (r = sd_varlink_server_add_interface(server, &vl_interface_io_platformd_Attest)) < 0 ||
            (r = sd_varlink_server_bind_method(server, ATTEST_METHOD, method_read)) < 0 ||
            (r = sd_varlink_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL)) < 0 ||
            (r = sd_event_add_time(event, NULL, CLOCK_BOOTTIME, now + INITIAL_TIMEOUT_USEC, 0, on_timeout, &broker)) < 0)
                goto finish;

        fd = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }
        r = sd_varlink_server_add_connection(server, fd, &connection);
        if (r < 0) {
                (void) close(fd);
                goto finish;
        }
        sd_varlink_ref(connection);
        (void) close(STDIN_FILENO);
        r = sd_event_loop(event);

finish:
        connection = sd_varlink_close_unref(connection);
        (void) timer_delete(broker.timer);
        profile_done(&broker.profile);
        return r;
}

int main(int argc, char *argv[]) {
        const char *path = ATTEST_CONFIG;
        int r;

        if (argc == 3 && strcmp(argv[1], "--connect-verify") == 0) {
                char *end;
                long fd;

                if (geteuid() == 0 || !argv[2][0] || strspn(argv[2], "0123456789") != strlen(argv[2]))
                        return EXIT_FAILURE;
                errno = 0;
                fd = strtol(argv[2], &end, 10);
                if (errno != 0 || *end || fd < 3 || fd > INT_MAX)
                        return EXIT_FAILURE;
                return local_connect_verify((int) fd) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        }
        if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
                puts("platformd-attestd [CONFIG]\n\nCoordinate a platform attestation request on an activated Unix socket.");
                return EXIT_SUCCESS;
        }
        if (argc == 2 && argv[1][0] == '/')
                path = argv[1];
        else if (argc != 1)
                return EXIT_FAILURE;

        if (geteuid() != 0)
                return EXIT_FAILURE;
        r = run(path);
        if (r < 0) {
                fprintf(stderr, "Failed to serve attestation request: %s\n", strerror(-r));
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}
