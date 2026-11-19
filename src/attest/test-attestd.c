/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <sys/wait.h>

#define main attestd_main
#include "attestd.c"
#undef main

#define DIGEST "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define OTHER_DIGEST "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define AUDIENCE "https://fixture.test"
#define CALL_PREFIX "{\"method\":\"io.platformd.Attest.Read\",\"parameters\":"

typedef enum Failure {
        GRANT,
        WRONG_PEER,
        NO_DISCLOSURE,
        WRONG_SESSION,
        WRONG_AUDIENCE,
        VERIFY_DENIED,
        WRONG_NONCE,
        REMOTE_DENIED,
} Failure;

struct Remote {
        AttestCheck check;
        void *userdata;
};

static Failure failure;

int profile_load(const char *path, Profile *profile) {
        (void) path;
        *profile = (Profile) {
                .uid = getuid() + (failure == WRONG_PEER),
                .audience = AUDIENCE,
                .key_id = DIGEST,
                .label = "Fixture",
                .allow_retained_history = failure != NO_DISCLOSURE,
        };
        return 0;
}

void profile_done(Profile *profile) {
        (void) profile;
}

int local_session_get(int pidfd, uid_t uid, char **ret) {
        assert(pidfd >= 0 && uid == getuid());
        *ret = strdup("fixture");
        return *ret ? 0 : -ENOMEM;
}

int local_connect_verify(int fd) {
        (void) fd;
        assert(false);
}

int local_verify(
                uid_t uid, const char *session, const char *label, sd_json_variant *context,
                AttestNotify notify, AttestCheck check, void *userdata, uint64_t deadline) {

        assert(failure != WRONG_SESSION && failure != WRONG_AUDIENCE);
        assert(uid == getuid() && strcmp(session, "fixture") == 0 && strcmp(label, "Fixture") == 0);
        assert(field_is(context, "challengeHex", DIGEST));
        assert(attest_now() < deadline && check(userdata) == 0);
        return failure == VERIFY_DENIED ? -ECANCELED : notify("Fixture notification", userdata);
}

int local_evidence(sd_json_variant *request, AttestCheck check, void *userdata, uint64_t deadline,
                   sd_json_variant **ret) {
        assert(failure != VERIFY_DENIED && field_is(request, "sessionId", "fixture"));
        assert(attest_now() < deadline && check(userdata) == 0);
        return sd_json_buildo(ret,
                             SD_JSON_BUILD_PAIR_STRING("profile", "io.platformd.Trust.Attestation.v2"),
                             SD_JSON_BUILD_PAIR_STRING("nonceHex", failure == WRONG_NONCE ? OTHER_DIGEST : DIGEST));
}

int remote_open(const Profile *profile, AttestCheck check, void *userdata, uint64_t deadline, Remote **ret) {
        assert(failure != WRONG_PEER && failure != NO_DISCLOSURE);
        assert(profile->uid == getuid() && profile->allow_retained_history);
        assert(attest_now() < deadline && check(userdata) == 0);
        *ret = malloc(sizeof(Remote));
        if (!*ret)
                return -ENOMEM;
        **ret = (Remote) { .check = check, .userdata = userdata };
        return 0;
}

int remote_begin(Remote *remote, sd_json_variant **ret) {
        assert(remote->check(remote->userdata) == 0);
        return sd_json_buildo(ret,
                             SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.AuthenticationRequest.v1"),
                             SD_JSON_BUILD_PAIR_STRING("keyId", DIGEST),
                             SD_JSON_BUILD_PAIR_STRING("requestId", DIGEST),
                             SD_JSON_BUILD_PAIR_OBJECT("request",
                                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", getuid()),
                                        SD_JSON_BUILD_PAIR_STRING("sessionId",
                                                                   failure == WRONG_SESSION ? "other" : "fixture"),
                                        SD_JSON_BUILD_PAIR_OBJECT("context",
                                                SD_JSON_BUILD_PAIR_STRING("challengeHex", DIGEST),
                                                SD_JSON_BUILD_PAIR_STRING("audience",
                                                                           failure == WRONG_AUDIENCE ?
                                                                           "https://other.test" : AUDIENCE),
                                                SD_JSON_BUILD_PAIR_STRING("operationDigestHex", DIGEST))));
}

int remote_complete(Remote *remote, sd_json_variant *token, void **ret, size_t *size) {
        assert(failure != WRONG_NONCE && field_is(token, "nonceHex", DIGEST));
        assert(remote->check(remote->userdata) == 0);
        if (failure == REMOTE_DENIED)
                return -EACCES;
        *size = 3;
        *ret = strdup("abc");
        return *ret ? 0 : -ENOMEM;
}

Remote *remote_free(Remote *remote) {
        free(remote);
        return NULL;
}

static void test_exchange(const char *call, Failure scenario, bool notification, bool granted) {
        char buffer[4096];
        size_t used = 0;
        int fds[2], status;
        pid_t child;

        failure = scenario;
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
        assert((child = fork()) >= 0);
        if (child == 0) {
                assert(close(fds[0]) == 0);
                assert(dup2(fds[1], STDIN_FILENO) == STDIN_FILENO);
                assert(close(fds[1]) == 0);
                exit(run("/unused") < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }
        assert(close(fds[1]) == 0);
        assert(send(fds[0], call, strlen(call) + 1, MSG_NOSIGNAL) == (ssize_t) strlen(call) + 1);
        for (;;) {
                struct pollfd p = { .fd = fds[0], .events = POLLIN };
                ssize_t n;

                assert(used < sizeof buffer);
                assert(poll(&p, 1, 6000) == 1);
                n = recv(fds[0], buffer + used, sizeof buffer - used, MSG_DONTWAIT);
                assert(n >= 0);
                if (n == 0)
                        break;
                used += n;
        }
        assert(close(fds[0]) == 0);
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);

        char *frame = buffer, *end = buffer + used;
        if (notification) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *notice = NULL;
                sd_json_variant *more, *parameters;
                char *nul = memchr(frame, 0, (size_t) (end - frame));

                assert(nul && sd_json_parse(frame, 0, &notice, NULL, NULL) >= 0);
                assert(has_fields(notice, 2));
                more = sd_json_variant_by_key(notice, "continues");
                assert(sd_json_variant_is_boolean(more) && sd_json_variant_boolean(more));
                parameters = sd_json_variant_by_key(notice, "parameters");
                assert(has_fields(parameters, 1) && field_is(parameters, "message", "Fixture notification"));
                frame = nul + 1;
        }
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        assert(frame < end && memchr(frame, 0, (size_t) (end - frame)) == end - 1);
        assert(sd_json_parse(frame, 0, &reply, NULL, NULL) >= 0);
        if (granted) {
                sd_json_variant *parameters = sd_json_variant_by_key(reply, "parameters");

                assert(has_fields(reply, 1) && has_fields(parameters, 2));
                assert(field_is(parameters, "status", "granted") && field_is(parameters, "dataBase64", "YWJj"));
        } else {
                sd_json_variant *parameters = sd_json_variant_by_key(reply, "parameters");

                assert(field_is(reply, "error", ATTEST_DENIED));
                assert(!parameters || sd_json_variant_is_blank_object(parameters));
        }
}

int main(void) {
        static const char request[] = CALL_PREFIX "{\"profile\":\"protected-read\"},\"more\":true}";
        int fds[2], r;
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *probe = NULL;

        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
        assert(sd_varlink_connect_fd(&probe, fds[0]) >= 0);
        r = sd_varlink_get_peer_pidfd(probe);
        probe = sd_varlink_close_unref(probe);
        assert(close(fds[1]) == 0);
        if (r == -EPERM || r == -EACCES || r == -ENOPROTOOPT || r == -EOPNOTSUPP)
                return 77;
        assert(r >= 0);

        test_exchange(request, GRANT, true, true);
        test_exchange(CALL_PREFIX "{\"profile\":\"unknown\"},\"more\":true}", GRANT, false, false);
        test_exchange(CALL_PREFIX "{\"profile\":\"protected-read\"}}", GRANT, false, false);
        test_exchange(CALL_PREFIX "{\"profile\":\"protected-read\",\"profile\":\"unknown\"},\"more\":true}",
                      GRANT, false, false);
        test_exchange(request, WRONG_PEER, false, false);
        test_exchange(request, NO_DISCLOSURE, false, false);
        test_exchange(request, WRONG_SESSION, false, false);
        test_exchange(request, WRONG_AUDIENCE, false, false);
        test_exchange(request, VERIFY_DENIED, false, false);
        test_exchange(request, WRONG_NONCE, true, false);
        test_exchange(request, REMOTE_DENIED, true, false);
        return 0;
}
