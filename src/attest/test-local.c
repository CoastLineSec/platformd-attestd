/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#include "local.c"

enum SessionScenario {
        ONE_SESSION,
        LOCKED_SESSION,
        AMBIGUOUS_SESSION,
        MISSING_SESSION,
};

static enum SessionScenario session_scenario;

int sd_pidfd_get_session(int pidfd, char **ret) {
        assert(pidfd == 10 && ret);
        return -ENODATA;
}

int sd_pidfd_get_owner_uid(int pidfd, uid_t *ret) {
        assert(pidfd == 10 && ret);
        *ret = 1000;
        return 0;
}

int sd_uid_get_sessions(uid_t uid, int require_active, char ***ret) {
        const char *ids[] = {
                require_active ? "c23" : "manager",
                "3",
                session_scenario == AMBIGUOUS_SESSION ? "7" : NULL,
                NULL,
        };
        char **sessions;
        size_t n = 0;

        assert(uid == 1000 && ret);
        sessions = calloc(sizeof(ids) / sizeof(ids[0]), sizeof(char *));
        assert(sessions);
        for (; ids[n]; n++) {
                sessions[n] = strdup(ids[n]);
                assert(sessions[n]);
        }
        *ret = sessions;
        return (int) n;
}

int sd_session_get_uid(const char *session, uid_t *ret) {
        assert(ret);
        if (streq(session, "c23") || (streq(session, "3") && session_scenario == MISSING_SESSION))
                return -ENXIO;
        *ret = 1000;
        return 0;
}

int sd_session_is_remote(const char *session) {
        assert(session);
        return 0;
}

int sd_session_is_active(const char *session) {
        assert(session);
        return 1;
}

int sd_session_get_type(const char *session, char **ret) {
        *ret = strdup(streq(session, "manager") ? "unspecified" : "wayland");
        return *ret ? 0 : -ENOMEM;
}

int sd_session_get_class(const char *session, char **ret) {
        *ret = strdup(streq(session, "manager") ? "manager" : "user");
        return *ret ? 0 : -ENOMEM;
}

int sd_session_get_state(const char *session, char **ret) {
        assert(session);
        *ret = strdup("active");
        return *ret ? 0 : -ENOMEM;
}

int sd_bus_open_system(sd_bus **ret) {
        return sd_bus_new(ret);
}

int sd_bus_get_property_trivial(sd_bus *bus, const char *destination, const char *path,
                               const char *interface, const char *member, sd_bus_error *error, char type, void *ret) {
        assert(bus && path && !error && ret && type == 'b');
        assert(streq(destination, "org.freedesktop.login1"));
        assert(streq(interface, "org.freedesktop.login1.Session"));
        assert(streq(member, "LockedHint"));
        *(int *) ret = session_scenario == LOCKED_SESSION;
        return 0;
}

static void test_session_fallback(void) {
        __attribute__((cleanup(freep))) char *selected = NULL;

        assert(local_session_get(10, 1001, &selected) == -EACCES && !selected);
        session_scenario = LOCKED_SESSION;
        assert(local_session_get(10, 1000, &selected) == -EACCES && !selected);
        session_scenario = AMBIGUOUS_SESSION;
        assert(local_session_get(10, 1000, &selected) == -ENOTUNIQ && !selected);
        session_scenario = MISSING_SESSION;
        assert(local_session_get(10, 1000, &selected) == -ENXIO && !selected);
        session_scenario = ONE_SESSION;
        assert(local_session_get(10, 1000, &selected) == 0 && streq(selected, "3"));
}

static sd_json_variant *parse(const char *text) {
        sd_json_variant *value = NULL;

        assert(sd_json_parse(text, 0, &value, NULL, NULL) >= 0);
        return value;
}

static void test_measured_event(void) {
        __attribute__((cleanup(sd_json_variant_unrefp))) sd_json_variant *record = NULL, *event = NULL,
                *events = NULL, *request = NULL, *runtime = NULL, *token = NULL, *wrong = NULL;
        __attribute__((cleanup(freep))) char *description = NULL;
        const char nonce[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        request = parse("{\"uid\":1000,\"sessionId\":\"c3\",\"context\":{"
                        "\"challengeHex\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                        "\"audience\":\"https://example.test\","
                        "\"operationDigestHex\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}}");
        wrong = parse("{\"uid\":1001,\"sessionId\":\"c3\",\"context\":{}}");
        runtime = parse("{\"format\":\"io.platformd.Trust.RuntimeLog.v2\",\"complete\":true,"
                        "\"evidenceQuality\":\"observed\",\"events\":[]}");
        assert(measure_match(runtime, request) == 0);
        runtime = sd_json_variant_unref(runtime);

        assert(sd_json_buildo(&record,
                       SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.RuntimeEvent.v2"),
                       SD_JSON_BUILD_PAIR_STRING("type", "authentication"),
                       SD_JSON_BUILD_PAIR_STRING("source", "io.platformd.Trust.SubmitVerificationEvent"),
                       SD_JSON_BUILD_PAIR_STRING("evidenceQuality", "declared"),
                       SD_JSON_BUILD_PAIR("payload", SD_JSON_BUILD_OBJECT(
                               SD_JSON_BUILD_PAIR_UNSIGNED("uid", 1000),
                               SD_JSON_BUILD_PAIR_STRING("sessionId", "c3"),
                               SD_JSON_BUILD_PAIR_VARIANT("context", sd_json_variant_by_key(request, "context")),
                               SD_JSON_BUILD_PAIR_STRING("result", "success"),
                               SD_JSON_BUILD_PAIR_STRING("pamService", "platformd-verify"),
                               SD_JSON_BUILD_PAIR_STRING("declaredMethod", "platformd-verify"),
                               SD_JSON_BUILD_PAIR_STRING("phase", "verify"),
                               SD_JSON_BUILD_PAIR_STRING("evidenceQuality", "declared"),
                               SD_JSON_BUILD_PAIR_BOOLEAN("qualifiesForFreshness", true),
                               SD_JSON_BUILD_PAIR_UNSIGNED("peerUid", 0),
                               SD_JSON_BUILD_PAIR_UNSIGNED("verificationBoottimeUSec", 10),
                               SD_JSON_BUILD_PAIR_UNSIGNED("verificationRealtimeUSec", 20)))) >= 0);
        assert(sd_json_variant_format(record, 0, &description) >= 0);
        assert(sd_json_buildo(&event, SD_JSON_BUILD_PAIR_STRING("description", description),
                              SD_JSON_BUILD_PAIR_STRING("digest", nonce)) >= 0);
        assert(sd_json_variant_append_array(&events, event) >= 0);
        assert(sd_json_buildo(&runtime,
                              SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.RuntimeLog.v2"),
                              SD_JSON_BUILD_PAIR_STRING("evidenceQuality", "measured"),
                              SD_JSON_BUILD_PAIR_BOOLEAN("complete", true),
                              SD_JSON_BUILD_PAIR_VARIANT("events", events)) >= 0);
        assert(measure_match(runtime, request) == 1);
        assert(measure_match(runtime, wrong) == 0);
        assert(sd_json_variant_set_field_boolean(&runtime, "complete", false) >= 0);
        assert(measure_match(runtime, request) == -EBADMSG);

        assert(sd_json_buildo(&token,
                              SD_JSON_BUILD_PAIR("measurements", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(
                                      SD_JSON_BUILD_PAIR_STRING("type", "nv-runtime-log"),
                                      SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.RuntimeLog.v2"),
                                      SD_JSON_BUILD_PAIR_VARIANT("events", events))))) >= 0);
        assert(token_match(token, request) == 1);
        assert(token_match(token, wrong) == 0);

        assert(sd_json_variant_append_array(&events, event) >= 0);
        assert(events_match(events, request) == -EBADMSG);
}

static int check(void *userdata) {
        (void) userdata;
        return 0;
}

static int notify(const char *message, void *userdata) {
        unsigned *count = userdata;

        assert(streq(message, "Test message"));
        (*count)++;
        return 0;
}

static void test_verification_reply(bool verified) {
        __attribute__((cleanup(sd_varlink_close_unrefp))) sd_varlink *link = NULL;
        const char reply[] = "{\"parameters\":{\"message\":{\"style\":\"info\",\"text\":\"Test message\"}},"
                             "\"continues\":true}\0";
        const char success[] = "{\"parameters\":{\"result\":{\"verified\":true,"
                               "\"method\":\"platformd-verify\",\"realtimeUSec\":1}}}";
        const char failure[] = "{\"parameters\":{\"result\":{\"verified\":false,"
                               "\"method\":\"platformd-verify\",\"realtimeUSec\":1}}}";
        const char *result = verified ? success : failure;
        int pair[2];
        unsigned count = 0;

        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        assert(sd_varlink_connect_fd(&link, pair[0]) >= 0);
        assert(write(pair[1], reply, sizeof(reply) - 1) == (ssize_t) sizeof(reply) - 1);
        assert(write(pair[1], result, strlen(result) + 1) == (ssize_t) strlen(result) + 1);
        assert(local_call(link, "io.platformd.Verify.VerifyUserWithContext", NULL,
                          notify, check, &count, attest_now() + USEC_PER_SEC, NULL) == (verified ? 0 : -EACCES));
        assert(count == 1);
        close(pair[1]);
}

int main(void) {
        test_session_fallback();
        test_measured_event();
        test_verification_reply(true);
        test_verification_reply(false);
        return 0;
}
