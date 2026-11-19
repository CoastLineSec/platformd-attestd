/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <systemd/sd-varlink.h>

#include "../attest/attestd.h"
#include "read.h"

#define _cleanup_(f) __attribute__((cleanup(f)))

#define READ_TIMEOUT_USEC (ATTEST_TIMEOUT_USEC + UINT64_C(10000000))
#define NOTICE_MAX 1024U
#define NOTICES_MAX 32U

typedef struct ReadReply {
        void (*notify)(const char *message, void *userdata);
        void *userdata;
        char *text;
        unsigned n_notices;
        int result;
        bool done;
} ReadReply;

void read_document_free(char *text) {
        if (!text)
                return;
        explicit_bzero(text, strlen(text) + 1);
        free(text);
}

static void reply_done(ReadReply *reply) {
        read_document_free(reply->text);
}

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static bool text_valid(const char *text, size_t size, bool multiline) {
        if (size == 0 || !g_utf8_validate(text, size, NULL))
                return false;

        for (const char *p = text; p < text + size; p = g_utf8_next_char(p)) {
                gunichar c = g_utf8_get_char(p);

                if (g_unichar_iscntrl(c) && !(multiline && (c == '\n' || c == '\t')))
                        return false;
        }

        return true;
}

static int parse_document(sd_json_variant *parameters, char **ret) {
        sd_json_variant *data;
        const char *status, *base64;
        void *bytes = NULL;
        char *text = NULL;
        size_t size;
        int r;

        if (sd_json_variant_elements(parameters) != 4)
                return -EBADMSG;
        status = sd_json_variant_string(sd_json_variant_by_key(parameters, "status"));
        if (!status || strcmp(status, "granted") != 0)
                return -EBADMSG;
        data = sd_json_variant_by_key(parameters, "dataBase64");
        base64 = sd_json_variant_string(data);
        if (!base64 || strlen(base64) > ((ATTEST_RESOURCE_MAX + 2) / 3) * 4)
                return -EBADMSG;

        r = sd_json_variant_unbase64(data, &bytes, &size);
        if (r < 0)
                return r == -ENOMEM ? r : -EBADMSG;
        if (size > ATTEST_RESOURCE_MAX || !text_valid(bytes, size, true))
                r = -EBADMSG;
        else {
                text = strndup(bytes, size);
                r = text ? 0 : -ENOMEM;
        }
        if (bytes)
                explicit_bzero(bytes, size);
        free(bytes);
        if (r < 0)
                return r;
        *ret = text;
        return 0;
}

static int on_read_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id,
                         sd_varlink_reply_flags_t flags, void *userdata) {
        ReadReply *reply = userdata;
        int r = -EBADMSG;

        if (reply->done)
                return 0;

        if (error_id) {
                if (flags == SD_VARLINK_REPLY_ERROR && strcmp(error_id, "io.platformd.Attest.Denied") == 0)
                        r = -EACCES;
                else if (flags & SD_VARLINK_REPLY_LOCAL) {
                        if (strcmp(error_id, SD_VARLINK_ERROR_DISCONNECTED) == 0)
                                r = -ENOTCONN;
                        else if (strcmp(error_id, SD_VARLINK_ERROR_TIMEOUT) == 0)
                                r = -ETIMEDOUT;
                }
        } else if (sd_json_variant_is_object(parameters)) {
                if (flags == SD_VARLINK_REPLY_CONTINUES) {
                        const char *message;
                        size_t size;

                        message = sd_json_variant_string(sd_json_variant_by_key(parameters, "message"));
                        if (sd_json_variant_elements(parameters) == 2 && ++reply->n_notices <= NOTICES_MAX &&
                            message && (size = strlen(message)) <= NOTICE_MAX && text_valid(message, size, false)) {
                                if (reply->notify)
                                        reply->notify(message, reply->userdata);
                                return 0;
                        }
                } else if (flags == 0)
                        r = parse_document(parameters, &reply->text);
        }

        reply->result = r;
        reply->done = true;
        return 0;
}

static int check_read(GCancellable *cancellable, uint64_t deadline) {
        uint64_t now;

        if (g_cancellable_is_cancelled(cancellable))
                return -ECANCELED;
        now = attest_now();
        if (now == UINT64_MAX)
                return -EIO;
        return now >= deadline ? -ETIMEDOUT : 0;
}

static int wait_reply(sd_varlink *link, GCancellable *cancellable, uint64_t deadline, ReadReply *reply) {
        _cleanup_(closep) int timer = -1;
        struct pollfd fds[3] = {};
        struct itimerspec expiry = { .it_value = {
                .tv_sec = deadline / UINT64_C(1000000),
                .tv_nsec = (deadline % UINT64_C(1000000)) * 1000,
        } };
        int r;

        timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (timer < 0 || timerfd_settime(timer, TFD_TIMER_ABSTIME, &expiry, NULL) < 0)
                return -errno;
        r = sd_varlink_get_fd(link);
        if (r < 0)
                return r;
        fds[0].fd = r;
        fds[1] = (struct pollfd) { .fd = timer, .events = POLLIN };
        fds[2] = (struct pollfd) { .fd = g_cancellable_get_fd(cancellable), .events = POLLIN };
        if (fds[2].fd < 0)
                return -EMFILE;

        for (;;) {
                r = check_read(cancellable, deadline);
                if (r < 0)
                        break;
                if (reply->done) {
                        r = reply->result;
                        break;
                }
                r = sd_varlink_process(link);
                if (r < 0)
                        break;
                if (r > 0 || reply->done)
                        continue;

                r = sd_varlink_get_events(link);
                if (r < 0)
                        break;
                fds[0].events = r;
                if (poll(fds, G_N_ELEMENTS(fds), -1) < 0) {
                        if (errno == EINTR)
                                continue;
                        r = -errno;
                        break;
                }
                if (fds[2].revents) {
                        r = -ECANCELED;
                        break;
                }
                if (fds[1].revents) {
                        r = -ETIMEDOUT;
                        break;
                }
                if (fds[0].revents & POLLNVAL) {
                        r = -EBADF;
                        break;
                }
        }

        g_cancellable_release_fd(cancellable);
        return r;
}

int read_document(const char *socket_path, GCancellable *cancellable,
                  void (*notify)(const char *message, void *userdata), void *userdata, char **ret) {
        _cleanup_(reply_done) ReadReply reply = { .notify = notify, .userdata = userdata };
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *link = NULL;
        uint64_t now, deadline;
        uid_t peer;
        int r;

        if (!socket_path || socket_path[0] != '/' || !socket_path[1] || !cancellable || !ret)
                return -EINVAL;
        if (g_cancellable_is_cancelled(cancellable))
                return -ECANCELED;
        now = attest_now();
        if (now == UINT64_MAX)
                return -EIO;
        deadline = now + READ_TIMEOUT_USEC;

        r = sd_varlink_connect_address(&link, socket_path);
        if (r < 0)
                return r;
        r = sd_varlink_get_peer_uid(link, &peer);
        if (r < 0)
                return r;
        if (peer != 0)
                return -EPERM;

        sd_varlink_set_userdata(link, &reply);
        if ((r = sd_varlink_set_input_sensitive(link)) < 0 ||
            (r = sd_varlink_set_relative_timeout(link, READ_TIMEOUT_USEC)) < 0 ||
            (r = sd_varlink_bind_reply(link, on_read_reply)) < 0 ||
            (r = sd_varlink_observebo(link, "io.platformd.Attest.Read", SD_JSON_BUILD_PAIR_STRING("profile", ATTEST_PROFILE))) < 0)
                return r;

        r = wait_reply(link, cancellable, deadline, &reply);
        if (r < 0)
                return r;
        r = check_read(cancellable, deadline);
        if (r < 0)
                return r;
        *ret = reply.text;
        reply.text = NULL;
        return 0;
}
