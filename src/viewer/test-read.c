/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#include "read.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <systemd/sd-varlink.h>

static bool trust_fixture, shorten_timeout;

int __real_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *ret);

int __wrap_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *ret) {
        int r;

        r = __real_sd_varlink_get_peer_uid(link, ret);
        if (r >= 0 && trust_fixture && *ret == geteuid())
                *ret = 0;
        return r;
}

int __real_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *ret);

int __wrap_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *ret) {
        const struct itimerspec shortened = { .it_value.tv_sec = 1 };

        if (shorten_timeout)
                return __real_timerfd_settime(fd, 0, &shortened, ret);
        return __real_timerfd_settime(fd, flags, value, ret);
}

static void on_message(const char *message, void *userdata) {
        GCancellable *cancel = userdata;

        fprintf(stderr, "message:%s\n", message);
        if (cancel)
                g_cancellable_cancel(cancel);
}

int main(int argc, char *argv[]) {
        g_autoptr(GCancellable) cancel = NULL;
        char *document = NULL;
        const char *mode;
        int r;

        if (argc != 3)
                return EXIT_FAILURE;
        mode = argv[2];
        trust_fixture = strcmp(mode, "untrusted") != 0;
        shorten_timeout = strcmp(mode, "timeout") == 0;
        cancel = g_cancellable_new();
        if (strcmp(mode, "pre-cancel") == 0)
                g_cancellable_cancel(cancel);
        r = read_document(argv[1], cancel, on_message, strcmp(mode, "cancel") == 0 ? cancel : NULL, &document);
        assert((r < 0) == (document == NULL));
        if (r < 0)
                fprintf(stderr, "error:%d\n", -r);
        if (document) {
                fputs(document, stdout);
                read_document_free(document);
        }
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
