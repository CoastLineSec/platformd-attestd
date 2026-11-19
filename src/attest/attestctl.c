/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attestd.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-varlink.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

typedef struct Reply {
        void *resource;
        size_t size;
        unsigned messages;
        bool done;
        int error;
} Reply;

static bool message_valid(const char *s) {
        if (!s || !*s || strlen(s) > 1024)
                return false;
        for (; *s; s++)
                if ((unsigned char) *s < 0x20 || (unsigned char) *s == 0x7f)
                        return false;
        return true;
}

static int on_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id,
                    sd_varlink_reply_flags_t flags, void *userdata) {
        Reply *reply = userdata;
        sd_json_variant *value;

        if (reply->done)
                return 0;
        reply->error = -EBADMSG;
        if (error_id) {
                reply->error = -EACCES;
                goto finish;
        }
        if (!sd_json_variant_is_object(parameters))
                goto finish;
        if (flags & SD_VARLINK_REPLY_CONTINUES) {
                const char *message;
                value = sd_json_variant_by_key(parameters, "message");
                if (sd_json_variant_elements(parameters) != 2 || ++reply->messages > 32 ||
                    !sd_json_variant_is_string(value) || !message_valid(message = sd_json_variant_string(value)))
                        goto finish;
                fprintf(stderr, "%s\n", message);
                return 0;
        }
        value = sd_json_variant_by_key(parameters, "status");
        if (sd_json_variant_elements(parameters) != 4 || !sd_json_variant_is_string(value) ||
            strcmp(sd_json_variant_string(value), "granted") != 0)
                goto finish;
        value = sd_json_variant_by_key(parameters, "dataBase64");
        if (!sd_json_variant_is_string(value) ||
            strlen(sd_json_variant_string(value)) > ((ATTEST_RESOURCE_MAX + 2) / 3) * 4 ||
            sd_json_variant_unbase64(value, &reply->resource, &reply->size) < 0 ||
            reply->size == 0 || reply->size > ATTEST_RESOURCE_MAX)
                goto finish;
        reply->error = 0;
finish:
        reply->done = true;
        return 0;
}

static int read_resource(const char *socket_path, const char *profile) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        Reply reply = {};
        uid_t peer;
        int r;

        r = sd_varlink_connect_address(&link, socket_path);
        if (r < 0)
                return r;
        r = sd_varlink_get_peer_uid(link, &peer);
        if (r < 0)
                return r;
        if (peer != 0)
                return -EACCES;
        r = sd_varlink_set_relative_timeout(link, ATTEST_TIMEOUT_USEC + 10000000);
        if (r < 0)
                return r;
        r = sd_json_buildo(&parameters, SD_JSON_BUILD_PAIR_STRING("profile", profile));
        if (r < 0)
                return r;
        sd_varlink_set_userdata(link, &reply);
        r = sd_varlink_bind_reply(link, on_reply);
        if (r >= 0)
                r = sd_varlink_observe(link, "io.platformd.Attest.Read", parameters);
        while (r >= 0 && !reply.done) {
                r = sd_varlink_process(link);
                if (r == 0 && !reply.done)
                        r = sd_varlink_wait(link, UINT64_MAX);
        }
        if (r >= 0)
                r = reply.error;
        if (r >= 0 && (fwrite(reply.resource, 1, reply.size, stdout) != reply.size || fflush(stdout) < 0))
                r = -EIO;
        if (reply.resource) {
                explicit_bzero(reply.resource, reply.size);
                free(reply.resource);
        }
        return r;
}

static void help(FILE *stream) {
        fputs("attestctl [OPTIONS...] read\n\n"
              "Read the resource of an attestation profile.\n\n"
              "  --profile=NAME    Select the profile\n"
              "  --socket=PATH     Connect to the specified socket\n"
              "  -h --help         Show this help\n", stream);
}

int main(int argc, char *argv[]) {
        static const struct option options[] = {
                { "profile", required_argument, NULL, 'p' },
                { "socket",  required_argument, NULL, 's' },
                { "help",    no_argument,       NULL, 'h' },
                {}
        };
        const char *profile = ATTEST_PROFILE, *socket_path = ATTEST_SOCKET;
        int c, r;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'p':
                        profile = optarg;
                        break;
                case 's':
                        socket_path = optarg;
                        break;
                case 'h':
                        help(stdout);
                        return EXIT_SUCCESS;
                default:
                        return EXIT_FAILURE;
                }

        if (argc - optind != 1 || strcmp(argv[optind], "read") != 0 ||
            !*profile || strlen(profile) > 64 || socket_path[0] != '/') {
                help(stderr);
                return EXIT_FAILURE;
        }
        (void) signal(SIGPIPE, SIG_IGN);
        r = read_resource(socket_path, profile);
        if (r < 0) {
                fputs("Attestation denied or unavailable.\n", stderr);
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}
