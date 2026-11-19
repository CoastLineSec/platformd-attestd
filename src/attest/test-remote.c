/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "attestd.h"

static int check(void *userdata) {
        return *(bool *) userdata ? 0 : -ECANCELED;
}

int main(int argc, char **argv) {
        sd_json_variant *issued = NULL, *token = NULL;
        size_t size = 0;
        Remote *remote = NULL;
        void *data = NULL;
        uint64_t deadline;
        bool active;
        int r;

        assert(argc == 7);
        const Profile profile = {
                .url = argv[1],
                .ca_file = argv[2],
                .certificate_file = argv[3],
                .private_key_file = argv[4],
                .pinned_public_key = argv[5],
                .allow_retained_history = strcmp(argv[6], "disallowed") != 0,
        };

        active = true;
        deadline = attest_now() + UINT64_C(5000000);
        if (strcmp(argv[6], "expired") == 0)
                deadline = attest_now();

        r = remote_open(&profile, check, &active, deadline, &remote);
        if (strcmp(argv[6], "disallowed") == 0) {
                assert(r == -EACCES && !remote);
                return 0;
        }
        if (strcmp(argv[6], "expired") == 0) {
                assert(r == -ETIMEDOUT && !remote);
                return 0;
        }
        assert(r == 0);

        r = remote_begin(remote, &issued);
        if (strcmp(argv[6], "untrusted") == 0) {
                assert(r < 0 && !issued);
                goto finish;
        }
        if (strcmp(argv[6], "disconnected") == 0 && r < 0) {
                assert(!issued);
                goto finish;
        }
        assert(r == 0 && sd_json_variant_is_object(issued));
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(issued, "sequence")) == 1);
        assert(sd_json_buildo(&token, SD_JSON_BUILD_PAIR_STRING("profile", "fixture")) >= 0);

        active = strcmp(argv[6], "cancelled") != 0;
        r = remote_complete(remote, token, &data, &size);
        if (strcmp(argv[6], "cancelled") == 0)
                assert(r == -ECANCELED && !data && size == 0);
        else if (strcmp(argv[6], "denied") == 0)
                assert(r == -EACCES && !data && size == 0);
        else if (strcmp(argv[6], "disconnected") == 0)
                assert(r < 0 && !data && size == 0);
        else {
                static const char resource[] = "protected\0file\xff";

                assert(r == 0 && size == sizeof(resource) - 1 && memcmp(data, resource, size) == 0);
        }
        assert(remote_complete(remote, token, &data, &size) == -EINVAL);

finish:
        free(data);
        sd_json_variant_unref(token);
        sd_json_variant_unref(issued);
        remote_free(remote);
        return 0;
}
