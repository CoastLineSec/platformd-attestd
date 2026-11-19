/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include <systemd/sd-json.h>

#define ATTEST_SOCKET "/run/platformd-attestd/io.platformd.Attest"
#define ATTEST_CONFIG "/etc/platformd/attestd.conf"
#define ATTEST_PROFILE "protected-read"
#define ATTEST_TIMEOUT_USEC (UINT64_C(100) * 1000000)
#define ATTEST_RESOURCE_MAX (1024U * 1024U)

typedef struct Profile {
        uid_t uid;
        char *url;
        char *audience;
        char *key_id;
        char *label;
        char *ca_file;
        char *certificate_file;
        char *private_key_file;
        char *pinned_public_key;
        bool allow_retained_history;
} Profile;

typedef struct Remote Remote;
typedef int (*AttestCheck)(void *userdata);
typedef int (*AttestNotify)(const char *message, void *userdata);

static inline uint64_t attest_now(void) {
        struct timespec ts;

        if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0)
                return UINT64_MAX;
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

int profile_load(const char *path, Profile *ret);
void profile_done(Profile *profile);

int local_session_get(int pidfd, uid_t uid, char **ret);
int local_session_check(const char *session, uid_t uid);
int local_connect_verify(int fd);
int local_verify(uid_t uid, const char *session, const char *label, sd_json_variant *context,
                 AttestNotify notify, AttestCheck check, void *userdata, uint64_t deadline);
int local_evidence(sd_json_variant *request, AttestCheck check, void *userdata, uint64_t deadline,
                   sd_json_variant **ret);

int remote_open(const Profile *profile, AttestCheck check, void *userdata, uint64_t deadline, Remote **ret);
int remote_begin(Remote *remote, sd_json_variant **ret);
int remote_complete(Remote *remote, sd_json_variant *token, void **ret_data, size_t *ret_size);
Remote *remote_free(Remote *remote);
