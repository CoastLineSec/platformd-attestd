/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attestd.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROFILE_SIZE_MAX (16U * 1024U)
#define PROFILE_FIELD_MAX 4096U

static const struct {
        const char *name;
        size_t offset;
} fields[] = {
        { "URL",              offsetof(Profile, url) },
        { "Audience",         offsetof(Profile, audience) },
        { "AttestationKey",   offsetof(Profile, key_id) },
        { "Label",            offsetof(Profile, label) },
        { "CAFile",           offsetof(Profile, ca_file) },
        { "CertificateFile",  offsetof(Profile, certificate_file) },
        { "PrivateKeyFile",   offsetof(Profile, private_key_file) },
        { "PinnedPublicKey",  offsetof(Profile, pinned_public_key) },
};

static int trusted_open(const char *path, bool private) {
        char *copy = NULL, *save = NULL, *name, *next;
        int fd, result = -EINVAL;
        struct stat st;

        if (!path || path[0] != '/' || path[1] == 0 || strstr(path, "//") || path[strlen(path) - 1] == '/')
                return -EINVAL;
        copy = strdup(path + 1);
        if (!copy)
                return -ENOMEM;
        fd = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
        if (fd < 0) {
                result = -errno;
                goto finish;
        }
        for (name = strtok_r(copy, "/", &save); name; name = next) {
                int child;

                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                        goto finish;
                next = strtok_r(NULL, "/", &save);
                child = openat(fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                                         (next ? O_DIRECTORY : 0));
                if (child < 0) {
                        result = -errno;
                        goto finish;
                }
                close(fd);
                fd = child;
                if (fstat(fd, &st) < 0) {
                        result = -errno;
                        goto finish;
                }
                if (st.st_uid != 0 || (st.st_mode & 0022) ||
                    (!next && (!S_ISREG(st.st_mode) || (private && (st.st_mode & 0077))))) {
                        result = -EPERM;
                        goto finish;
                }
        }
        result = fd;
        fd = -1;
finish:
        if (fd >= 0)
                close(fd);
        free(copy);
        return result;
}

static bool text_valid(const char *s, size_t limit, bool space) {
        if (!s || !*s || strlen(s) > limit)
                return false;
        for (; *s; s++)
                if ((unsigned char) *s < (space ? 0x20 : 0x21) || (unsigned char) *s > 0x7e)
                        return false;
        return true;
}

static bool hex_digest(const char *s) {
        return strlen(s) == 64 && strspn(s, "0123456789abcdef") == 64;
}

static bool pin_valid(const char *s) {
        static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        return strlen(s) == 52 && strncmp(s, "sha256//", 8) == 0 &&
                strspn(s + 8, alphabet) == 43 && s[51] == '=';
}

static char *strip(char *s) {
        s += strspn(s, " \t");
        char *end = s + strlen(s);
        while (end > s && strchr(" \t\r\n", end[-1]))
                *--end = 0;
        return s;
}

static int parse_profile(FILE *stream, Profile *ret) {
        char *line = NULL;
        size_t allocated = 0, total = 0;
        bool section = false, have_uid = false, have_disclosure = false;
        ssize_t length;
        int r = -EINVAL;

        while ((length = getline(&line, &allocated, stream)) >= 0) {
                char *key, *value;
                size_t i;

                if ((size_t) length > PROFILE_FIELD_MAX || total + (size_t) length > PROFILE_SIZE_MAX ||
                    memchr(line, 0, (size_t) length))
                        goto finish;
                total += (size_t) length;
                key = strip(line);
                if (!*key || *key == '#' || *key == ';')
                        continue;
                if (strcmp(key, "[Verifier]") == 0 && !section) {
                        section = true;
                        continue;
                }
                if (!section || !(value = strchr(key, '=')))
                        goto finish;
                *value++ = 0;
                key = strip(key);
                value = strip(value);
                if (strcmp(key, "UID") == 0) {
                        unsigned long long uid;

                        if (have_uid || !*value || strspn(value, "0123456789") != strlen(value))
                                goto finish;
                        errno = 0;
                        uid = strtoull(value, NULL, 10);
                        if (errno || uid == 0 || uid >= UINT32_MAX)
                                goto finish;
                        ret->uid = (uid_t) uid;
                        have_uid = true;
                        continue;
                }
                if (strcmp(key, "AllowRetainedHistory") == 0) {
                        if (have_disclosure || strcmp(value, "yes") != 0)
                                goto finish;
                        ret->allow_retained_history = have_disclosure = true;
                        continue;
                }
                if (!text_valid(value, PROFILE_FIELD_MAX, strcmp(key, "Label") == 0))
                        goto finish;
                for (i = 0; i < sizeof fields / sizeof *fields; i++) {
                        char **field;

                        if (strcmp(key, fields[i].name) != 0)
                                continue;
                        field = (char**) ((uint8_t*) ret + fields[i].offset);
                        if (*field)
                                goto finish;
                        *field = strdup(value);
                        if (!*field) {
                                r = -ENOMEM;
                                goto finish;
                        }
                        break;
                }
                if (i == sizeof fields / sizeof *fields)
                        goto finish;
        }
        if (ferror(stream)) {
                r = -EIO;
                goto finish;
        }
        if (!section || !have_uid || !have_disclosure)
                goto finish;
        for (size_t i = 0; i < sizeof fields / sizeof *fields; i++)
                if (!*(char**) ((uint8_t*) ret + fields[i].offset))
                        goto finish;
        if (strncmp(ret->url, "https://", 8) != 0 || !text_valid(ret->audience, 256, false) ||
            strncmp(ret->audience, "https://", 8) != 0 || !ret->audience[8] ||
            !text_valid(ret->label, 160, true) || !hex_digest(ret->key_id) ||
            !pin_valid(ret->pinned_public_key))
                goto finish;
        r = 0;
finish:
        free(line);
        return r;
}

int profile_load(const char *path, Profile *ret) {
        Profile profile = {};
        struct stat st;
        FILE *stream;
        int fd, r;

        fd = trusted_open(path, true);
        if (fd < 0)
                return fd;
        if (fstat(fd, &st) < 0) {
                r = -errno;
                close(fd);
                return r;
        }
        if (st.st_size <= 0 || st.st_size > PROFILE_SIZE_MAX) {
                close(fd);
                return -E2BIG;
        }
        stream = fdopen(fd, "re");
        if (!stream) {
                r = -errno;
                close(fd);
                return r;
        }
        r = parse_profile(stream, &profile);
        fclose(stream);
        if (r >= 0) {
                const char *paths[] = { profile.ca_file, profile.certificate_file, profile.private_key_file };
                for (size_t i = 0; i < sizeof paths / sizeof *paths; i++) {
                        fd = trusted_open(paths[i], i == 2);
                        if (fd < 0) {
                                r = fd;
                                break;
                        }
                        close(fd);
                }
        }
        if (r < 0)
                profile_done(&profile);
        else
                *ret = profile;
        return r;
}

void profile_done(Profile *profile) {
        for (size_t i = 0; i < sizeof fields / sizeof *fields; i++)
                free(*(char**) ((uint8_t*) profile + fields[i].offset));
        *profile = (Profile) {};
}
