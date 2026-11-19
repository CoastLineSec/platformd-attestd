/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <curl/curl.h>

#include "attestd.h"

#define CHALLENGE_MAX (16U * 1024U)
#define EVIDENCE_MAX (16U * 1024U * 1024U + 64U)
#define TRANSFER_TIMEOUT_USEC (UINT64_C(25) * 1000000)
#define CHECK_INTERVAL_USEC UINT64_C(250000)
#define _cleanup_(f) __attribute__((cleanup(f)))

typedef enum RemoteState {
        REMOTE_NEW,
        REMOTE_BEGIN,
        REMOTE_PENDING,
        REMOTE_FINISHED,
} RemoteState;

typedef struct Transfer {
        const char *input;
        size_t input_size;
        size_t input_offset;
        char *output;
        size_t output_limit;
        size_t output_size;
} Transfer;

struct Remote {
        CURL *curl;
        struct curl_slist *headers;
        AttestCheck check;
        void *userdata;
        uint64_t deadline;
        uint64_t checked_at;
        int check_error;
        RemoteState state;
        Transfer *transfer;
};

static int remote_check(Remote *remote, bool force) {
        uint64_t now = attest_now();
        int r;

        if (remote->check_error < 0)
                return remote->check_error;
        if (now >= remote->deadline)
                return remote->check_error = -ETIMEDOUT;
        if (!force && now - remote->checked_at < CHECK_INTERVAL_USEC)
                return 0;

        r = remote->check(remote->userdata);
        if (r < 0)
                return remote->check_error = r;
        remote->checked_at = attest_now();
        if (remote->checked_at >= remote->deadline)
                return remote->check_error = -ETIMEDOUT;

        return 0;
}

static curl_socket_t open_socket(void *userdata, curlsocktype purpose, struct curl_sockaddr *address) {
        Remote *remote = userdata;

        /* A completion request is valid only on the connection that issued the challenge. */
        if (remote->state != REMOTE_BEGIN || purpose != CURLSOCKTYPE_IPCXN ||
            (address->family != AF_INET && address->family != AF_INET6) ||
            remote_check(remote, false) < 0)
                return CURL_SOCKET_BAD;

        return socket(address->family, address->socktype | SOCK_CLOEXEC, address->protocol);
}

static int seek_input(void *userdata, curl_off_t offset, int origin) {
        return CURL_SEEKFUNC_FAIL;
}

static size_t read_input(char *buffer, size_t size, size_t n_items, void *userdata) {
        Remote *remote = userdata;
        Transfer *transfer = remote->transfer;
        size_t n, left;

        if (!transfer || (size > 0 && n_items > SIZE_MAX / size) || remote_check(remote, false) < 0)
                return CURL_READFUNC_ABORT;

        n = size * n_items;
        left = transfer->input_size - transfer->input_offset;
        if (n > left)
                n = left;
        memcpy(buffer, transfer->input + transfer->input_offset, n);
        transfer->input_offset += n;

        return n;
}

static size_t write_output(char *buffer, size_t size, size_t n_items, void *userdata) {
        Remote *remote = userdata;
        Transfer *transfer = remote->transfer;
        size_t n;

        if (!transfer || (size > 0 && n_items > SIZE_MAX / size) || remote_check(remote, false) < 0)
                return 0;

        n = size * n_items;
        if (n > transfer->output_limit - transfer->output_size)
                return 0;

        memcpy(transfer->output + transfer->output_size, buffer, n);
        transfer->output_size += n;
        return n;
}

static int progress(void *userdata, curl_off_t total, curl_off_t downloaded,
                    curl_off_t pending, curl_off_t uploaded) {
        return remote_check(userdata, false) < 0;
}

Remote *remote_free(Remote *remote) {
        if (!remote)
                return NULL;

        curl_easy_cleanup(remote->curl);
        curl_slist_free_all(remote->headers);
        free(remote);

        return NULL;
}

static int set_headers(Remote *remote) {
        static const char *const headers[] = { "Content-Type: application/json", "Expect:" };

        for (size_t i = 0; i < sizeof(headers) / sizeof(headers[0]); i++) {
                struct curl_slist *l = curl_slist_append(remote->headers, headers[i]);

                if (!l)
                        return -ENOMEM;
                remote->headers = l;
        }

        return 0;
}

int remote_open(const Profile *profile, AttestCheck check, void *userdata, uint64_t deadline, Remote **ret) {
        Remote *remote;
        int r;

        if (!profile || !check || !ret)
                return -EINVAL;
        if (!profile->allow_retained_history || getenv("SSLKEYLOGFILE"))
                return -EACCES;
        if (!profile->url || !profile->ca_file || !profile->certificate_file ||
            !profile->private_key_file || !profile->pinned_public_key)
                return -EINVAL;

        remote = calloc(1, sizeof(*remote));
        if (!remote)
                return -ENOMEM;

        remote->curl = curl_easy_init();
        if (!remote->curl) {
                r = -ENOMEM;
                goto fail;
        }

        remote->check = check;
        remote->userdata = userdata;
        remote->deadline = deadline;
        r = remote_check(remote, true);
        if (r < 0)
                goto fail;

        r = set_headers(remote);
        if (r < 0)
                goto fail;

        r = -EOPNOTSUPP;
#define SET_OPTION(option, value)                                            \
        do {                                                                 \
                if (curl_easy_setopt(remote->curl, option, value) != CURLE_OK) \
                        goto fail;                                            \
        } while (0)

        SET_OPTION(CURLOPT_URL, profile->url);
        SET_OPTION(CURLOPT_PROTOCOLS_STR, "https");
        SET_OPTION(CURLOPT_FOLLOWLOCATION, 0L);
        SET_OPTION(CURLOPT_DISALLOW_USERNAME_IN_URL, 1L);
        SET_OPTION(CURLOPT_PROXY, "");
        SET_OPTION(CURLOPT_NOSIGNAL, 1L);
        SET_OPTION(CURLOPT_HTTP_VERSION, (long) CURL_HTTP_VERSION_1_1);
        SET_OPTION(CURLOPT_HTTP09_ALLOWED, 0L);
        SET_OPTION(CURLOPT_HTTP_CONTENT_DECODING, 0L);
        SET_OPTION(CURLOPT_HTTPHEADER, remote->headers);

        SET_OPTION(CURLOPT_SSLVERSION, (long) CURL_SSLVERSION_TLSv1_3);
        SET_OPTION(CURLOPT_SSL_VERIFYPEER, 1L);
        SET_OPTION(CURLOPT_SSL_VERIFYHOST, 2L);
        SET_OPTION(CURLOPT_CAINFO, profile->ca_file);
        SET_OPTION(CURLOPT_CAPATH, (char *) NULL);
        SET_OPTION(CURLOPT_SSLCERT, profile->certificate_file);
        SET_OPTION(CURLOPT_SSLKEY, profile->private_key_file);
        SET_OPTION(CURLOPT_KEYPASSWD, "");
        SET_OPTION(CURLOPT_PINNEDPUBLICKEY, profile->pinned_public_key);

        SET_OPTION(CURLOPT_MAXCONNECTS, 1L);
        SET_OPTION(CURLOPT_OPENSOCKETFUNCTION, open_socket);
        SET_OPTION(CURLOPT_OPENSOCKETDATA, remote);
        SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, 5000L);
        SET_OPTION(CURLOPT_NOPROGRESS, 0L);
        SET_OPTION(CURLOPT_XFERINFOFUNCTION, progress);
        SET_OPTION(CURLOPT_XFERINFODATA, remote);
        SET_OPTION(CURLOPT_POST, 1L);
        SET_OPTION(CURLOPT_SEEKFUNCTION, seek_input);
        SET_OPTION(CURLOPT_READFUNCTION, read_input);
        SET_OPTION(CURLOPT_READDATA, remote);
        SET_OPTION(CURLOPT_WRITEFUNCTION, write_output);
        SET_OPTION(CURLOPT_WRITEDATA, remote);

#undef SET_OPTION

        *ret = remote;
        return 0;

fail:
        remote_free(remote);
        return r;
}

static int perform(
                Remote *remote,
                const char *input,
                size_t input_size,
                const char *expected_type,
                size_t output_limit,
                void **ret_output,
                size_t *ret_size) {

        Transfer transfer = {
                .input = input,
                .input_size = input_size,
                .output_limit = output_limit,
        };
        uint64_t time_left;
        long status, version, connects;
        char *type;
        CURLcode code;
        int r;

        r = remote_check(remote, true);
        if (r < 0)
                return r;

        time_left = remote->deadline - remote->checked_at;
        if (time_left > TRANSFER_TIMEOUT_USEC)
                time_left = TRANSFER_TIMEOUT_USEC;

        transfer.output = malloc(output_limit + 1);
        if (!transfer.output)
                return -ENOMEM;

        if (curl_easy_setopt(remote->curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) input_size) != CURLE_OK ||
            curl_easy_setopt(remote->curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t) output_limit) != CURLE_OK ||
            curl_easy_setopt(remote->curl, CURLOPT_TIMEOUT_MS, (long) ((time_left + 999) / 1000)) != CURLE_OK) {
                r = -EOPNOTSUPP;
                goto finish;
        }

        remote->transfer = &transfer;
        code = curl_easy_perform(remote->curl);
        remote->transfer = NULL;

        r = remote_check(remote, true);
        if (r < 0)
                goto finish;
        if (code != CURLE_OK) {
                r = code == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT : -EIO;
                goto finish;
        }

        if (curl_easy_getinfo(remote->curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
            curl_easy_getinfo(remote->curl, CURLINFO_HTTP_VERSION, &version) != CURLE_OK ||
            curl_easy_getinfo(remote->curl, CURLINFO_CONTENT_TYPE, &type) != CURLE_OK ||
            curl_easy_getinfo(remote->curl, CURLINFO_NUM_CONNECTS, &connects) != CURLE_OK ||
            version != CURL_HTTP_VERSION_1_1 || connects != (remote->state == REMOTE_BEGIN ? 1 : 0)) {
                r = -EBADMSG;
                goto finish;
        }
        if (status != 200) {
                r = -EACCES;
                goto finish;
        }
        if (!type || strcmp(type, expected_type) != 0 || transfer.input_offset != input_size ||
            transfer.output_size == 0) {
                r = -EBADMSG;
                goto finish;
        }

        transfer.output[transfer.output_size] = 0;
        *ret_output = transfer.output;
        *ret_size = transfer.output_size;
        return 0;

finish:
        explicit_bzero(transfer.output, transfer.output_size);
        free(transfer.output);
        return r;
}

int remote_begin(Remote *remote, sd_json_variant **ret) {
        static const char begin[] = "{\"action\":\"begin\"}";
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        sd_json_variant *issued;
        curl_socket_t fd;
        void *output = NULL;
        size_t size;
        int r;

        if (!remote || remote->state != REMOTE_NEW || !ret)
                return -EINVAL;

        remote->state = REMOTE_BEGIN;
        r = perform(remote, begin, sizeof(begin) - 1, "application/json", CHALLENGE_MAX, &output, &size);
        remote->state = REMOTE_FINISHED;
        if (r < 0)
                return r;

        r = memchr(output, 0, size) ? -EBADMSG :
                sd_json_parse(output, 0, &reply, NULL, NULL);
        free(output);
        if (r < 0)
                return r;

        issued = sd_json_variant_by_key(reply, "request");
        if (!sd_json_variant_is_object(reply) || sd_json_variant_elements(reply) != 2 ||
            !sd_json_variant_is_object(issued) ||
            curl_easy_getinfo(remote->curl, CURLINFO_ACTIVESOCKET, &fd) != CURLE_OK || fd == CURL_SOCKET_BAD)
                return -EBADMSG;

        remote->state = REMOTE_PENDING;
        *ret = sd_json_variant_ref(issued);
        return 0;
}

int remote_complete(Remote *remote, sd_json_variant *token, void **ret_data, size_t *ret_size) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *request = NULL;
        char *input = NULL;
        size_t size;
        int r;

        if (!remote || remote->state != REMOTE_PENDING || !sd_json_variant_is_object(token) || !ret_data || !ret_size)
                return -EINVAL;

        remote->state = REMOTE_FINISHED;
        r = sd_json_buildo(&request,
                           SD_JSON_BUILD_PAIR_STRING("action", "complete"),
                           SD_JSON_BUILD_PAIR_VARIANT("token", token));
        if (r < 0)
                return r;

        r = sd_json_variant_format(request, 0, &input);
        if (r < 0)
                return r;

        size = strlen(input);
        r = size > EVIDENCE_MAX ? -E2BIG :
                perform(remote, input, size, "application/octet-stream", ATTEST_RESOURCE_MAX, ret_data, ret_size);
        explicit_bzero(input, size);
        free(input);
        return r;
}
