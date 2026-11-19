/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include <systemd/sd-varlink.h>

int __real_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *ret);

int __wrap_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *ret) {
        int r;

        r = __real_sd_varlink_get_peer_uid(link, ret);
        if (r >= 0 && *ret == geteuid())
                *ret = 0;
        return r;
}
