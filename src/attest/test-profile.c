/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#include "profile.c"

#define PROFILE_CONTENT                                                         \
        "[Verifier]\n"                                                          \
        "UID=1000\n"                                                            \
        "URL=https://verifier.example/v1/read\n"                                 \
        "Audience=https://verifier.example\n"                                    \
        "AttestationKey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n" \
        "Label=Example verifier\n"                                              \
        "CAFile=/etc/platformd/ca.pem\n"                                         \
        "CertificateFile=/etc/platformd/client.pem\n"                            \
        "PrivateKeyFile=/etc/platformd/client.key\n"                             \
        "PinnedPublicKey=sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"

static void check(const char *config, size_t size, bool valid) {
        Profile profile = {};
        FILE *stream;
        int r;

        stream = fmemopen((void*) config, size, "r");
        assert(stream);
        r = parse_profile(stream, &profile);
        assert(fclose(stream) == 0);
        assert((r == 0) == valid);
        if (valid) {
                assert(profile.uid == 1000);
                assert(profile.allow_retained_history);
                assert(strcmp(profile.label, "Example verifier") == 0);
        }
        profile_done(&profile);
}

#define CHECK(s, valid) check((s), sizeof(s) - 1, (valid))

int main(void) {
        CHECK(PROFILE_CONTENT "AllowRetainedHistory=yes\n", true);
        CHECK(PROFILE_CONTENT, false);
        CHECK(PROFILE_CONTENT "AllowRetainedHistory=no\n", false);
        CHECK(PROFILE_CONTENT "AllowRetainedHistory=yes\nUID=1001\n", false);
        CHECK(PROFILE_CONTENT "AllowRetainedHistory=yes\n[Other]\n", false);
        CHECK(PROFILE_CONTENT "AllowRetainedHistory=yes\nUnexpected=yes\n", false);
        CHECK(PROFILE_CONTENT "AllowRetainedHistory=yes\0ignored\n", false);
        CHECK("[Verifier]\nUID=0\n", false);
        CHECK("UID=1000\n" PROFILE_CONTENT "AllowRetainedHistory=yes\n", false);
        assert(trusted_open("relative", false) == -EINVAL);
        assert(trusted_open("/tmp/../etc/passwd", false) < 0);
        assert(trusted_open("/etc//passwd", false) == -EINVAL);
        return 0;
}
