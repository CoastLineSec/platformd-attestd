/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <gio/gio.h>

int read_document(const char *socket_path, GCancellable *cancellable,
                  void (*notify)(const char *message, void *userdata), void *userdata, char **ret);
void read_document_free(char *text);
