/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <sys/prctl.h>

#include <gtk/gtk.h>

#include "../attest/attestd.h"
#include "read.h"

typedef struct Read {
        const char *socket;
        GMutex lock;
        char *message;
        char *document;
} Read;

typedef struct Viewer {
        GtkApplication *application;
        GtkWindow *window;
        GtkWidget *open, *cancel;
        GtkLabel *status;
        GtkTextBuffer *document;
        const char *socket;
        GTask *task;
        guint progress_source;
} Viewer;

static void read_free(gpointer userdata) {
        Read *read = userdata;

        g_free(read->message);
        read_document_free(read->document);
        g_mutex_clear(&read->lock);
        g_free(read);
}

static void read_notify(const char *message, void *userdata) {
        Read *read = userdata;

        g_mutex_lock(&read->lock);
        g_free(read->message);
        read->message = g_strdup(message);
        g_mutex_unlock(&read->lock);
}

static void read_worker(GTask *task, gpointer source, gpointer userdata, GCancellable *cancellable) {
        Read *read = userdata;
        int r;

        r = read_document(read->socket, cancellable, read_notify, read, &read->document);
        g_task_return_int(task, r);
}

static gboolean on_progress(gpointer userdata) {
        Viewer *viewer = userdata;
        g_autofree char *message = NULL;
        Read *read = g_task_get_task_data(viewer->task);

        if (!viewer->window || g_cancellable_is_cancelled(g_task_get_cancellable(viewer->task)))
                return G_SOURCE_CONTINUE;

        g_mutex_lock(&read->lock);
        message = g_steal_pointer(&read->message);
        g_mutex_unlock(&read->lock);
        if (message)
                gtk_label_set_text(viewer->status, message);
        return G_SOURCE_CONTINUE;
}

static void on_read_finished(GObject *source, GAsyncResult *result, gpointer userdata) {
        Viewer *viewer = userdata;
        GTask *task = G_TASK(result);
        Read *read = g_task_get_task_data(task);
        gssize r;

        if (task != viewer->task)
                return;

        r = g_task_propagate_int(task, NULL);
        if (g_cancellable_is_cancelled(g_task_get_cancellable(task)))
                r = -ECANCELED;
        g_clear_handle_id(&viewer->progress_source, g_source_remove);

        if (viewer->window) {
                const char *status;

                if (r >= 0 && read->document) {
                        gtk_text_buffer_set_text(viewer->document, read->document, -1);
                        status = "Document opened.";
                } else if (r == -ECANCELED)
                        status = "Cancelled.";
                else if (r == -EACCES)
                        status = "Access denied.";
                else
                        status = "Attestation unavailable.";

                gtk_label_set_text(viewer->status, status);
                gtk_widget_set_sensitive(viewer->cancel, FALSE);
                gtk_widget_set_sensitive(viewer->open, TRUE);
        }

        read_document_free(g_steal_pointer(&read->document));
        g_clear_object(&viewer->task);
        g_application_release(G_APPLICATION(source));
}

static void on_open(GtkButton *button, gpointer userdata) {
        Viewer *viewer = userdata;
        g_autoptr(GCancellable) cancellable = NULL;
        Read *read;

        if (viewer->task)
                return;

        gtk_text_buffer_set_text(viewer->document, "", 0);
        gtk_label_set_text(viewer->status, "Requesting protected document…");
        gtk_widget_set_sensitive(viewer->open, FALSE);
        gtk_widget_set_sensitive(viewer->cancel, TRUE);

        cancellable = g_cancellable_new();
        read = g_new0(Read, 1);
        read->socket = viewer->socket;
        g_mutex_init(&read->lock);

        g_application_hold(G_APPLICATION(viewer->application));
        viewer->task = g_task_new(viewer->application, cancellable, on_read_finished, viewer);
        g_task_set_check_cancellable(viewer->task, FALSE);
        g_task_set_task_data(viewer->task, read, read_free);
        viewer->progress_source = g_timeout_add(50, on_progress, viewer);
        g_task_run_in_thread(viewer->task, read_worker);
}

static void on_cancel(GtkButton *button, gpointer userdata) {
        Viewer *viewer = userdata;

        if (!viewer->task)
                return;

        g_cancellable_cancel(g_task_get_cancellable(viewer->task));
        gtk_widget_set_sensitive(viewer->cancel, FALSE);
        gtk_label_set_text(viewer->status, "Cancelling…");
}

static gboolean on_close(GtkWindow *window, gpointer userdata) {
        Viewer *viewer = userdata;

        if (viewer->task)
                g_cancellable_cancel(g_task_get_cancellable(viewer->task));
        gtk_text_buffer_set_text(viewer->document, "", 0);
        viewer->window = NULL;
        viewer->document = NULL;
        viewer->open = viewer->cancel = NULL;
        viewer->status = NULL;
        return FALSE;
}

static void on_activate(GtkApplication *application, gpointer userdata) {
        Viewer *viewer = userdata;
        GtkWidget *layout, *actions, *scroller, *text;

        if (viewer->window) {
                gtk_window_present(viewer->window);
                return;
        }

        viewer->window = GTK_WINDOW(gtk_application_window_new(application));
        gtk_window_set_title(viewer->window, "Protected Document Viewer");
        gtk_window_set_default_size(viewer->window, 600, 420);
        g_signal_connect(viewer->window, "close-request", G_CALLBACK(on_close), viewer);

        layout = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
        gtk_widget_set_margin_start(layout, 12);
        gtk_widget_set_margin_end(layout, 12);
        gtk_widget_set_margin_top(layout, 12);
        gtk_widget_set_margin_bottom(layout, 12);
        gtk_window_set_child(viewer->window, layout);

        actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        viewer->open = gtk_button_new_with_label("Open Protected Document");
        viewer->cancel = gtk_button_new_with_label("Cancel");
        gtk_widget_set_sensitive(viewer->open, !viewer->task);
        gtk_widget_set_sensitive(viewer->cancel, FALSE);
        g_signal_connect(viewer->open, "clicked", G_CALLBACK(on_open), viewer);
        g_signal_connect(viewer->cancel, "clicked", G_CALLBACK(on_cancel), viewer);
        gtk_box_append(GTK_BOX(actions), viewer->open);
        gtk_box_append(GTK_BOX(actions), viewer->cancel);
        gtk_box_append(GTK_BOX(layout), actions);

        viewer->status = GTK_LABEL(gtk_label_new(viewer->task ? "Cancelling…" : "Ready."));
        gtk_label_set_xalign(viewer->status, 0);
        gtk_label_set_wrap(viewer->status, TRUE);
        gtk_box_append(GTK_BOX(layout), GTK_WIDGET(viewer->status));

        scroller = gtk_scrolled_window_new();
        gtk_widget_set_vexpand(scroller, TRUE);
        gtk_box_append(GTK_BOX(layout), scroller);

        text = gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), FALSE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_WORD_CHAR);
        gtk_widget_set_focusable(text, FALSE);
        gtk_widget_set_can_target(text, FALSE);
        viewer->document = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
        gtk_text_buffer_set_enable_undo(viewer->document, FALSE);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), text);
        gtk_window_present(viewer->window);
}

int main(int argc, char *argv[]) {
        g_autoptr(GOptionContext) context = NULL;
        g_autoptr(GtkApplication) application = NULL;
        g_autoptr(GError) error = NULL;
        g_autofree char *socket = NULL;
        const GOptionEntry options[] = {
                { "socket", 0, 0, G_OPTION_ARG_FILENAME, &socket, "Connect to the specified socket", "PATH" },
                {},
        };
        Viewer viewer;

        context = g_option_context_new(NULL);
        g_option_context_set_summary(context, "View a protected text document.");
        g_option_context_add_main_entries(context, options, NULL);
        if (!g_option_context_parse(context, &argc, &argv, &error)) {
                g_printerr("%s\n", error->message);
                return EXIT_FAILURE;
        }
        if (argc != 1 || (socket && (socket[0] != '/' || !socket[1]))) {
                g_printerr("Expected an absolute socket path and no positional arguments.\n");
                return EXIT_FAILURE;
        }
        if (prctl(PR_SET_DUMPABLE, 0L) < 0) {
                g_printerr("Failed to disable core dumps: %s\n", g_strerror(errno));
                return EXIT_FAILURE;
        }

        application = gtk_application_new("io.platformd.AttestViewer", G_APPLICATION_NON_UNIQUE);
        viewer = (Viewer) {
                .application = application,
                .socket = socket ?: ATTEST_SOCKET,
        };
        g_signal_connect(application, "activate", G_CALLBACK(on_activate), &viewer);
        return g_application_run(G_APPLICATION(application), argc, argv);
}
