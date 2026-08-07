/* SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd. */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "ipwatchd.h"

#include <grp.h>

#define IPWD_SECURITY_LOADER_GROUP "deepin-daemon"

typedef struct IPWD_S_ALLOWED_CALLER {
  char *name;
  struct IPWD_S_ALLOWED_CALLER *next;
} IPWD_S_ALLOWED_CALLER;

static IPWD_S_ALLOWED_CALLER *allowed_callers;
static gid_t loader_group = (gid_t)-1;

static void remove_caller(const char *name) {
  IPWD_S_ALLOWED_CALLER **current = &allowed_callers;
  while (*current != NULL) {
    if (strcmp((*current)->name, name) == 0) {
      IPWD_S_ALLOWED_CALLER *removed = *current;
      *current = removed->next;
      free(removed->name);
      free(removed);
      return;
    }
    current = &(*current)->next;
  }
}

static int caller_allowed(const char *name) {
  IPWD_S_ALLOWED_CALLER *current;
  for (current = allowed_callers; current != NULL; current = current->next) {
    if (strcmp(current->name, name) == 0) return 1;
  }
  return 0;
}

static int process_in_group(unsigned long pid, gid_t group) {
  char path[64], line[1024];
  FILE *status;
  snprintf(path, sizeof(path), "/proc/%lu/status", pid);
  status = fopen(path, "r");
  if (status == NULL) return 0;
  while (fgets(line, sizeof(line), status) != NULL) {
    char *value;
    if (strncmp(line, "Groups:", 7) == 0) {
      value = line + 7;
    } else if (strncmp(line, "Gid:", 4) == 0) {
      value = line + 4;
    } else {
      continue;
    }
    while (*value != '\0') {
      char *end;
      unsigned long gid;
      while (*value == ' ' || *value == '\t') value++;
      if (*value == '\n' || *value == '\0') break;
      errno = 0;
      gid = strtoul(value, &end, 10);
      if (errno != 0 || end == value) break;
      if ((gid_t)gid == group) {
        fclose(status);
        return 1;
      }
      value = end;
    }
  }
  fclose(status);
  return 0;
}

static int is_descendant(unsigned long pid, unsigned long ancestor) {
  unsigned int depth;
  for (depth = 0; pid > 1 && depth < 128; depth++) {
    char path[64], line[256];
    FILE *status;
    unsigned long parent = 0;
    snprintf(path, sizeof(path), "/proc/%lu/status", pid);
    status = fopen(path, "r");
    if (status == NULL) return 0;
    while (fgets(line, sizeof(line), status) != NULL) {
      if (sscanf(line, "PPid:\t%lu", &parent) == 1) break;
    }
    fclose(status);
    if (parent == ancestor) return 1;
    if (parent == 0 || parent == pid) return 0;
    pid = parent;
  }
  return 0;
}

static int get_uid_and_pid(DBusConnection *conn, const char *name, unsigned long *uid, unsigned long *pid) {
  DBusError error;
  DBusMessage *request = NULL;
  DBusMessage *reply = NULL;
  dbus_uint32_t dbus_pid;
  dbus_error_init(&error);
  *uid = dbus_bus_get_unix_user(conn, name, &error);
  if (dbus_error_is_set(&error)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get UID for %s: %s", name, error.message);
    dbus_error_free(&error);
    return 0;
  }
  request = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "GetConnectionUnixProcessID");
  if (request == NULL || !dbus_message_append_args(request, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)) {
    if (request != NULL) dbus_message_unref(request);
    return 0;
  }
  reply = dbus_connection_send_with_reply_and_block(conn, request, -1, &error);
  dbus_message_unref(request);
  if (reply == NULL || !dbus_message_get_args(reply, &error, DBUS_TYPE_UINT32, &dbus_pid, DBUS_TYPE_INVALID)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to get PID for %s: %s", name,
        dbus_error_is_set(&error) ? error.message : "unknown error");
    if (reply != NULL) dbus_message_unref(reply);
    if (dbus_error_is_set(&error)) dbus_error_free(&error);
    return 0;
  }
  dbus_message_unref(reply);
  *pid = dbus_pid;
  if (dbus_error_is_set(&error)) {
    dbus_error_free(&error);
    return 0;
  }
  return 1;
}

int ipwd_securityloader_init(DBusConnection *conn) {
  DBusError error;
  struct group *group = getgrnam(IPWD_SECURITY_LOADER_GROUP);
  if (group != NULL) loader_group = group->gr_gid;
  dbus_error_init(&error);
  dbus_bus_add_match(conn, "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'", &error);
  if (dbus_error_is_set(&error)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Unable to subscribe to NameOwnerChanged: %s", error.message);
    dbus_error_free(&error);
    return 0;
  }
  return 1;
}

void ipwd_securityloader_cleanup(void) {
  while (allowed_callers != NULL) remove_caller(allowed_callers->name);
}

int ipwd_securityloader_authorize(DBusMessage *msg, DBusConnection *conn) {
  const char *sender = dbus_message_get_sender(msg);
  unsigned long uid, pid;
  if (sender == NULL || !get_uid_and_pid(conn, sender, &uid, &pid)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Unable to identify DBus caller");
    return 0;
  }
  if (uid == 0 || caller_allowed(sender)) return 1;
  return ipwd_dbus_check_authorization(msg, conn);
}

int ipwd_securityloader_set_allow_caller(DBusMessage *msg, DBusConnection *conn) {
  DBusMessageIter args;
  const char *sender = dbus_message_get_sender(msg);
  const char *target;
  unsigned long sender_uid, sender_pid, target_uid, target_pid;
  IPWD_S_ALLOWED_CALLER *entry;
  if (sender == NULL || !dbus_message_iter_init(msg, &args) ||
      dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_INVALID_ARGS, "SetAllowCaller requires one DBus unique name");
    return 0;
  }
  dbus_message_iter_get_basic(&args, &target);
  if (target == NULL || target[0] != ':' || dbus_message_iter_next(&args)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_INVALID_ARGS, "SetAllowCaller requires exactly one DBus unique name");
    return 0;
  }
  if (!get_uid_and_pid(conn, sender, &sender_uid, &sender_pid) ||
      !get_uid_and_pid(conn, target, &target_uid, &target_pid)) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "Unable to identify DBus caller");
    return 0;
  }
  if (sender_uid != 0 && (loader_group == (gid_t)-1 || !process_in_group(sender_pid, loader_group) ||
      sender_uid != target_uid || !is_descendant(target_pid, sender_pid))) {
    ipwd_reply_error(msg, conn, DBUS_ERROR_ACCESS_DENIED, "SetAllowCaller registrar is not allowed to authorize this caller");
    return 0;
  }
  if (!caller_allowed(target)) {
    entry = calloc(1, sizeof(*entry));
    if (entry == NULL || (entry->name = strdup(target)) == NULL) {
      free(entry);
      ipwd_reply_error(msg, conn, DBUS_ERROR_NO_MEMORY, "Unable to register DBus caller");
      return 0;
    }
    entry->next = allowed_callers;
    allowed_callers = entry;
    ipwd_message(IPWD_MSG_TYPE_INFO, "Registered security-loader caller %s", target);
  }
  ipwd_reply_to_empty_method(msg, conn);
  return 1;
}

void ipwd_securityloader_handle_name_owner_changed(DBusMessage *msg) {
  DBusMessageIter args;
  const char *name, *old_owner, *new_owner;
  if (!dbus_message_iter_init(msg, &args) || dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) return;
  dbus_message_iter_get_basic(&args, &name);
  if (!dbus_message_iter_next(&args) || dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) return;
  dbus_message_iter_get_basic(&args, &old_owner);
  if (!dbus_message_iter_next(&args) || dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) return;
  dbus_message_iter_get_basic(&args, &new_owner);
  if (name != NULL && name[0] == ':' && old_owner != NULL && old_owner[0] != '\0' && new_owner != NULL && new_owner[0] == '\0') remove_caller(name);
}
