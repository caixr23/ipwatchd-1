#include "ipwatchd.h"

void ipwd_send_signal(DBusConnection *conn, const char *ip, const char *smac, const char *dmac, int is_conflict) {
  DBusMessage *msg;
  dbus_uint32_t serial = 0;

  // create a signal & check for errors
  msg = dbus_message_new_signal(
      "/com/deepin/system/IPWatchD",                                    // object name of the signal
      "com.deepin.system.IPWatchD",                                     // interface name of the signal
      is_conflict ? "IPConflict" : "IPConflictReslove");                // name of the signal
  if (NULL == msg) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Message Null");
    return;
  }

  // append arguments onto signal
  if (!dbus_message_append_args(msg,
      DBUS_TYPE_STRING, &ip,
      DBUS_TYPE_STRING, &smac,
      DBUS_TYPE_STRING, &dmac,
      DBUS_TYPE_INVALID)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    exit(1);
  }

  // send the message and flush the connection
  if (!dbus_connection_send(conn, msg, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    exit(1);
  }
  dbus_connection_flush(conn);

  // free the message
  if (msg != NULL)
    dbus_message_unref(msg);
}

void ipwd_reply_to_method(DBusMessage *msg, DBusConnection *conn, const char *mac) {
  DBusMessage* reply;
  DBusMessageIter args;
  dbus_uint32_t serial = 0;

  // create a reply from the message
  reply = dbus_message_new_method_return(msg);

  dbus_message_iter_init_append(reply, &args);
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &mac)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    exit(1);
  }

  // send the reply && flush the connection
  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory\n");
    exit(1);
  }
  dbus_connection_flush(conn);

  // free the reply
  dbus_message_unref(reply);
}
