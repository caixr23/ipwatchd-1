#include "ipwatchd.h"

// Introspection XML data
static const char *introspection_xml =
"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
"<node name=\"/com/deepin/system/IPWatchD\">\n"
"</node>\n";

void ipwd_send_signal(DBusConnection *conn, const char *ip, const char *smac, const char *dmac, int is_conflict) {
  DBusMessage *msg;
  dbus_uint32_t serial = 0;

  if (!conn) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "DBus connection is NULL");
    return;
  }

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

void ipwd_reply_to_introspect(DBusMessage *msg, DBusConnection *conn) {
  DBusMessage *reply;
  DBusMessageIter args;
  dbus_uint32_t serial = 0;
  const char *xml_data = introspection_xml;

  // create a reply from the message
  reply = dbus_message_new_method_return(msg);
  if (!reply) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to create introspect reply");
    return;
  }

  dbus_message_iter_init_append(reply, &args);
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &xml_data)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");
    dbus_message_unref(reply);
    return;
  }

  // send the reply && flush the connection
  if (!dbus_connection_send(conn, reply, &serial)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Failed to send introspect reply\n");
    dbus_message_unref(reply);
    return;
  }
  dbus_connection_flush(conn);

  ipwd_message(IPWD_MSG_TYPE_DEBUG, "Introspection data sent");

  // free the reply
  dbus_message_unref(reply);
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
