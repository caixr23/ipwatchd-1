#include "ipwatchd.h"

void ipwd_send_signal(const char* ip, const char *smac, const char *dmac) {
  DBusMessage *msg;
  DBusMessageIter args;
  DBusConnection *conn;
  DBusError err;
  dbus_uint32_t serial = 0;

  // initialise the error value
  dbus_error_init(&err);

  // connect to the DBUS system bus, and check for errors
  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
  if (dbus_error_is_set(&err)) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Connection Error (%s)", err.message);
    dbus_error_free(&err);
  }
  if (NULL == conn) {
    return;
  }

  // create a signal & check for errors
  msg = dbus_message_new_signal(
      "/com/deepin/system/IPWatchD", // object name of the signal
      "com.deepin.system.IPWatchD",  // interface name of the signal
      "IPConflict");                // name of the signal
  if (NULL == msg) {
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Message Null");
    return;
  }

  const char *err_msg = "Out of Memory";

  // append arguments onto signal
  dbus_message_iter_init_append(msg, &args);
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &ip)) {
    goto end;
  }
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &smac)) {
    goto end;
  }
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &dmac)) {
    goto end;
  }

  // send the message and flush the connection
  if (!dbus_connection_send(conn, msg, &serial)) {
    goto end;
  }
  dbus_connection_flush(conn);
  err_msg = NULL;

  end:
  if (err_msg != NULL)
    ipwd_message(IPWD_MSG_TYPE_ERROR, "Out Of Memory!\n");

  // free the message
  if (msg != NULL)
    dbus_message_unref(msg);
}
