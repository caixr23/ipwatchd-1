/* IPwatchD - IP conflict detection tool for Linux
 * Copyright (C) 2007-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

/** \file ipwatchd.c
 * \brief Main source file of the project
 */

#include "ipwatchd.h"


//! Flag indicating debug mode
int debug_flag = 0;

//! Flag indicating that output of program must be recorded by syslog
int syslog_flag = 0;

//! Flag indicating testing mode when every ARP packet is considered to be conflicting
int testing_flag = 0;

//! Structure that holds information about network interfaces
IPWD_S_DEVS devices;

//! Structure that holds values of particular configuration variables
IPWD_S_CONFIG config;

//! Handle for libpcap
pcap_t *h_pcap = NULL;

//! Flag indicating loop over
volatile int exit_flag =  0;

//! Structure that holds ip conflict check context
IPWD_S_CHECK_CONTEXT check_context;

IPCONFLICT_DEV_INFO *ipconflict_dev_info;

//! Main function of the ipwatchd program
/*!
 * \param argc Number of received command line arguments
 * \param argv Argument values
 * \return IPWD_RV_SUCCESS if successful IPWD_RV_ERROR otherwise
 */
int main (int argc, char *argv[])
{
	/* Name of configuration file  */
	char *config_file = NULL;

	int c = 0;
	int option_index = 0;

	/* Open connection to syslog with default daemon facility */
	openlog ("ipwatchd", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	/* Parse command line arguments */
	while (1)
	{
		static struct option long_options[] = {
			{ "config", required_argument, 0, 'c' },
			{ "debug", no_argument, 0, 'd' },
			{ "test", no_argument, 0, 't' },
			{ "help", no_argument, 0, 'h' },
			{ "version", no_argument, 0, 'v' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long (argc, argv, "c:dthv", long_options, &option_index);

		if (c == -1)
		{
			break;
		}

		switch (c)
		{
			case 'c':
				if (ipwd_file_exists (optarg) == IPWD_RV_ERROR)
				{
					ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open configuration file %s", optarg);
					return (IPWD_RV_ERROR);
				}

				if ((config_file = (char *) malloc ((strlen (optarg) + 1) * sizeof (char))) == NULL)
				{
					ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to open configuration file %s - malloc failed", optarg);
					return (IPWD_RV_ERROR);
				}

				strcpy (config_file, optarg);
				break;

			case 'd':
				debug_flag = 1;
				break;

			case 't':
				testing_flag = 1;
				break;

			case 'h':
				ipwd_print_help ();
				return (IPWD_RV_SUCCESS);

			case 'v':
				ipwd_message (IPWD_MSG_TYPE_INFO, IPWATCHD_VERSION);
				return (IPWD_RV_SUCCESS);

			case '?':
				ipwd_message (IPWD_MSG_TYPE_ERROR, "Try %s --help", argv[0]);
				return (IPWD_RV_ERROR);

			default:
				ipwd_print_help ();
				return (IPWD_RV_ERROR);
		}

	}

	/* Print help if there is any unknown argument */
	if (optind < argc)
	{
		ipwd_print_help ();
		return (IPWD_RV_ERROR);
	}

	/* Path to configuration file must be specified */
	if (config_file == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "You must specify path to configuration file.");
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Try %s --help", argv[0]);
		return (IPWD_RV_ERROR);
	}

	/* Only root can run IPwatchD */
	if (getuid () != 0)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "You must be root to run IPwatchD");
		return (IPWD_RV_ERROR);
	}

	/* Read config file */
	if (ipwd_read_config (config_file) == IPWD_RV_ERROR)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to read configuration file");
		return (IPWD_RV_ERROR);
	}

	free (config_file);
	config_file = NULL;

	/* Daemonize - Skip daemonization in debug mode for easier debugging */
	if (!debug_flag) {
		if (ipwd_daemonize () != IPWD_RV_SUCCESS)
		{
			ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to daemonize");
			return (IPWD_RV_ERROR);
		}
	} else {
		ipwd_message (IPWD_MSG_TYPE_INFO, "Running in debug mode - skipping daemonization");
	}

	ipwd_message (IPWD_MSG_TYPE_INFO, "IPwatchD started");

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	/* Check if "any" pseudodevice is available */
	/* IPwatchD cannot be used on Debian GNU/kFreeBSD because of the lack of this device */
	pcap_if_t * pcap_alldevs = NULL;
	pcap_if_t * pcap_dev = NULL;
	int any_exists = 0;

	if (pcap_findalldevs(&pcap_alldevs, errbuf))
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to get network device list - %s", errbuf);
		return (IPWD_RV_ERROR);
	}

	for (pcap_dev = pcap_alldevs; pcap_dev; pcap_dev = pcap_dev->next)
	{
		if (strcasecmp (pcap_dev->name, "any") == 0)
		{
			any_exists = 1;
			break;
		}
	}

	if (!any_exists)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Pseudodevice \"any\" used by libpcap is not available");
		return (IPWD_RV_ERROR);
	}

	/* Initialize libpcap and listen on all interfaces */
	h_pcap = pcap_open_live ("any", BUFSIZ, 0, 0, errbuf);
	if (h_pcap == NULL)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to create packet capture object - %s", errbuf);
		return (IPWD_RV_ERROR);
	}

    if (pcap_setnonblock(h_pcap, 1, errbuf) == -1)
    {
      ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to set non block - %s", errbuf);
      return (IPWD_RV_ERROR);
    }

	/* Set SIGTERM handler */
	if (ipwd_set_signal_handler () != IPWD_RV_SUCCESS)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to set signal handlers");
		return (IPWD_RV_ERROR);
	}

	/* Compile packet capture filter - only ARP packets will be captured */
	if (pcap_compile (h_pcap, &fp, "arp", 0, 0) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to compile packet capture filter - %s", pcap_geterr (h_pcap));
		return (IPWD_RV_ERROR);
	}

	/* Set packet capture filter */
	if (pcap_setfilter (h_pcap, &fp) == -1)
	{
		ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to set packet capture filter - %s", pcap_geterr (h_pcap));
		return (IPWD_RV_ERROR);
	}

	pcap_freecode (&fp);

	ipwd_message (IPWD_MSG_TYPE_DEBUG, "Entering pcap loop");

    /* Loop until SIGTERM calls pcap_breakloop */
    /* pcap_loop(h_pcap, -1, ipwd_analyse, NULL); */

   DBusMessage* msg;
   DBusMessageIter args;
   DBusConnection* conn;
   DBusError err;
   int ret;

   check_context.stage = 0;

   // initialise the errors
   dbus_error_init(&err);

   // connect to the bus and check for errors
   conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
   if (dbus_error_is_set(&err)) {
     ipwd_message(IPWD_MSG_TYPE_ERROR, "Connection Error (%s)", err.message);
     dbus_error_free(&err);
   }
   if (NULL == conn) {
     return (IPWD_RV_ERROR);
   }
   check_context.conn = conn;

   // request our name on the bus and check for errors
   ret = dbus_bus_request_name(conn, "com.deepin.system.IPWatchD", DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
   if (dbus_error_is_set(&err)) {
      ipwd_message(IPWD_MSG_TYPE_ERROR, "Name Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
      fprintf(stderr, "Not Primary Owner (%d)\n", ret);
      return (IPWD_RV_ERROR);
   }

   while (!exit_flag) {
     // non blocking read of the next available message
     dbus_connection_read_write(conn, 0);
     msg = dbus_connection_pop_message(conn);

     if (msg != NULL) {
        // 检查并处理Introspect消息
        if (dbus_message_is_method_call(msg, "org.freedesktop.DBus.Introspectable", "Introspect")) {
            ipwd_reply_to_introspect(msg, conn);
            dbus_message_unref(msg);
            continue;
        }
       // check this is a method call for the right interface & method
       if (dbus_message_is_method_call(msg, "com.deepin.system.IPWatchD", "RequestIPConflictCheck") &&
         dbus_message_has_path(msg, "/com/deepin/system/IPWatchD") &&
         check_context.stage == 0) {
         // read the parameters
         if (!dbus_message_iter_init(msg, &args)) {
           ipwd_message(IPWD_MSG_TYPE_ERROR, "Message Has No Parameters\n");
         } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
           ipwd_message(IPWD_MSG_TYPE_ERROR, "Argument is not string!");
         } else {
           check_context.stage++;
           dbus_message_iter_get_basic(&args, &check_context.ip);
         }
         if (!dbus_message_iter_has_next(&args) || !dbus_message_iter_next(&args)) {
           ipwd_message(IPWD_MSG_TYPE_ERROR, "Argument is not enough!");
         } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
           ipwd_message(IPWD_MSG_TYPE_ERROR, "Argument is not string!");
         } else {
           check_context.stage++;
           dbus_message_iter_get_basic(&args, &check_context.misc);
         }

         check_context.msg = msg;
         ipwd_check_context_verify();
       } else {
         dbus_message_unref(msg);
       }
     }

     static time_t last_update_time = 0;
     time_t current_time = time(NULL);
     if (current_time - last_update_time >= config.update_interval) {
        ipwd_update_devices();
        last_update_time = current_time;
     }
     ipwd_check_context_update();

     if (pcap_dispatch (h_pcap, -1, ipwd_analyse, NULL) == 0) {
       usleep(check_context.stage > 2 ? 10000 : 100000);
     }
   }

	pcap_close (h_pcap);

	/* Stop IPwatchD */
	ipwd_message (IPWD_MSG_TYPE_INFO, "IPwatchD stopped");

	closelog ();

	if (config.script != NULL)
	{
		free (config.script);
		config.script = NULL;
	}

	if (devices.dev != NULL)
	{
		free (devices.dev);
		devices.dev = NULL;
	}

	IPCONFLICT_DEV_INFO *ipconflictinfo = ipconflict_dev_info;
	while (ipconflictinfo)
	{
		IPCONFLICT_DEV_INFO *tmp = ipconflictinfo;
		ipconflictinfo = ipconflictinfo->next;
		free(tmp);
	}

	return (IPWD_RV_SUCCESS);
}


//! Prints help to the stdout
void ipwd_print_help (void)
{
	fprintf (stdout, "IPwatchD - IP conflict detection tool for Linux\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "IPwatchD is simple daemon that analyses all incoming ARP\n");
	fprintf (stdout, "packets in order to detect IP conflicts.\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "Usage: ipwatchd --config config_file [--debug] [--test]\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "  -c | --config config_file    - Path to configuration file\n");
	fprintf (stdout, "  -d | --debug                 - Run in debug mode\n");
	fprintf (stdout, "  -t | --test                  - Run in testing mode\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "or     ipwatchd --version|--help\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "  -v | --version               - Prints program version\n");
	fprintf (stdout, "  -v | --help                  - Displays this help message\n");
	fprintf (stdout, "\n");
	fprintf (stdout, "Please send any bug reports to jariq@jariq.sk\n");
}

void ipwd_check_context_verify (void)
{
  if (check_context.ip == NULL || check_context.misc == NULL) {
    ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to convert source IP address %s", check_context.ip);
    check_context.stage = -1;
    return;
  }

  struct in_addr sip, dip;
  if (inet_aton(check_context.ip, &sip) == 0) {
    ipwd_message (IPWD_MSG_TYPE_ERROR, "Unable to convert source IP address %s", check_context.ip);
    check_context.stage = -1;
    return;
  }
  if (sip.s_addr == 0) {
    ipwd_message (IPWD_MSG_TYPE_ERROR, "Error source IP address %s", check_context.ip);
    check_context.stage = -1;
    return;
  }

  int i;
  memset(&check_context.dev, 0, sizeof(IPWD_S_DEV));
  check_context.dev.state = IPWD_DEVICE_STATE_UNUSABLE;

  if (check_context.misc[0] == '\0') {
    IPWD_S_DEV dev;
    for (i = 0; i < devices.devnum; i++) {
      memset(dev.device, 0, sizeof(dev.device));
      strcpy(dev.device, devices.dev[i].device);
      if (ipwd_devinfo (dev.device, dev.ip, dev.mac) == IPWD_RV_ERROR) {
        continue;
      }
      if (inet_aton(dev.ip, &dip) != 0) {
        uint8_t *p = (uint8_t*)&sip.s_addr;
        uint8_t *q = (uint8_t*)&dip.s_addr;

        if (p[0] == q[0] && p[1] == q[1] && p[2] == q[2]) {
          memcpy(&check_context.dev, &dev, sizeof(IPWD_S_DEV));
          check_context.dev.state = IPWD_DEVICE_STATE_USABLE;
          break;
        }
      }

      memcpy(&check_context.dev, &dev, sizeof(IPWD_S_DEV));
      check_context.dev.state = IPWD_DEVICE_STATE_USABLE;
    }
  } else {
    strncpy(check_context.dev.device, check_context.misc, IPWD_MAX_DEVICE_NAME_LEN - 1);
    for (i = 0; i < devices.devnum; i++) {
      if (strcasecmp (check_context.dev.device, devices.dev[i].device) == 0) {
        if (ipwd_devinfo (check_context.dev.device, check_context.dev.ip, check_context.dev.mac) != IPWD_RV_ERROR) {
          check_context.dev.state = IPWD_DEVICE_STATE_USABLE;
        }
        break;
      }
    }
  }

  if (check_context.dev.state == IPWD_DEVICE_STATE_UNUSABLE) {
    ipwd_message(IPWD_MSG_TYPE_ALERT, "can't find dev: %s - %s", check_context.ip, check_context.misc);
    check_context.stage = -1;
    ipwd_reply_to_method(check_context.msg, check_context.conn, "");
  } else {
    ipwd_message(IPWD_MSG_TYPE_DEBUG, "check ip %s use dev: %s", check_context.ip, check_context.dev.device);
  }
}

void ipwd_check_context_update (void)
{
    switch (check_context.stage) {
      case 0:
        break;
      case 2:
      case 3:
      case 4:
      case 5:
      case 6:
      case 7:
        // send arp packet
        ipwd_genarp(check_context.dev.device, "0.0.0.0", check_context.dev.mac, check_context.ip, "ff:ff:ff:ff:ff:ff", ARPOP_REQUEST);
        usleep(10000);
        check_context.stage++;
        break;
      case 8:
        // reply ok
        ipwd_reply_to_method(check_context.msg, check_context.conn, "");
      default:
        check_context.stage = 0;
        if (check_context.msg != NULL)
          dbus_message_unref(check_context.msg);
      }
}
