# IPwatchD - IP conflict detection tool for Linux
# Copyright (C) 2007-2010 Jaroslav Imrich <jariq(at)jariq(dot)sk>

CC= gcc
CFLAGS= -g -Wall -O2 

# 包含路径设置
INCLUDES = -I/usr/include/dbus-1.0 \
	   -I/usr/include/dbus-1.0/dbus/dbus.h \
           -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include \
	   -I/usr/include/glib-2.0 \
	   -I/usr/lib/x86_64-linux-gnu/glib-2.0 \

LIBS= -lpcap -lnet  $(shell pkg-config --libs dbus-1 glib-2.0) 
override CFLAGS +=  $(shell pkg-config --cflags dbus-1 glib-2.0)
override CFLAGS += -fPIC -fstack-protector-all -z relro -z noexecstack -z now -pie

all: analyse.o config.o daemonize.o devinfo.o genarp.o ipwatchd.o message.o signal.o dbus.o utils.o
	$(CC) $(CFLAGS) analyse.o config.o daemonize.o devinfo.o genarp.o \
	ipwatchd.o message.o signal.o dbus.o utils.o -o ipwatchd $(LIBS)


analyse.o: analyse.c ipwatchd.h
	$(CC) $(CFLAGS) -c analyse.c -o analyse.o

config.o: config.c ipwatchd.h
	$(CC) $(CFLAGS) -c config.c -o config.o

daemonize.o: daemonize.c ipwatchd.h
	$(CC) $(CFLAGS) -c daemonize.c -o daemonize.o

devinfo.o: devinfo.c ipwatchd.h
	$(CC) $(CFLAGS) -c devinfo.c -o devinfo.o

genarp.o: genarp.c ipwatchd.h
	$(CC) $(CFLAGS) -c genarp.c -o genarp.o

ipwatchd.o: ipwatchd.c ipwatchd.h
	$(CC) $(CFLAGS) -c ipwatchd.c -o ipwatchd.o

message.o: message.c ipwatchd.h
	$(CC) $(CFLAGS) -c message.c -o message.o

signal.o: signal.c ipwatchd.h
	$(CC) $(CFLAGS) -c signal.c -o signal.o

dbus.o: dbus.c ipwatchd.h
	$(CC) $(CFLAGS) -c dbus.c -o dbus.o

utils.o: utils.c ipwatchd.h
	$(CC) $(CFLAGS) -c utils.c -o utils.o

clean:
	-rm *.o

distclean: clean
	-rm ipwatchd


install:
	mkdir -p $(DESTDIR)/etc/init.d
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/share/man/man8
	mkdir -p $(DESTDIR)/usr/share/man/man5
	mkdir -p $(DESTDIR)/usr/share/man/man1
	mkdir -p ${DESTDIR}/usr/share/dbus-1/system.d
	cp ipwatchd $(DESTDIR)/usr/sbin
	cp scripts/ipwatchd-script $(DESTDIR)/usr/sbin
	cp scripts/ipwatchd $(DESTDIR)/etc/init.d
	cp ipwatchd.conf $(DESTDIR)/etc
	cp misc/conf/*.conf ${DESTDIR}/usr/share/dbus-1/system.d/
	cp -r misc/system-services ${DESTDIR}/usr/share/dbus-1/
	cp ../doc/ipwatchd.8.gz $(DESTDIR)/usr/share/man/man8
	cp ../doc/ipwatchd.conf.5.gz $(DESTDIR)/usr/share/man/man5
	cp ../doc/ipwatchd-script.1.gz $(DESTDIR)/usr/share/man/man1



uninstall:
	rm $(DESTDIR)/usr/sbin/ipwatchd
	rm $(DESTDIR)/usr/sbin/ipwatchd-script
	rm $(DESTDIR)/etc/init.d/ipwatchd
	rm $(DESTDIR)/etc/ipwatchd.conf
	rm $(DESTDIR)/usr/share/man/man8/ipwatchd.8.gz
	rm $(DESTDIR)/usr/share/man/man5/ipwatchd.conf.5.gz
	rm $(DESTDIR)/usr/share/man/man1/ipwatchd-script.1.gz
