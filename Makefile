PROGNAME=	dhcprelya
OBJS=		dhcprelya.o utils.o net_utils.o ip_checksum.o dhcp_utils.o
HEADER=		dhcprelya.h
LIBS=		-lpcap -lutil -lradius -pthread
CFLAGS+=	-Wall -fPIC
LDFLAGS+=	${LIBS}
PREFIX?=	/usr/local

LOG_PLUGIN=	${PROGNAME}_log_plugin.so
RADIUS_PLUGIN=	${PROGNAME}_radius_plugin.so
OPTION82_PLUGIN=	${PROGNAME}_option82_plugin.so
ALL_PLUGINS=	${LOG_PLUGIN} ${RADIUS_PLUGIN} ${OPTION82_PLUGIN}

${LOG_PLUGIN}_OBJS=	utils.o log_plugin.o dhcp_utils.o
${OPTION82_PLUGIN}_OBJS=	utils.o option82_plugin.o ip_checksum.o dhcp_utils.o
${RADIUS_PLUGIN}_OBJS=	utils.o net_utils.o radius_plugin.o dhcp_utils.o

.if defined(DEBUG)
DEBUG_FLAGS=	-g
.else
STRIP_FLAG=	-s
.endif

all:	${PROGNAME} ${ALL_PLUGINS}

${PROGNAME}: ${OBJS}
	${CC} ${LDFLAGS} ${DEBUG_FLAGS} ${OBJS} -o ${.TARGET}

.for _plugin in ${ALL_PLUGINS}
${_plugin}: ${${_plugin}_OBJS}
	${CC} ${DEBUG_FLAGS} -shared ${${_plugin}_OBJS} -o ${.TARGET}
.endfor

.c.o: ${HEADER}
	${CC} ${CPPFLAGS} ${DEBUG_FLAGS} ${CFLAGS} -c ${.IMPSRC}

clean:
	rm -f ${PROGNAME} *.so *.o *.core

install: install-exec install-plugins

install-exec: ${PROGNAME}
	install ${STRIP_FLAG} -m 555 ${PROGNAME} ${DESTDIR}${PREFIX}/sbin/

install-plugins: ${ALL_PLUGINS}
.for _plugin in ${ALL_PLUGINS}
	install ${STRIP_FLAG} -m 555 ${_plugin} ${DESTDIR}${PREFIX}/lib/
.endfor

install-rc:
	install -m 555 ${PROGNAME}.sh ${PREFIX}/etc/rc.d/${PROGNAME}

deinstall:
	rm -f ${PREFIX}/sbin/${PROGNAME} ${PREFIX}/lib/${PROGNAME}_* ${PREFIX}/etc/rc.d/${PROGNAME}
