PROGNAME=	dhcprelya
OBJS=		dhcprelya.o utils.o net_utils.o ip_checksum.o log_plugin.o \
		option82_plugin.o
HEADER=		dhcprelya.h
LIBS=		-L/usr/local/lib -lpcap -lutil -lthr
CFLAGS+=	-Wall -fPIC
PREFIX?=	/usr/local

LOG_PLUGIN_OBJS=	utils.o log_plugin.o
OPTION82_PLUGIN_OBJS=	utils.o option82_plugin.o ip_checksum.o

.if defined(DEBUG)
DEBUG_FLAGS=	-g
.else
STRIP_FLAG=	-s
.endif

LOG_PLUGIN=	log_plugin
RADIUS_PLUGIN=	radius_plugin
OPTION82_PLUGIN=	option82_plugin
.if defined(WITH_RADIUS_PLUGIN)
LIBS+=		-lradius
RADIUS_PLUGIN_OBJS=	utils.o net_utils.o radius_plugin.o
OBJS+=		radius_plugin.o
CFLAGS+=	-rdynamic

all:	${PROGNAME} ${PROGNAME}_${RADIUS_PLUGIN}.so ${PROGNAME}_${LOG_PLUGIN}.so \
	${PROGNAME}_${OPTION82_PLUGIN}.so
.else
all:	${PROGNAME} ${PROGNAME}_${LOG_PLUGIN}.so ${PROGNAME}_${OPTION82_PLUGIN}.so
.endif

${PROGNAME}: ${OBJS}
	${CC} ${DEBUG_FLAGS} ${CFLAGS} ${OBJS} ${LIBS} -o ${.TARGET}

${PROGNAME}_${RADIUS_PLUGIN}.so: ${OBJS}
	${CC} ${DEBUG_FLAGS} -shared ${RADIUS_PLUGIN_OBJS} -o ${.TARGET}

${PROGNAME}_${LOG_PLUGIN}.so: ${OBJS}
	${CC} ${DEBUG_FLAGS} -shared ${LOG_PLUGIN_OBJS} -o ${.TARGET}

${PROGNAME}_${OPTION82_PLUGIN}.so: ${OBJS}
	${CC} ${DEBUG_FLAGS} -shared ${OPTION82_PLUGIN_OBJS} -o ${.TARGET}

.c.o: ${HEADER}
	${CC} ${CPPFLAGS} ${DEBUG_FLAGS} ${CFLAGS} -c ${.IMPSRC}

clean:
	rm -f ${PROGNAME} *.so *.o *.core

install: ${PROGNAME}
	install ${STRIP_FLAG} -m 555 ${PROGNAME} ${PREFIX}/sbin/
	install ${STRIP_FLAG} -m 555 ${PROGNAME}_${LOG_PLUGIN}.so ${PREFIX}/lib/
	install ${STRIP_FLAG} -m 555 ${PROGNAME}_${OPTION82_PLUGIN}.so ${PREFIX}/lib/
.if defined(WITH_RADIUS_PLUGIN)
	install ${STRIP_FLAG} -m 555 ${PROGNAME}_${RADIUS_PLUGIN}.so ${PREFIX}/lib/
.endif

install-rc:
	install -m 555 ${PROGNAME}.sh ${PREFIX}/etc/rc.d/${PROGNAME}

deinstall:
	rm -f ${PREFIX}/sbin/${PROGNAME} ${PREFIX}/lib/${PROGNAME}_* ${PREFIX}/etc/rc.d/${PROGNAME}
