AC_PREREQ([2.68])
AC_INIT([foolgfw], [1.0], [whatever@whatever])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR(foolgfw.c)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_PROG_CC
dnl AC_CHECK_HEADERS([libnetfilter_queue/libnetfilter_queue.h linux/netfilter.h])
dnl AC_CONFIG_HEADERS([])

AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

AC_CHECK_FUNCS([memset socket])

AC_CHECK_LIB([netfilter_queue], [nfq_get_msg_packet_hdr])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
