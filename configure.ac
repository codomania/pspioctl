AC_INIT([psp-ioctl], [0.1], [brijesh.singh@amd.com])
AM_INIT_AUTOMAKE
AC_PROG_CC
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([GLIB], [glib-2.0])
AC_CHECK_DECLS([SEV_GET_ID2], [], [], [[#include <linux/psp-sev.h>]])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
