#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([MockLibc], [1.1], [vonhollen@google.com])
AC_CONFIG_AUX_DIR([../../admin])
AC_CONFIG_MACRO_DIR([../../m4])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AM_PROG_AR

# Checks for libraries.
LT_INIT([disable-static])

# Checks for header files.
AC_CHECK_HEADERS([netdb.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([endgrent endpwent memset regcomp strdup])

# Build wrapper scripts from templates
AC_SUBST([libname], [libmocklibc.so])
#AC_CONFIG_FILES([bin/mocklibc], [chmod +x bin/mocklibc], [libname=${libname}])
#AC_CONFIG_FILES([bin/mocklibc-test], [chmod +x bin/mocklibc-test],
#                [libname=${libname}]))

AC_CONFIG_FILES([
Makefile
src/Makefile
bin/Makefile
])
AC_OUTPUT
