dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59c)
AC_INIT([polkit], [0.111], [http://lists.freedesktop.org/mailman/listinfo/polkit-devel])
AM_INIT_AUTOMAKE([])
AC_CONFIG_HEADERS(config.h)
AM_MAINTAINER_MODE

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Include external mocklibc tool for unit testing
AC_CONFIG_SUBDIRS([test/mocklibc])

# libtool versioning - this applies to all libraries in this package
#
# See http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91 for details
#
LT_CURRENT=0
LT_REVISION=0
LT_AGE=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

AC_ISC_POSIX
AC_PROG_CC
AC_HEADER_STDC
AM_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_SYS_LARGEFILE
AM_PROG_CC_C_O

# Taken from dbus
AC_ARG_ENABLE(ansi,             [  --enable-ansi           enable -ansi -pedantic gcc flags],enable_ansi=$enableval,enable_ansi=no)
AC_ARG_ENABLE(man-pages,        [  --enable-man-pages      build manual pages],enable_man_pages=$enableval,enable_man_pages=yes)

if test "${enable_man_page}" != no; then
dnl
dnl Check for xsltproc
dnl
AC_PATH_PROG([XSLTPROC], [xsltproc])
  if test -z "$XSLTPROC"; then
    enable_man_pages=no
  fi
fi
AM_CONDITIONAL(MAN_PAGES_ENABLED, test x$enable_man_pages = xyes)

#### gcc warning flags

if test "x$GCC" = "xyes"; then
  changequote(,)dnl
  case " $CFLAGS " in
  *[\ \	]-Wall[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wchar-subscripts[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wchar-subscripts" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wmissing-declarations[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wmissing-declarations" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wnested-externs[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wnested-externs" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wpointer-arith[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wpointer-arith" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wcast-align[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wcast-align" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wsign-compare[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wsign-compare" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wformat[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wformat" ;;
  esac

  case " $CFLAGS " in
  *[\ \	]-Wformat-security[\ \	]*) ;;
  *) CFLAGS="$CFLAGS -Wformat-security" ;;
  esac

  if test "x$enable_ansi" = "xyes"; then
    case " $CFLAGS " in
    *[\ \	]-ansi[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -ansi" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-D_POSIX_C_SOURCE*) ;;
    *) CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=199309L" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-D_BSD_SOURCE[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -D_BSD_SOURCE" ;;
    esac

    case " $CFLAGS " in
    *[\ \	]-pedantic[\ \	]*) ;;
    *) CFLAGS="$CFLAGS -pedantic" ;;
    esac
  fi
  changequote([,])dnl
fi

PKG_CHECK_MODULES(GLIB, [gmodule-2.0 gio-2.0 >= 2.30.0])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
AC_DEFINE([GLIB_VERSION_MIN_REQUIRED], [GLIB_VERSION_2_30],
	[Avoid warning spew about g_type_init() being deprecated])
AC_DEFINE([GLIB_VERSION_MAX_ALLOWED], [G_ENCODE_VERSION(2,34)],
        [Notify us when we'll need to transition away from g_type_init()])

PKG_CHECK_MODULES([POLKIT], [polkit-gobject-1])
AC_SUBST([POLKIT_CFLAGS])
AC_SUBST([POLKIT_LIBS])

EXPAT_LIB=""
AC_ARG_WITH(expat, [  --with-expat=<dir>      Use expat from here],
                      [
                      expat=$withval
                      CPPFLAGS="$CPPFLAGS -I$withval/include"
                      LDFLAGS="$LDFLAGS -L$withval/lib"
                      ]
                      )
AC_CHECK_HEADERS(expat.h, [AC_DEFINE(HAVE_EXPAT_H)], 
		 [AC_MSG_ERROR([Can't find expat.h. Please install expat.])])
AC_CHECK_LIB(expat,XML_ParserCreate,[EXPAT_LIBS="-lexpat"],
	     [AC_MSG_ERROR([Can't find expat library. Please install expat.])])
AC_SUBST(EXPAT_LIBS)

AC_CHECK_FUNCS(clearenv)

if test "x$GCC" = "xyes"; then
  LDFLAGS="-Wl,--as-needed $LDFLAGS"
fi

dnl ---------------------------------------------------------------------------
dnl - Select wether to use libsystemd-login or ConsoleKit for session tracking
dnl ---------------------------------------------------------------------------

have_libsystemd_login=no
SESSION_TRACKING=ConsoleKit

AC_ARG_ENABLE([libsystemd-login],
              AS_HELP_STRING([--enable-libsystemd-login[=@<:@auto/yes/no@:>@]], [Use libsystemd-login (auto/yes/no)]),
              [enable_libsystemd_login=$enableval],
              [enable_libsystemd_login=auto])
if test "$enable_libsystemd_login" != "no"; then
  PKG_CHECK_MODULES(LIBSYSTEMD_LOGIN,
                    [libsystemd-login],
                    have_libsystemd_login=yes,
                    have_libsystemd_login=no)
  if test "$have_libsystemd_login" = "yes"; then
    SESSION_TRACKING=libsystemd-login
    AC_DEFINE([HAVE_LIBSYSTEMD_LOGIN], 1, [Define to 1 if libsystemd-login is available])
  else
    if test "$enable_libsystemd_login" = "yes"; then
      AC_MSG_ERROR([libsystemd-login support requested but libsystemd-login library not found])
    fi
  fi
fi

AS_IF([test "x$cross_compiling" != "xyes" ], [
  AS_IF([test "$have_libsystemd_login" = "yes"], [
    AS_IF([test ! -d /sys/fs/cgroup/systemd/ ], [
      AS_IF([test "$enable_libsystemd_login" = "yes"], [
        AC_MSG_WARN([libsystemd-login requested but system does not appear to be using systemd])
      ], [
        AC_MSG_ERROR([libsystemd-login autoconfigured, but system does not appear to use systemd])
      ])
    ])
  ], [
    AS_IF([test -d /sys/fs/cgroup/systemd/ ], [
      AS_IF([test "$enable_libsystemd_login" = "no" ], [
        AC_MSG_WARN([ConsoleKit requested but system appears to use systemd])
      ], [
        AC_MSG_ERROR([ConsoleKit autoconfigured, but systemd is in use (missing libsystemd-login pkg-config?)])
      ])
    ])
  ])
])

AC_SUBST(LIBSYSTEMD_LOGIN_CFLAGS)
AC_SUBST(LIBSYSTEMD_LOGIN_LIBS)
AM_CONDITIONAL(HAVE_LIBSYSTEMD_LOGIN, [test "$have_libsystemd_login" = "yes"], [Using libsystemd-login])

dnl ---------------------------------------------------------------------------
dnl - User for running polkitd
dnl ---------------------------------------------------------------------------

AC_ARG_WITH(polkitd_user, AS_HELP_STRING([--with-polkitd-user=<user>],[User for running polkitd (polkitd)]))

if test -z "$with_polkitd_user" ; then
    POLKITD_USER=polkitd
else
    POLKITD_USER=$with_polkitd_user
fi
AC_SUBST(POLKITD_USER)
AC_DEFINE_UNQUOTED(POLKITD_USER,"$POLKITD_USER", [User for running polkitd])


# ********************
# Internationalization
# ********************

IT_PROG_INTLTOOL([0.40.0])
GETTEXT_PACKAGE=polkit-1
AC_SUBST([GETTEXT_PACKAGE])
AM_GLIB_GNU_GETTEXT
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[gettext domain])

AC_OUTPUT([
Makefile
src/Makefile
src/polkitbackend/Makefile
docs/version.xml
docs/Makefile
docs/man/Makefile
po/Makefile.in
test/Makefile
test/polkitbackend/Makefile
])

dnl ==========================================================================
echo "
                  polkit $VERSION
                =================

        prefix:                     ${prefix}
        libdir:                     ${libdir}
        libexecdir:                 ${libexecdir}
        bindir:                     ${bindir}
        datadir:                    ${datadir}
        sysconfdir:                 ${sysconfdir}
        localstatedir:              ${localstatedir}

        compiler:                   ${CC}
        cflags:                     ${CFLAGS}
        cppflags:                   ${CPPFLAGS}
        xsltproc:                   ${XSLTPROC}

        Session tracking:           ${SESSION_TRACKING}
        polkitd user:               ${POLKITD_USER}"
echo "
        Maintainer mode:            ${USE_MAINTAINER_MODE}
        Building man pages:         ${enable_man_pages}
        Building examples:          ${enable_examples}

"

echo "NOTE: The file ${prefix}/lib/polkit-1/polkit-agent-helper-1 must be owned"
echo "      by root and have mode 4755 (setuid root binary)"
echo

echo "NOTE: The file ${bindir}/pkexec must be owned by root and"
echo "      have mode 4755 (setuid root binary)"
echo

echo "NOTE: The directory ${sysconfdir}/polkit-1/rules.d must be owned"
echo "      by user '$POLKITD_USER' and have mode 700"
echo

echo "NOTE: The directory ${datadir}/polkit-1/rules.d must be owned"
echo "      by user '$POLKITD_USER' and have mode 700"
echo
