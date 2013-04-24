dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59c)
AC_INIT([polkit-pkla-compat], [0.1],
	[https://fedorahosted.org/polkit-pkla-compat/])
AC_CONFIG_AUX_DIR([admin])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([no-dist-gzip dist-xz no-define subdir-objects])
AC_CONFIG_HEADERS(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Include external mocklibc tool for unit testing
AC_CONFIG_SUBDIRS([test/mocklibc])

AC_PROG_CC
AM_PROG_LIBTOOL
AC_SYS_LARGEFILE
AM_PROG_CC_C_O

# Taken from dbus
AC_ARG_ENABLE(ansi,             [  --enable-ansi           enable -ansi -pedantic gcc flags],enable_ansi=$enableval,enable_ansi=no)

dnl
dnl Check for xsltproc
dnl
AC_PATH_PROG([XSLTPROC], [xsltproc])
if test -z "$XSLTPROC"; then
   AC_MSG_ERROR([cannot find xsltproc])
fi

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

PKG_CHECK_MODULES(GLIB, [glib-2.0 gio-2.0 >= 2.30.0])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
AC_DEFINE([GLIB_VERSION_MIN_REQUIRED], [GLIB_VERSION_2_30],
	[Avoid warning spew about g_type_init() being deprecated])
AC_DEFINE([GLIB_VERSION_MAX_ALLOWED], [G_ENCODE_VERSION(2,34)],
        [Notify us when we'll need to transition away from g_type_init()])

PKG_CHECK_MODULES([POLKIT], [polkit-gobject-1])
AC_SUBST([POLKIT_CFLAGS])
AC_SUBST([POLKIT_LIBS])

AC_ARG_WITH(expat, [  --with-expat=<dir>      Use expat from here],
                      [
                      expat=$withval
                      CPPFLAGS="$CPPFLAGS -I$withval/include"
                      LDFLAGS="$LDFLAGS -L$withval/lib"
                      ]
                      )
AC_CHECK_HEADERS([expat.h], ,
		 [AC_MSG_ERROR([Can't find expat.h. Please install expat.])])
AC_CHECK_LIB([expat], [XML_ParserCreate], [true],
	     [AC_MSG_ERROR([Can't find expat library. Please install expat.])])
AC_SUBST([EXPAT_LIBS], [-lexpat])

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


# ********************
# Internationalization
# ********************

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.1])

AC_CONFIG_FILES([
Makefile
src/polkitbackend/Makefile
docs/man/Makefile
po/Makefile.in
test/Makefile
test/polkitbackend/Makefile
])
AC_OUTPUT

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


"

echo "NOTE: The directory ${sysconfdir}/polkit-1/rules.d must be owned"
echo "      by user '$POLKITD_USER' and have mode 700"
echo

echo "NOTE: The directory ${datadir}/polkit-1/rules.d must be owned"
echo "      by user '$POLKITD_USER' and have mode 700"
echo
