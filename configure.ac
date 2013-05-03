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
AC_PROG_MKDIR_P
AC_PROG_RANLIB
AC_SYS_LARGEFILE
AM_PROG_CC_C_O
AM_PROG_AR

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

if test "x$GCC" = "xyes"; then
  LDFLAGS="-Wl,--as-needed $LDFLAGS"
fi

dnl ---------------------------------------------------------------------------
dnl - Group polkid runs as
dnl ---------------------------------------------------------------------------

AC_ARG_WITH([polkitd_group],
	    [AS_HELP_STRING([--with-polkitd-group=<user>],
                            [Group polkitd runs as (polkitd)])])
if test -z "$with_polkitd_group" ; then
    POLKITD_GROUP=polkitd
else
    POLKITD_GROUP=$with_polkitd_group
fi
AC_SUBST([POLKITD_GROUP])


# ********************
# Internationalization
# ********************

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.1])

AC_CONFIG_FILES([Makefile po/Makefile.in test/Makefile])
AC_OUTPUT

dnl ==========================================================================
echo "
                  polkit $VERSION
                =================

        prefix:                     ${prefix}
        bindir:                     ${bindir}
        sysconfdir:                 ${sysconfdir}
        localstatedir:              ${localstatedir}

        compiler:                   ${CC}
        cflags:                     ${CFLAGS}
        cppflags:                   ${CPPFLAGS}
        xsltproc:                   ${XSLTPROC}

        polkitd group:              ${POLKITD_GROUP}"
echo "


"
echo "NOTE: The directory ${sysconfdir}/polkit-1/localauthority must be owned"
echo "      by root:$POLKITD_GROUP and have mode 750"
echo
echo "NOTE: The directory ${localstatedir}/lib/polkit-1 must be owned"
echo "      by root:$POLKITD_GROUP and have mode 750"
echo
