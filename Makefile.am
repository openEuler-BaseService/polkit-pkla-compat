## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(POLKIT_CFLAGS) $(GLIB_CFLAGS)
AM_CPPFLAGS = -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT
LDADD = $(POLKIT_LIBS) $(GLIB_LIBS)
PKLA_CPPFLAGS = -DPACKAGE_LOCALSTATE_DIR='"$(localstatedir)"' \
	-DPACKAGE_SYSCONF_DIR='"$(sysconfdir)"'

## Targets
SUBDIRS = src/polkitbackend po . test

bin_PROGRAMS = src/polkitbackend/pkla-admin-identities \
	src/polkitbackend/pkla-check-authorization
man_MANS = docs/pklocalauthority.8

noinst_LIBRARIES = src/polkitbackend/libpolkit-backend.a

## Rules
CLEANFILES = $(man_MANS)
EXTRA_DIST = docs/pklocalauthority.xml

src_polkitbackend_libpolkit_backend_a_SOURCES = \
	src/polkitbackend/polkitbackendlocalauthorizationstore.c \
	src/polkitbackend/polkitbackendlocalauthorizationstore.h

src_polkitbackend_pkla_admin_identities_SOURCES = \
	src/polkitbackend/pkla-admin-identities.c \
	src/polkitbackend/polkitbackendconfigsource.c \
	src/polkitbackend/polkitbackendconfigsource.h
src_polkitbackend_pkla_admin_identities_CPPFLAGS = $(AM_CPPFLAGS) \
	$(PKLA_CPPFLAGS)

src_polkitbackend_pkla_check_authorization_CPPFLAGS = $(AM_CPPFLAGS) \
	$(PKLA_CPPFLAGS)
src_polkitbackend_pkla_check_authorization_LDADD = $(LDADD) \
	src/polkitbackend/libpolkit-backend.a

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --xinclude -o $@ \
		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
