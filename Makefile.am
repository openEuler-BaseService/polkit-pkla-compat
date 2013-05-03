## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(POLKIT_CFLAGS) $(GLIB_CFLAGS)
AM_CPPFLAGS = -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT
LDADD = $(POLKIT_LIBS) $(GLIB_LIBS)
PKLA_CPPFLAGS = -DPACKAGE_LOCALSTATE_DIR='"$(localstatedir)"' \
	-DPACKAGE_SYSCONF_DIR='"$(sysconfdir)"'
TEST_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/test
TESTS_ENVIRONMENT = MOCK_PASSWD=$(abs_top_srcdir)/test/data/etc/passwd \
	MOCK_GROUP=$(abs_top_srcdir)/test/data/etc/group \
	MOCK_NETGROUP=$(abs_top_srcdir)/test/data/etc/netgroup \
	POLKIT_TEST_DATA=$(abs_top_srcdir)/test/data \
	$(abs_top_builddir)/test/mocklibc/bin/mocklibc

## Targets
SUBDIRS = src/polkitbackend po test

bin_PROGRAMS = src/polkitbackend/pkla-admin-identities \
	src/polkitbackend/pkla-check-authorization
man_MANS = docs/pklocalauthority.8

noinst_LIBRARIES = src/polkitbackend/libpolkit-backend.a \
	test/libpolkit-test-helper.a

check_PROGRAMS = test/polkitbackend/polkitbackendlocalauthoritytest \
	test/polkitbackend/polkitbackendlocalauthorizationstoretest
noinst_PROGRAMS = $(check_PROGRAMS)
TESTS = $(check_PROGRAMS)

## Rules
CLEANFILES = $(man_MANS)
EXTRA_DIST = docs/pklocalauthority.xml test/data

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

test_libpolkit_test_helper_a_SOURCES = test/polkittesthelper.c \
	test/polkittesthelper.h

test_polkitbackend_polkitbackendlocalauthoritytest_CPPFLAGS = $(AM_CPPFLAGS) \
	$(TEST_CPPFLAGS)
test_polkitbackend_polkitbackendlocalauthoritytest_LDADD = $(LDADD) \
	src/polkitbackend/libpolkit-backend.a test/libpolkit-test-helper.a

test_polkitbackend_polkitbackendlocalauthorizationstoretest_CPPFLAGS = \
	$(AM_CPPFLAGS) $(TEST_CPPFLAGS)
test_polkitbackend_polkitbackendlocalauthorizationstoretest_LDADD = $(LDADD) \
	src/polkitbackend/libpolkit-backend.a test/libpolkit-test-helper.a

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --xinclude -o $@ \
		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
