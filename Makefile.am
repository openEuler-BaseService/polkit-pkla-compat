## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(POLKIT_CFLAGS) $(GLIB_CFLAGS)
AM_CPPFLAGS = -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT
LDADD = $(POLKIT_LIBS) $(GLIB_LIBS)
PKLA_CPPFLAGS = -DPACKAGE_LOCALSTATE_DIR='"$(localstatedir)"' \
	-DPACKAGE_SYSCONF_DIR='"$(sysconfdir)"'
TESTS_ENVIRONMENT = MOCK_PASSWD=$(abs_top_srcdir)/test/data/etc/passwd \
	MOCK_GROUP=$(abs_top_srcdir)/test/data/etc/group \
	MOCK_NETGROUP=$(abs_top_srcdir)/test/data/etc/netgroup \
	POLKIT_TEST_DATA=$(abs_top_srcdir)/test/data \
	$(abs_top_builddir)/test/mocklibc/bin/mocklibc
rulesdir = $(sysconfdir)/polkit-1/rules.d

## Targets
SUBDIRS = po test

bin_PROGRAMS = src/pkla-admin-identities src/pkla-check-authorization
man_MANS = docs/pkla-admin-identities.8 docs/pkla-check-authorization.8 \
	docs/pklocalauthority.8
rules_DATA = src/49-polkit-pkla-compat.rules

noinst_LIBRARIES = src/libpolkit-backend.a test/libpolkit-test-helper.a

check_PROGRAMS = test/polkitbackendlocalauthoritytest \
	test/polkitbackendlocalauthorizationstoretest
noinst_PROGRAMS = $(check_PROGRAMS)
TESTS = $(check_PROGRAMS)

## Rules
CLEANFILES = $(man_MANS) $(rules_DATA)
EXTRA_DIST = docs/pkla-admin-identities.xml docs/pkla-check-authorization.xml \
	docs/pklocalauthority.xml \
	src/49-polkit-pkla-compat.rules.in test/data

src_libpolkit_backend_a_SOURCES = src/polkitbackendlocalauthorizationstore.c \
	src/polkitbackendlocalauthorizationstore.h

src_pkla_admin_identities_SOURCES = src/pkla-admin-identities.c \
	src/polkitbackendconfigsource.c src/polkitbackendconfigsource.h
src_pkla_admin_identities_CPPFLAGS = $(AM_CPPFLAGS) $(PKLA_CPPFLAGS)

src_pkla_check_authorization_CPPFLAGS = $(AM_CPPFLAGS) $(PKLA_CPPFLAGS)
src_pkla_check_authorization_LDADD = $(LDADD) src/libpolkit-backend.a

test_libpolkit_test_helper_a_SOURCES = test/polkittesthelper.c \
	test/polkittesthelper.h

test_polkitbackendlocalauthoritytest_LDADD = $(LDADD) src/libpolkit-backend.a \
	test/libpolkit-test-helper.a

test_polkitbackendlocalauthorizationstoretest_LDADD = $(LDADD) \
	src/libpolkit-backend.a test/libpolkit-test-helper.a

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority.conf.d
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 750 $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chown root:$(POLKITD_GROUP) $(DESTDIR)$(localstatedir)/lib/polkit-1
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 750 $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
	-chown root:$(POLKITD_GROUP) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --xinclude -o $@ \
		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

src/49-polkit-pkla-compat.rules: src/49-polkit-pkla-compat.rules.in Makefile
	sed 's,@''bindir''@,$(bindir),g' \
		< $(srcdir)/src/49-polkit-pkla-compat.rules.in > $@
