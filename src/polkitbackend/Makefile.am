NULL =

bin_PROGRAMS = pkla-admin-identities pkla-check-authorization

pkla_admin_identities_SOURCES = pkla-admin-identities.c \
	polkitbackendconfigsource.h polkitbackendconfigsource.c

pkla_check_authorization_SOURCES = pkla-check-authorization.c \
	polkitbackendlocalauthorizationstore.h \
	polkitbackendlocalauthorizationstore.c

AM_CPPFLAGS =                                                   \
        -DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\"               \
        -DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\"         \
        -D_POSIX_PTHREAD_SEMANTICS                              \
        -D_REENTRANT                                            \
        $(NULL)

AM_CFLAGS = $(POLKIT_CFLAGS) $(GLIB_CFLAGS)

LDADD = $(POLKIT_LIBS) $(GLIB_LIBS)

noinst_LIBRARIES = libpolkit-backend.a

libpolkit_backend_a_SOURCES =                                   			\
	polkitbackendlocalauthorizationstore.h	polkitbackendlocalauthorizationstore.c	\
        $(NULL)

rulesdir = $(sysconfdir)/polkit-1/rules.d
dist_rules_DATA = 50-pkla.rules

# ----------------------------------------------------------------------------------------------------

localauthorityconfigdir = $(sysconfdir)/polkit-1/localauthority.conf.d
dist_localauthorityconfig_DATA = 50-localauthority.conf

install-data-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 700 $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chown $(POLKITD_USER) $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 700 $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
	-chown $(POLKITD_USER) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
	mkdir -p $(DESTDIR)$(libdir)/polkit-1/extensions
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1/rules.d
	-chmod 700 $(DESTDIR)$(sysconfdir)/polkit-1/rules.d
	-chown $(POLKITD_USER) $(DESTDIR)$(sysconfdir)/polkit-1/rules.d
	mkdir -p $(DESTDIR)$(datadir)/polkit-1/rules.d
	-chmod 700 $(DESTDIR)$(datadir)/polkit-1/rules.d
	-chown $(POLKITD_USER) $(DESTDIR)$(datadir)/polkit-1/rules.d
