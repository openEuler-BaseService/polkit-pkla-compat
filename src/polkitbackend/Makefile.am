rulesdir = $(sysconfdir)/polkit-1/rules.d
rules_DATA = 50-pkla.rules
EXTRA_DIST = 50-pkla.rules.in

CLEANFILES = $(rules_DATA)

50-pkla.rules: 50-pkla.rules.in Makefile
	sed 's,@bindir@,$(bindir),g' < $(srcdir)/50-pkla.rules.in > $@

# ----------------------------------------------------------------------------------------------------

localauthorityconfigdir = $(sysconfdir)/polkit-1/localauthority.conf.d
dist_localauthorityconfig_DATA = 50-localauthority.conf

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 750 $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chown root:$(POLKITD_GROUP) $(DESTDIR)$(localstatedir)/lib/polkit-1
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 750 $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
	-chown root:$(POLKITD_GROUP) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
