rulesdir = $(sysconfdir)/polkit-1/rules.d
dist_rules_DATA = 50-pkla.rules

# ----------------------------------------------------------------------------------------------------

localauthorityconfigdir = $(sysconfdir)/polkit-1/localauthority.conf.d
dist_localauthorityconfig_DATA = 50-localauthority.conf

install-data-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 750 $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chown root:$(POLKITD_GROUP) $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 750 $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
	-chown root:$(POLKITD_GROUP) $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
