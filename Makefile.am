## Process this file with automake to produce Makefile.in

SUBDIRS = src docs po test

NULL =

EXTRA_DIST = 			\
	HACKING 		\
	$(NULL)

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=							\
	--disable-man-pages 							\
	$(NULL)

sign : dist
	gpg --armor --detach-sign --output polkit-$(VERSION).tar.gz.sign polkit-$(VERSION).tar.gz

publish : sign
	scp polkit-$(VERSION).tar.gz polkit-$(VERSION).tar.gz.sign "david@people.freedesktop.org:/srv/www.freedesktop.org/www/software/polkit/releases/"

clean-local :
	rm -f *~
