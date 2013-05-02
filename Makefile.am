## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4

## Targets
SUBDIRS = src/polkitbackend po test

man_MANS = docs/man/pklocalauthority.8

## Rules
CLEANFILES = $(man_MANS)
EXTRA_DIST = docs/man/pklocalauthority.xml

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --xinclude -o $@ \
		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
