
NULL =

man_MANS = 				\
	pklocalauthority.8		\
	$(NULL)

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

EXTRA_DIST = 				\
	pklocalauthority.xml		\
	$(NULL)

CLEANFILES = $(man_MANS)
