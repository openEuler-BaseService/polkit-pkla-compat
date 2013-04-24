## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/polkitbackend docs/man po test

NULL =

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=							\
	--disable-man-pages 							\
	$(NULL)

clean-local :
	rm -f *~
