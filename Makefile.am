## Process this file with automake to produce Makefile.in

SUBDIRS = src docs po test

NULL =

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=							\
	--disable-man-pages 							\
	$(NULL)

clean-local :
	rm -f *~
