
NULL =

AM_CPPFLAGS =                                              	\
	-I$(top_srcdir)/src                             	\
	-I$(top_srcdir)/test                             	\
	-D_POSIX_PTHREAD_SEMANTICS                      	\
	-D_REENTRANT	                                	\
	$(NULL)

AM_CFLAGS =							\
	$(GLIB_CFLAGS)						\
	$(POLKIT_CFLAGS)					\
	$(NULL)

LDADD =  	                      				\
	$(GLIB_LIBS)						\
	$(POLKIT_LIBS)						\
	$(top_builddir)/src/polkitbackend/libpolkit-backend-1.la\
	$(top_builddir)/test/libpolkit-test-helper.la           \
	$(NULL)

TEST_PROGS =

# ----------------------------------------------------------------------------------------------------

TEST_PROGS += polkitbackendlocalauthorizationstoretest
polkitbackendlocalauthorizationstoretest_SOURCES = polkitbackendlocalauthorizationstoretest.c

TEST_PROGS += polkitbackendlocalauthoritytest
polkitbackendlocalauthoritytest_SOURCES = polkitbackendlocalauthoritytest.c

# ----------------------------------------------------------------------------------------------------

noinst_PROGRAMS = $(TEST_PROGS)
check_PROGRAMS = $(TEST_PROGS)
TESTS = $(TEST_PROGS)
