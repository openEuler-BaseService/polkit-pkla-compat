
SUBDIRS = mocklibc . polkitbackend

EXTRA_DIST = data

# Use mocklibc to override NSS services for tests
export MOCK_PASSWD   := $(abs_top_srcdir)/test/data/etc/passwd
export MOCK_GROUP    := $(abs_top_srcdir)/test/data/etc/group
export MOCK_NETGROUP := $(abs_top_srcdir)/test/data/etc/netgroup
export TESTS_ENVIRONMENT := $(abs_top_builddir)/test/mocklibc/bin/mocklibc

# Include path to mock config files
export POLKIT_TEST_DATA := $(abs_top_srcdir)/test/data


# Never install anything in this dir (specifically MockLibc)
install:; @:
install-exec:; @:
install-data:; @:
uninstall:; @:

