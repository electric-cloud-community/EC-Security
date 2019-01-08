# Makefile

SRCTOP=..
include $(SRCTOP)/build/vars.mak


NTESTINCLUDES += -Isrc/test/ntest -Isrc/main/resources/project/lib
ntest: NTESTFILES ?= src/test/ntest
systemtest-run: NTESTFILES?=systemtest

build: package
unittest: ntest
systemtest: systemtest-setup systemtest-run systemtest-cleanup

.PHONY: systemtest-setup
systemtest-setup:
	$(INSTALL_PLUGINS) EC-Security

systemtest-cleanup:
	$(EC_PERL) systemtest/setup.pl teardown

include $(SRCTOP)/build/rules.mak
