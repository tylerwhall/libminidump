#  -*- Mode: makefile; indent-tabs-mode: t -*-
#
#  This file is part of libminidump.
#
#  Copyright 2012 Lennart Poettering
#
#  libminidump is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  libminidump is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with libminidump; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

LIBMINIDUMP_CURRENT=0
LIBMINIDUMP_REVISION=0
LIBMINIDUMP_AGE=0

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h

AM_CFLAGS = $(WARNINGFLAGS)

pkgconfiglibdir=$(libdir)/pkgconfig

lib_LTLIBRARIES = \
	libminidump.la

libminidump_la_SOURCES = \
	minidump.h \
	format.h \
	context.h \
	context.c \
	read-coredump.h \
	read-coredump.c \
	read-minidump.h \
	read-minidump.c \
	read-process.h \
	read-process.c \
	write-minicore.h \
	write-minicore.c \
	write-minidump.h \
	write-minidump.c \
	coredump-util.h \
	coredump-util.c \
	util.h \
	util.c

libminidump_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libminidump_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-version-info $(LIBMINIDUMP_CURRENT):$(LIBMINIDUMP_REVISION):$(LIBMINIDUMP_AGE) \
	-Wl,--version-script=$(top_srcdir)/libminidump.sym

include_HEADERS = \
	minidump.h

bin_PROGRAMS = \
	mkminidump

mkminidump_SOURCES = \
	mkminidump.c

mkminidump_LDADD = \
	libminidump.la

noinst_PROGRAMS = \
	segfault

segfault_SOURCES = \
	segfault.c

segfault_CFLAGS = \
	$(AM_CFLAGS) \
	-pthread

noinst_DATA = \
	core

core: segfault
	$(AM_V_GEN)( ./segfault ||:) > /dev/null 2>&1

pkgconfiglib_DATA= \
	libminidump.pc

EXTRA_DIST = \
	libminidump.sym \
	libminidump.pc.in

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED)	-e 's,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g' \
		-e 's,@PACKAGE_NAME\@,$(PACKAGE_NAME),g' \
		-e 's,@PACKAGE_URL\@,$(PACKAGE_URL),g' \
		-e 's,@prefix\@,$(prefix),g' \
		-e 's,@exec_prefix\@,$(exec_prefix),g' \
		-e 's,@libdir\@,$(libdir),g' \
		-e 's,@includedir\@,$(includedir),g' \
		-e 's,@VERSION\@,$(VERSION),g' \
		< $< > $@ || rm $@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

CLEAN_FILES = \
	core.* \
	core \
	$(pkgconfiglib_DATA)
