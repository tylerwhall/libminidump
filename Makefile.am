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
	src/minidump.h \
	src/format.h \
	src/context.h \
	src/context.c \
	src/read-coredump.h \
	src/read-coredump.c \
	src/read-minidump.h \
	src/read-minidump.c \
	src/read-process.h \
	src/read-process.c \
	src/write-minicore.h \
	src/write-minicore.c \
	src/write-minidump.h \
	src/write-minidump.c \
	src/coredump-util.h \
	src/coredump-util.c \
	src/util.h \
	src/util.c

libminidump_la_CFLAGS = \
	$(AM_CFLAGS) \
	-fvisibility=hidden

libminidump_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-shared \
	-version-info $(LIBMINIDUMP_CURRENT):$(LIBMINIDUMP_REVISION):$(LIBMINIDUMP_AGE) \
	-Wl,--version-script=$(top_srcdir)/src/libminidump.sym

include_HEADERS = \
	src/minidump.h

bin_PROGRAMS = \
	mkminidump

mkminidump_SOURCES = \
	src/mkminidump.c

mkminidump_LDADD = \
	libminidump.la

noinst_PROGRAMS = \
	segfault

segfault_SOURCES = \
	src/segfault.c

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
	src/libminidump.sym \
	src/libminidump.pc.in \
	src/Makefile

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

%.pc: src/%.pc.in Makefile
	$(SED_PROCESS)

CLEANFILES = \
	core.* \
	core \
	$(pkgconfiglib_DATA)
