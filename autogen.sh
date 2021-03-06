#!/bin/bash

#  This file is part of libminidump.
#
#  Copyright 2012 Lennart Poettering
#
#  libminidump is free software; you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as
#  published by the Free Software Foundation; either version 2.1 of
#  the License, or (at your option) any later version.
#
#  libminidump is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with libminidump; If not, see
#  <http://www.gnu.org/licenses/>.

if [ -f .git/hooks/pre-commit.sample -a ! -f .git/hooks/pre-commit ] ; then
        cp -p .git/hooks/pre-commit.sample .git/hooks/pre-commit && \
        chmod +x .git/hooks/pre-commit && \
        echo "Activated pre-commit hook."
fi

autoreconf --force --install --symlink

if [ "x$1" != "xc" ]; then
        echo
        echo "----------------------------------------------------------------"
        echo "Initialized build system. For a common configuration please run:"
        echo "----------------------------------------------------------------"
        echo
        echo "./configure CFLAGS='-g -O0' $args"
        echo
else
        echo ./configure CFLAGS='-g -O0' $args
        ./configure CFLAGS='-g -O0' $args
        make clean
fi
