#!/usr/bin/env bash
#
# This file is part of the pebil project.
#
# Copyright (c) 2010, University of California Regents
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

sfile=$1

if [ "$sfile" == "" ]; then
    echo "usage: $0 <static_file>"
    exit -1
fi

if [ -f $sfile ]; then
    grep -v "^#" $sfile | grep -v "+" | awk '{print $2 " dfTypePattern_Gather"}'
else
    echo "file not found: $sfile"
    exit -1
fi
