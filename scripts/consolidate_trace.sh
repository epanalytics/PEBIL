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

prog=$0
pmactrace_dir=$1
execname=$2
appname=$3
dataset=$4
ncpus=$5

set -e

function print_err(){
    echo $1 1>&2
}

function print_usage(){
    if [ "$1" != "" ]; then
        print_err $1
    fi
    print_err "usage: $prog </path/to/pmacTRACE/> <execname> <appname> <dataset> <ncpus>"
    exit 1
}

if [ "$pmactrace_dir" == "" -o "$execname" == "" -o "$appname" == "" -o "$ncpus" == "" ]; then
    print_usage "missing argument(s)"
fi

cpustr=`printf "%04d" $ncpus`
appdir="$execname"_"$dataset"_"$cpustr"
tgtdir=$pmactrace_dir/processed/$appdir

if [ -d "$tgtdir" ]; then
    print_err "target directory already exists, consider removing: $tgtdir"
    exit 1
fi

mkdir -p $tgtdir
cp -r $pmactrace_dir/jbbinst/$appdir/* $tgtdir
cp -r $pmactrace_dir/jbbcoll/$appdir/* $tgtdir
cp -r $pmactrace_dir/siminst/$appdir/* $tgtdir
cp -r $pmactrace_dir/simcoll/$appdir/* $tgtdir
