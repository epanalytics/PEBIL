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
# computes lookahead average from the output for pebil_full_results.py, and prints the results
# only for cpu 0

trace_file=$1
if [ "$trace_file" == "" ]; then
    cat /dev/stdin > tmpfile
    trace_file=tmpfile
fi

head -n1 $trace_file | awk '{for (i = 1; i < 45; i++) { printf $i " "; } print "<n_dud_int> <tot_dud_int> <n_dud_fp> <tot_dud_fp>"; }'
cat $trace_file | awk '{if ($1 == 0) { print $_ }}' | tr ":" " "  | awk '{for (i = 1; i < 45; i++) { printf $i " "; }  ni=0; ti=0; nf=0; tf=0; for (i=45; i <= NF; i += 3) { vi=i+1; vf=i+2; ni+=$vi; ti+=($i*$vi); nf+=$vf; tf+=($i*$vf); } print ni " " ti " " nf " " tf; }'

rm tmpfile
