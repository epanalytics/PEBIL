#!/usr/bin/env bash

object-blacklist() { readelf -s $1 | grep FUNC |  grep -v UND | awk '{print $8}' | grep -wvi "main\|main_\|main__\|_fini\|_start\|call_gmon_start"; }

set -e

tmp_file="__pebil__tmp"
list_dir="scripts/inputlist"
list_intermed="$list_dir"/local.func

trivialprog_CC="#ifdef HAVE_MPI\n#include <mpi.h>\n#endif\n\
int main(int argc, char** argv){\n\
#ifdef HAVE_MPI\nMPI_Init(&argc, &argv); MPI_Finalize();\n#endif\n\
return 0; }"

trivialprog_CXX="#ifdef HAVE_MPI\n#include <mpi.h>\n#endif\n\
using namespace std;\nint main(int argc, char** argv){\n\
#ifdef HAVE_MPI\nMPI::Init(argc, argv); MPI::Finalize();\n#endif\n\
return 0; }"

trivialprog_FC="\
      program test\n\
#ifdef HAVE_MPI\n\
      include 'mpif.h'\n\
#endif\n\
      integer ierr\n\
#ifdef HAVE_MPI\n\
      call MPI_Init(ierr)\n\
      call MPI_Finalize (ierr)\n\
#endif\n\
      end"

DO_CXX=yes

# CC blacklist
echo -e "$trivialprog_CC" > "$tmp_file".c
mpicc -DHAVE_MPI   -o "$tmp_file"_c "$tmp_file".c
object-blacklist "$tmp_file"_c > "$list_intermed"

# CXX blacklist
if [ "$DO_CXX" == "yes" ]
then
  echo -e "$trivialprog_CXX" > "$tmp_file".cxx
  mpic++ -DHAVE_MPI   -o "$tmp_file"_cxx "$tmp_file".cxx
  object-blacklist "$tmp_file"_cxx >> "$list_intermed"
fi

# FC blacklist
echo -e "$trivialprog_FC" > "$tmp_file"_f90.c
gcc -E "$tmp_file"_f90.c > "$tmp_file".f90
mpif90 -DHAVE_MPI   -o "$tmp_file"_f90 "$tmp_file".f90
object-blacklist "$tmp_file"_f90 >> "$list_intermed"

sort -u "$list_intermed" | grep .
rm "$list_intermed"
rm "$tmp_file"*

exit 0
