#
# Process this file with autoconf to produce a configure script.
#/* 
# * This file is part of the pebil project.
# * 
# * Copyright (c) 2010, University of California Regents
# * All rights reserved.
# * 
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation, either version 3 of the License, or
# * (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program.  If not, see <http://www.gnu.org/licenses/>.
# */

AC_PREREQ([2.63])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/ElfFileInst.C])
AC_CONFIG_MACRO_DIR([m4])
m4_include([m4/acx_mpi.m4])
m4_include([m4/ax_cxx_header_unordered_map.m4])
m4_include([m4/ax_compile_stdcxx_0x.m4])
m4_include([m4/ax_check_x86_features.m4])
m4_include([m4/ax_gcc_x86_cpu_supports.m4])

# Check if avx512f instruction set is present
AX_GCC_X86_CPU_SUPPORTS(avx512f, has_avx512="yes", has_avx512="no")
if test "$has_avx512" = "yes"; then
    PEBIL_BUILD_FOR_AVX512="-DHAS_AVX512_SET"
else
    PEBIL_BUILD_FOR_AVX512=""
fi
AC_SUBST(PEBIL_BUILD_FOR_AVX512)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_FC
AC_PROG_CPP

AC_ARG_ENABLE(mpi, AC_HELP_STRING([--enable-mpi], [Use mpi compiler when building instrumentation libraries [yes]]), mpi_ok=$enableval)
if test "$mpi_ok" = "no"; then
   MPICC="$CC"
   MPIFC="$FC"
   MPICXX="$CXX"
   MPI_FLAGS=""
else
   AC_LANG([C])
   ACX_MPI
   AC_LANG_PUSH([Fortran])
   ACX_MPI
   AC_LANG_POP
   AC_LANG_PUSH(C++)
   ACX_MPI
   AC_LANG_POP()
   MPI_FLAGS="-DHAVE_MPI"

   SAVECXX="$CXX"
   CXX="$MPICXX"
   MPI_CXXFLAGS="$CXXFLAGS"
   AC_COMPILE_STDCXX_0X
   AX_CXX_HEADER_UNORDERED_MAP
   if test "$ax_cv_cxx_unordered_map" = "yes"; then
      if test "$ac_cv_cxx_compile_cxx0x_gxx" = "yes"; then
         MPI_CXXFLAGS="-std=gnu++0x";
      elif test "$ac_cv_cxx_compile_cxx0x_cxx" = "yes"; then
         MPI_CXXFLAGS="-std=c++0x";
      else
         AC_MSG_ERROR([configure detected that unordered_map is present for $CXX but neither -std=c++0x nor -std=gnu++0x is accepted])   
      fi
      MPI_CXXFLAGS="$MPI_CXXFLAGS -DHAVE_UNORDERED_MAP"
   fi
   CXX="$SAVECXX"
fi

# set correct map type depending on whether unordered_map is present
AC_COMPILE_STDCXX_0X
AX_CXX_HEADER_UNORDERED_MAP
if test "$ax_cv_cxx_unordered_map" = "yes"; then
   if test "$ac_cv_cxx_compile_cxx0x_gxx" = "yes"; then
      CXXFLAGS="$CXXFLAGS -std=gnu++0x";
   elif test "$ac_cv_cxx_compile_cxx0x_cxx" = "yes"; then
      CXXFLAGS="$CXXFLAGS -std=c++0x";
   else
      AC_MSG_ERROR([configure detected that unordered_map is present for $CXX but neither -std=c++0x nor -std=gnu++0x is accepted])   
   fi
   CXXFLAGS="$CXXFLAGS -DHAVE_UNORDERED_MAP"
fi

#Allow debug option
AC_ARG_ENABLE(debug, AC_HELP_STRING([--debug], [Print debugging information [no]]),debug_ok=$enableval)
if test "$debug_ok" !="yes"; then
    PEBIL_DEBUG="-DWARNING_SEVERITY=20"
else
    PEBIL_DEBUG=""
fi
AC_SUBST(PEBIL_DEBUG)

AC_ARG_ENABLE(static, AC_HELP_STRING([--enable-static], [Build a statically-linked pebil executable in addition to a dynamically-linked executable [yes]]), static_ok=$enableval)
if test "$static_ok" == "yes"; then
   PEBIL_STATIC_BUILD="yes"
else
   PEBIL_STATIC_BUILD="no"
fi
AC_SUBST(PEBIL_STATIC_BUILD)

AC_ARG_ENABLE(mpicxxbind, AC_HELP_STRING([--enable-mpicxxbind], [Assume C++ bindings during build [yes]]), mpicxxbind_ok=$enableval)
if test "$mpicxxbind_ok" != "no"; then
  PEBIL_CXX_BINDINGS="yes"
else
  PEBIL_CXX_BINDINGS="no"
fi
AC_SUBST(PEBIL_CXX_BINDINGS)

AC_CHECK_PROG(OPENMPI_IS_NEW, mpifort, "yes")
if test x"$OPENMPI_IS_NEW" == x"yes"; then
  PEBIL_MPIFC_OPENMPI_LIB="-lmpi_mpifh"
else
  PEBIL_MPIFC_OPENMPI_LIB="-lmpi_f77 -lmpi_f90"
fi
AC_SUBST(PEBIL_MPIFC_OPENMPI_LIB)

AC_ARG_ENABLE(adamant, AC_HELP_STRING([--enable-adamant], [enable adamant [yes]]), adamant_ok=$enableval)
AC_CHECK_HEADERS([adm.h],
  [
    if test "$adamant_ok" == "yes"; 
    then 
      ADAMANT_HEADER_FLAGS="-DHAVE_ADAMANT"
      ADAMANT_LIBS_BUILD="yes"
    else
       ADAMANT_LIBS_BUILD="no"
    fi
  ],
  ADAMANT_LIBS_BUILD="no")

AC_SUBST(ADAMANT_HEADER_FLAGS)
AC_SUBST(ADAMANT_LIBS_BUILD)  

AC_ARG_ENABLE(mpiinit_check, AC_HELP_STRING([--enable-mpiinit-check], [Disable output file printing in inst libraries unless mpi_init is executed [no]]), mpiinit_check_ok=$enableval)
if test "$mpiinit_check_ok" = "yes"; then
   MPI_FLAGS="$MPI_FLAGS -DMPI_INIT_REQUIRED"
fi

AC_SUBST(MPI_FLAGS)
AC_SUBST(MPI_CXXFLAGS)

AC_ARG_WITH(throttler_headers,
            [AS_HELP_STRING([--with-throttler-headers=<path>],[specify path to throttler headers])],
            [throttler_headers=$withval
             AC_CHECK_HEADER([$throttler_headers/throttler.h],
                             [THROTTLER_FLAGS="-DHAVE_THROTTLER_H -I$throttler_headers"],
                             [AC_MSG_ERROR(throttler.h not found using $throttler_headers)])],
            [throttler_headers=no])
AC_SUBST(THROTTLER_FLAGS)

AC_ARG_WITH(epa_tools, [AS_HELP_STRING([--with-epa-tools=<path>],[specify path to epa tools])],
            [epa_tools=$withval], [epa_tools=no])
if test x"$epa_tools" = x"no"; then
    PEBIL_EPA_TOOLS_AVAILABLE="no"
    PEBIL_EPA_TOOLS_PATH=""
else
    PEBIL_EPA_TOOLS_AVAILABLE="yes"
    PEBIL_EPA_TOOLS_PATH="$epa_tools"
fi
AC_SUBST(PEBIL_EPA_TOOLS_AVAILABLE)
AC_SUBST(PEBIL_EPA_TOOLS_PATH)

AC_ARG_ENABLE(papi, AC_HELP_STRING([--enable-papi], [Build with PAPI hardware counter support [yes]]), enable_papi_ok=$enableval)
if test "$enable_papi_ok" = "yes"; then
  PEBIL_PAPI_BUILD="yes"
else
  PEBIL_PAPI_BUILD="no"
fi
AC_SUBST(PEBIL_PAPI_BUILD)

AC_ARG_VAR(PAPI_PATH,[path to PAPI folder])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h strings.h unistd.h])
AC_CHECK_HEADERS([cpufreq.h],
        CPUFREQ_FLAGS="-DHAVE_CPUFREQ_H")
AC_SUBST(CPUFREQ_FLAGS)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tools/Makefile
                 instcode/Makefile
                 scripts/blacklist.sh
                 cshrc
                 bashrc])
AC_CONFIG_SUBDIRS([external/udis86-1.7])
AC_CONFIG_SUBDIRS([external/ReuseDistance])
AC_OUTPUT
chmod +x scripts/blacklist.sh

exit 0
