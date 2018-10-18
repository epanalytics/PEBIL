#!/usr/bin/env csh

setenv PEBIL_ROOT /home/ewoodruff/bitbucket/pebil
echo "***** initializing environment using PEBIL_ROOT=$PEBIL_ROOT"
setenv LD_LIBRARY_PATH ${PEBIL_ROOT}/lib:${PEBIL_ROOT}/external/ReuseDistance:${LD_LIBRARY_PATH}
setenv PATH ${PEBIL_ROOT}/bin:${PEBIL_ROOT}/scripts:${PEBIL_ROOT}/external/udis86-1.7/udcli:${PATH}

