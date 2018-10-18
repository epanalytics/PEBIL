CC          = gcc
CXX         = g++
FC          = mpif90
MPICC       = mpicc

BINDIR      = ../src

all: makeTargets

makeTargets:
	$(MAKE) -C toys
	$(MAKE) -C apps

showme:
	which pebil
	ldd `which pebil`

check: makeTargets showme checkAppBinary

checkAppBinary:
	$(MAKE) checkAppBinary -C toys
	$(MAKE) checkAppBinary -C apps

clean: 
	rm -f *.o $(TARGETS) *.jbbinst *.lpiinst *.siminst *.ideinst *.static *.$(OUT)
	$(MAKE) clean -C toys
	$(MAKE) clean -C apps
