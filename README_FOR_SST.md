# README for SST Users

## About
This document contains the requirements for building and using the 
PEBIL binary instrumentation package for use with SST's Ariel component.

PEBIL can be used to instrument and run binaries on x86 systems. For
arm-based systems, check out EP Analytic's EPAX toolkit.

Direct any questions or comments to allysonc@epanalytics.com

## Build

### System Requirements

    Operating System          Linux
    Architecture              ia32 or x86_64
    Binary Format             ELF

### Set Up

1. Clone PEBIL from https://github.com/epanalytics/PEBIL.

2. Checkout the `feature/sst` branch.

3. Initialize the `epa-inst-libs` submodule like so:

  ```
      $ git submodule init external/epa-inst-libs
      $ git submodule update
  ```

  Note: `external/epa-pebil-tools` is a private submodule. github users will
        not be able to access this submodule, and will encounter errors if 
        initializing submodules without specifying `external/epa-inst-libs`.
        `epa-pebil-tools` is not necessary to use PEBIL. 

### Configure

PEBIL uses an autoconf configure script to generate Makefiles. To build for 
use with SST, you must include `--with-sst-core` and `--with-sst-elements`:

  ```
      ./configure --with-sst-core=${SST_CORE_HOME}
                  --with-sst-elements=${SST_ELEMENTS_HOME}
  ```

Here are configure options to consider:

  * `--with-sst-core=/path/to/sst-core` : To build SST-related instrumentation
      tools. Must also use `--with-sst-elements`.
  * `--with-sst-elements=/path/to/sst-elements` : To build SST-related
      instrumentation. Must also use `--with-sst-core`.
  * `--enable-mpicxxbind` : If using a version of MPI that calls
      C++ bindings.
  * `--prefix=/path/to/install` : The default location for a PEBIL install is
      the PEBIL directory. Use this parameter to change that.

It is best practice to use the same C/C++ compilers that you use to build 
your executable. If there are multiple compilers in your environment or the 
configure script is not picking up the compilers, set them with:
  * `CC=<C compiler>` : Specify the C compiler
  * `CXX=<C++ compiler>` : Specify the C++ compiler
  * `FC=<Fortran compiler>` : Specify the fortran compiler
  * `MPICC=<MPI C compiler>` : Specify the MPI wrapper for the C compiler
  * `MPICXX=<MPI C++ compiler>` : Specify the MPI wrapper for the C++ compiler
  * `MPIFC=<MPI Fortran compiler>` : Specify the MPI wrapper for the fortran
      compiler

### Make

Bring PEBIL into your environment and build:

  ```
      cd /path/to/PEBIL
      source bashrc
      make all install
  ```

Verify that the following tools/libraries built:
  1. /path/to/PEBIL/bin/pebil
  2. /path/to/PEBIL/lib/libArielInterceptTool.so
  3. /path/to/PEBIL/lib/libddressstream.so

## Using PEBIL for SST

### Source PEBIL

If PEBIL isn't already in your environment, do that with

  ```
      source /path/to/PEBIL/bashrc
  ```

### Instrument the Application

In order to use the EPA Ariel frontend, the application must be instrumented. 
PEBIL will create a copy of the compiled binary and insert snippets of 
assembly to collect the address stream at runtime and pass it to SST. Do this
with:

  ```
      pebil --tool ArielIntercept --app <YourApplication> --inp <option>
            --saveall [--threaded] [--fbl <FunctionList>]
  ```

This will produce an instrumented binary called `<YourApplication>.arielinst`.

Explanation:

    --tool ArielIntercept   Tells PEBIL to insert assembly to collect the
                              address stream for SST
    --app <YourApp>         The binary to instrument for simulation
    --inp <option>          Which memory operations to instrument. Specify
                              either + or <BlockList>
                              + : Instrument every memory operation
                              <BlockList> : A file listing which basic blocks
                                to instrument (see below)
    --saveall               Assume all registers are live -- save them before
                              using them
    --threaded              Required for OpenMP applications
    --fbl <FunctionList>    A file listing spcific functions to exclude or
                              include during instrumentattion (see below)

### Setting up your SST script

Minor changes to your SST script are required to the Ariel Component to use 
the EPA frontend:
  1. Point your script to run the instrumented executable instead of the 
     original:
     ```
        "executable"   :  "<YourApplication>.arielinst"
     ```
  2. Specify the epa frontend:
     ```
        "frontend"     :  "ariel.frontend.epa"
     ```
  3. RECOMMENDED: set or add environment variables to adjust how to collect
     the address stream (see below). By default, the simulation will use a 
     10% sampling rate of the main application (no shared libraries).

### Tweaking Instrumentation

PEBIL offers a number of ways to change which memory operations are collected 
and how often they are collected.

#### Excluding and Including Functions (the --fbl option)

This option is the easiest way to start instrumenting a selection of the 
application as it does not require any modifications to the source code and 
thus does not necessitate recompiling.

**Exclude List**:
If you have a list of functions that you are not interested in (or they are 
causing an issue with instrumentation), you can add them to an exclude list.
PEBIL will collect the memory address stream for all functions that are not 
on this list. Create a file with the functions to exclude, one on each line:

             function1
             function2
             function3
             ...

Note that for C++ applications, the function name should be the mangled name.

**Include List**:
Similar to the exclude list you can specify functions that you *only* want to
simulate. This can greatly reduce simulation time. This can also be helpful to
reduce the size of the instrumented binary by listing only user defined 
functions that are utilized for a given input. Create a file with the fuctions
to include, one on each line, and add a * at the top of the file:

             *
             function1
             function2
             function3
             ...

Note that for C++ applications, the function name should be the mangled name.

**Mangled Names/Fortran/OpenMP**:
PEBIL uses the function name as it is defined in the application symbol table. 
For C++, this usually means a mangled name. If you uncertain what the mangled 
name is, you can use `nm` to find it. For example, if you are hoping add
a specific copy function to your list, look for it with:

  ```
      nm omp-stream | grep "copy"
      0000000000401ea0 W _ZN9OMPStreamIfE4copyEv
      0000000000401a50 t _ZN9OMPStreamIfE4copyEv._omp_fn.0
      00000000004066f0 W _ZSt16__do_uninit_copyIPKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPS5_ET0_T_SA_S9_
  ```

You can verify the mangled name with `c++filt`:

  ```
      c++filt _ZN9OMPStreamIfE4copyEv
      OMPStream<float>::copy()
  ```

Fortran function names often end in an underscore, so be sure to verify 
them with `nm`:
  ```
      nm gsnap | grep "translv"
      0000000000412e50 T translv_
      0000000000411840 t translv_._omp_fn.0
      0000000000410d40 t translv_._omp_fn.1
  ```

Lastly, your compiler may generate separate functions for parallel regions. 
In the examples above, the gnu compiler created extra functions, labeled with
`_omp_fn`, to handle the OpenMP regions. Be sure to include these names in 
your include/exclude lists to instrument the entire function.

**Include + Exclude**
At this time, there is no way to ust both an include list and an exclude list.

#### Specifying Blocks (the --inp option)

Sometimes, you may not want to instrument every single memory operation in 
your application and you might not have enough information to create an 
exclude or include list (see above). Perhaps the simulation is taking too 
long. Perhaps instrumentation is taking too long. Or perhaps PEBIL is running 
into a memory operation that it does not know how to instrument. To help get 
around this, PEBIL offers a way to instrument certain blocks in the app.

Most users will not be able to select the blocks on their own, so here is a 
workflow to generate a list of blocks:

1. Instrument the application with a block counter. This lightweight tool will
   tell you how many times a block is executed in a given run.
   ```
      pebil --tool BasicBlockCounter --app <YourApplication> --saveall
            [--threaded] [--fbl <FunctionList>]
   ```
   This will generate a file called `<YourApplication>.jbbinst`. The option 
   descriptions are the same as for the ArielIntercept tool, described above.

2. Run the newly instrumented application like you would run the application. 
   For example:
   ```
      mpirun -np <N> ./<YourApplication>.jbbinst --input1 -i < input.txt
   ```
   This will generate a file for each mpi rank with the pattern
   `<YourApplication>.r*.t*.jbbinst`.

3. Use PEBIL's built-in script to select blocks that are executed at least
   `<M>` times:
   ```
      getImportantBlocks.py [--blockmin <M>] <YourApplication>.r*.t*.jbbinst
   ```
   This will generate a file called `<YourApplication>.<YourApplication.t*.lbb`
4. Instrument with ArielIntercept (described above) and pass the option
   `--inp <YourApplication>.<YourApplication.t*.lbb`

#### Source Code Modifications

The EPA frontend will observe the `ariel_enable` and `ariel_disable` functions 
in source code and turn instrumentation on/off accordingly. See the SST 
documentation for more information on this.

#### Sampling the Address Stream

Collecting and simulating every single address in the address stream can take 
a long time. PEBIL offers some runtime sampling options to help manage this.

To sample the address stream, decide how many addresses you want to collect at 
a time (C) and how many you would like to skip at a time (S). Then set these 
values in your SST script with the following environment variables:
  ```
      METASIM_SAMPLE_ON=C
      METASIM_SAMPLE_OFF=S
  ```
where C and S are positive integers.

By *default*, these values are set to a 10% sampling rate, collecting one
million addresses and then skipping 10 million addresses:
  ```
      METASIM_SAMPLE_ON=1000000
      METASIM_SAMPLE_OFF=10000000
  ```

To turn sampling **off** (i.e. use a sampling rate of 100%):
  ```
      METASIM_SAMPLE_OFF=0
  ```

We recommend selecting large numbers for C and S (at least in the millions) 
so that SST can get a good view of the shape of the address stream. 
Additionally, PEBIL cannot turn sampling on/off after the exact number of 
addresses (but it will be close). Using large numbers will ensure that you 
collect what you are expecting to collect.

#### Shutting off Collection

Another option to help manage simulation overhead is to use collection 
shutoff. Once a memory operation has been simulated some maximum number of 
times (M), PEBIL will turn off address stream collection for that memory 
operation. This happens at the block granularity (i.e. PEBIL will turn off 
memory operations that always get executed together). Other memory operations 
that have not been executed M times will continue to send addresses to SST.
  ```
      METASIM_SAMPLE_MAX=M
  ```

This option is best used for applications with timesteps where the shape of 
the address stream is similar in each timestep. When M is set to a very low 
number (like 100), this can be a very useful tool for making sure the 
instrumented binary works as expected and your SST script is set up correctly.

