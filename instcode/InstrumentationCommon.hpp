/* 
 * This file is part of the pebil project.
 * 
 * Copyright (c) 2010, University of California Regents
 * All rights reserved.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _InstrumentationCommon_hpp_
#define _InstrumentationCommon_hpp_
#include <stdint.h>
#include <pthread.h>
#include <iostream>
#include <fstream>

#ifdef HAVE_UNORDERED_MAP
#include <tr1/unordered_map>
#define pebil_map_type std::tr1::unordered_map
#else
#include <map>
#define pebil_map_type std::map
#endif

#define ENV_OUTPUT_PREFIX "PEBIL_OUTPUT_PREFIX"
#define PROCESS getpid() << "/" << getppid()
#define THREAD pthread_self()

typedef struct DynamicInst_s DynamicInst;
typedef uint64_t image_key_t;
typedef pthread_t thread_key_t;

// thread id support
typedef struct {
    uint64_t id;
    uint64_t data;
} ThreadData;

// handling of different initialization/finalization events
// analysis libraries define these differently
extern "C" {
    extern void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool* 
      isThreadedModeFlag);

    extern void* tool_mpi_init();

    // Entry function when a thread is created by pthread_create
    // However, there may already be threads in existence if this library was loaded late
    extern void* tool_thread_init(pthread_t args);

    // Called just after a thread is joined
    extern void* tool_thread_fini(pthread_t args);

    // Placed at entry points to image
    // In an executable, this is the entry block for the program
    // In a shared library, this is every function
    // These points are killed after this function is called
    extern void* tool_image_init(void* s, image_key_t* key, ThreadData* td);

    // Called when the image is unloaded
    extern void* tool_image_fini(image_key_t* key);
};

// some function re-naming support
#define __give_pebil_name(__fname) \
    __fname ## _pebil_wrapper

#ifdef PRELOAD_WRAPPERS
#define __wrapper_name(__fname) \
    __fname
#else // PRELOAD_WRAPPERS
#define __wrapper_name(__fname) \
    __give_pebil_name(__fname)
#endif // PRELOAD_WRAPPERS

// handle rank/process identification with/without MPI
static int taskid;
#ifdef HAVE_MPI
#define __taskid taskid
#define __ntasks ntasks
static int __ntasks = 1;
#else //HAVE_MPI
#define __taskid getpid()
#define __ntasks 1
#endif //HAVE_MPI

int GetTaskId();
int GetNTasks();

// a timer
void ptimer(double *tmr); 

// support for output/warnings/errors
#define METASIM_ID "Metasim"
#define METASIM_VERSION "3.0.0"
#define METASIM_ENV "PEBIL_ROOT"

#define TAB "\t"
#define ENDL "\n"
#define DISPLAY_ERROR std::cerr << "[" << METASIM_ID << "-r" << GetTaskId() << "] " << "Error: "
#define warn std::cerr << "[" << METASIM_ID << "-r" << GetTaskId() << "] " << "Warning: "
#define ErrorExit(__msg, __errno) DISPLAY_ERROR << __msg << std::endl << std::flush; exit(__errno);
#define inform std::cout << "[" << METASIM_ID << "-r" << std::dec << GetTaskId() << "] "
#define SAVE_STREAM_FLAGS(__s) std::ios_base::fmtflags ff ## __s = __s.flags()
#define RESTORE_STREAM_FLAGS(__s) __s.flags(ff ## __s)


enum MetasimErrors {
    MetasimError_None = 0,
    MetasimError_MemoryAlloc,
    MetasimError_NoThread,
    MetasimError_TooManyInsnReads,
    MetasimError_StringParse,
    MetasimError_FileOp,
    MetasimError_Env,
    MetasimError_NoImage,
    MetaSimError_ExternalLib,
    MetasimError_Total,
};

void TryOpen(std::ofstream& f, const char* name);

// some help geting task/process information into strings
void AppendPidString(std::string& str); 
void AppendRankString(std::string& str); 
void AppendTasksString(std::string& str);

// support for MPI wrapping
//static bool MpiValid; // = false;
static bool IsMpiValid(); // { return MpiValid; }

extern "C" {
// C init wrapper
#ifdef USES_PSINSTRACER
int __give_pebil_name(MPI_Init)(int* argc, char*** argv);
#else
int __wrapper_name(MPI_Init)(int* argc, char*** argv);
#endif // USES_PSINSTRACER

#ifdef HAVE_MPI
extern void pmpi_init_(int*);
#endif

#ifdef USES_PSINSTRACER
void __give_pebil_name(mpi_init_)(int* ierr);
#else
void __wrapper_name(mpi_init_)(int* ierr);
#endif // USES_PSINSTRACER

// C init wrapper
#ifdef USES_PSINSTRACER
int __give_pebil_name(MPI_Init_thread)(int* argc, char*** argv, int required, 
  int* provided);
#else
int __wrapper_name(MPI_Init_thread)(int* argc, char*** argv, int required, int*
  provided);
#endif // USES_PSINSTRACER

#ifdef HAVE_MPI
extern void pmpi_init_thread_(int*, int*, int*);
#endif

#ifdef USES_PSINSTRACER
void __give_pebil_name(mpi_init_thread_)(int* required, int* provided, int* 
  ierr);
#else
void __wrapper_name(mpi_init_thread_)(int* required, int* provided, int* ierr);
#endif // USES_PSINSTRACER
}; // END extern C

#endif //_InstrumentationCommon_hpp_

