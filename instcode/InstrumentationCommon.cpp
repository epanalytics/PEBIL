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

//#ifndef _InstrumentationCommon_hpp_
//#define _InstrumentationCommon_hpp_

#ifdef HAVE_MPI
#include <mpi.h>
#endif

#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include <Metasim.hpp>
#include <InstrumentationCommon.hpp>

using namespace std;

int GetTaskId(){
    return __taskid;
}
int GetNTasks(){
    return __ntasks;
}
// a timer
void ptimer(double *tmr) {
    struct timeval timestr;
    void *tzp=0;

    gettimeofday(&timestr, (struct timezone*)tzp);
    *tmr=(double)timestr.tv_sec + 1.0E-06*(double)timestr.tv_usec;
}

void TryOpen(ofstream& f, const char* name) {
    f.open(name);
    f.setf(ios::showbase);
    if (f.fail()){
        ErrorExit("cannot open output file: " << name, MetasimError_FileOp);
    }
}

// some help geting task/process information into strings
void AppendPidString(string& str){
    char buf[6];
    sprintf(buf, "%05d", getpid());
    buf[5] = '\0';

    str.append(buf);
}

void AppendRankString(string& str){
    char buf[9];
    sprintf(buf, "%08d", GetTaskId());
    buf[8] = '\0';

    str.append(buf);
}

void AppendTasksString(string& str){
    char buf[9];
    sprintf(buf, "%08d", GetNTasks());
    buf[8] = '\0';

    str.append(buf);
}

// support for MPI wrapping
static bool MpiValid = false;
static bool IsMpiValid() { return MpiValid; }

extern "C" {
// C init wrapper
#ifdef USES_PSINSTRACER
int __give_pebil_name(MPI_Init)(int* argc, char*** argv){
    int retval = 0;
#else
int __wrapper_name(MPI_Init)(int* argc, char*** argv){

#ifdef HAVE_MPI
    int retval = PMPI_Init(argc, argv);
#else
    int retval = 0;
#endif
#endif // USES_PSINSTRACER

#ifdef HAVE_MPI
    PMPI_Comm_rank(MPI_COMM_WORLD, &__taskid);
    PMPI_Comm_size(MPI_COMM_WORLD, &__ntasks);

    MpiValid = true;
#endif

    //fprintf(stdout, "-[p%d]- Mapping pid to taskid %d/%d in MPI_Init wrapper\n", getpid(), __taskid, __ntasks);
    tool_mpi_init();

    return retval;
}

#ifdef USES_PSINSTRACER
void __give_pebil_name(mpi_init_)(int* ierr){
#else
void __wrapper_name(mpi_init_)(int* ierr){
  //fprintf(stderr, "PEBIL calling pmpi_init\n");
#ifdef HAVE_MPI
    pmpi_init_(ierr);
#endif
#endif // USES_PSINSTRACER
    //fprintf(stderr, "PEBIL called pmpi_init\n");

#ifdef HAVE_MPI
    PMPI_Comm_rank(MPI_COMM_WORLD, &__taskid);
    PMPI_Comm_size(MPI_COMM_WORLD, &__ntasks);

    MpiValid = true;
#endif

    //fprintf(stdout, "-[p%d]- Mapping pid to taskid %d/%d in mpi_init_ wrapper\n", getpid(), __taskid, __ntasks);
    tool_mpi_init();
}
//
// C init wrapper
#ifdef USES_PSINSTRACER
int __give_pebil_name(MPI_Init_thread)(int* argc, char*** argv, int required, int* provided){
    int retval = 0;
#else
int __wrapper_name(MPI_Init_thread)(int* argc, char*** argv, int required, int* provided){

#ifdef HAVE_MPI
    int retval = PMPI_Init_thread(argc, argv, required, provided);
#else
    int retval = 0;
#endif
#endif // USES_PSINSTRACER

#ifdef HAVE_MPI
    PMPI_Comm_rank(MPI_COMM_WORLD, &__taskid);
    PMPI_Comm_size(MPI_COMM_WORLD, &__ntasks);

    MpiValid = true;
#endif

    //fprintf(stdout, "-[p%d]- Mapping pid to taskid %d/%d in MPI_Init wrapper\n", getpid(), __taskid, __ntasks);
    tool_mpi_init();

    return retval;
}

#ifdef USES_PSINSTRACER
void __give_pebil_name(mpi_init_thread_)(int* required, int* provided, int* ierr){
#else
void __wrapper_name(mpi_init_thread_)(int* required, int* provided, int* ierr){
#ifdef HAVE_MPI
    pmpi_init_thread_(required, provided, ierr);
#endif
#endif // USES_PSINSTRACER

#ifdef HAVE_MPI
    PMPI_Comm_rank(MPI_COMM_WORLD, &__taskid);
    PMPI_Comm_size(MPI_COMM_WORLD, &__ntasks);

    MpiValid = true;
#endif

    //fprintf(stdout, "-[p%d]- Mapping pid to taskid %d/%d in mpi_init_ wrapper\n", getpid(), __taskid, __ntasks);
    tool_mpi_init();
}
}; // END extern C
