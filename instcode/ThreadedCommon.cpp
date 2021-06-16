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

#define _GNU_SOURCE
#include <dlfcn.h>

#ifdef HAVE_MPI
#include <mpi.h>
#endif
#include <InstrumentationCommon.hpp>
#include <ThreadedCommon.hpp>
#include <Metasim.hpp>
#include <assert.h>
#include <execinfo.h>
#include <string.h>

using namespace std;

// thread handling
extern "C" {
    const int SuspendSignal = SIGUSR2;
    uint32_t CountSuspended = 0;
    pthread_mutex_t countlock;
    pthread_mutex_t leader;
    pthread_mutex_t pauser;
    bool CanSuspend = false;

    void SuspendHandler(int signum){
        // increment pause counter
        pthread_mutex_lock(&countlock);
        CountSuspended++;
        pthread_mutex_unlock(&countlock);

        // the thread doing the pausing will lock this prior to asking for the 
        // pause, therefore every other thread that hits this will wait on the 
        // the thread asking for the pause
        pthread_mutex_lock(&pauser);
        pthread_mutex_unlock(&pauser);

        // decrement pause counter
        pthread_mutex_lock(&countlock);
        CountSuspended--;
        pthread_mutex_unlock(&countlock);

    }

    void InitializeSuspendHandler(){
        if (CanSuspend){
            return;
        }
        debug(inform << "Thread " << hex << pthread_self() << 
          " initializing Suspension handling" << ENDL);

        CountSuspended = 0;
        pthread_mutex_init(&pauser, NULL);
        pthread_mutex_init(&leader, NULL);
        pthread_mutex_init(&countlock, NULL);

        CanSuspend = true;

        struct sigaction NewAction, OldAction;
        NewAction.sa_handler = SuspendHandler;
        sigemptyset(&NewAction.sa_mask);
        NewAction.sa_flags = 0;
     
        sigaction(SuspendSignal, NULL, &OldAction);
        sigaction(SuspendSignal, &NewAction, NULL);
    }

    void SuspendAllThreads(uint32_t size, set<thread_key_t>::iterator b, 
      set<thread_key_t>::iterator e){
        if (!CanSuspend){
            return;
        }

        pthread_mutex_lock(&leader);
        while (CountSuspended > 0){
            pthread_yield();
        }
        assert(CountSuspended == 0);
        pthread_mutex_lock(&pauser);

        for (set<thread_key_t>::iterator tit = b; tit != e; tit++){
            if ((*tit) != pthread_self()){
                pthread_kill((*tit), SuspendSignal);
            }
        }

        // wait for all other threads to reach paused state
        uint32_t ksize = size - 1;
        while (CountSuspended < ksize){
            pthread_yield();
        }
        assert(CountSuspended == ksize);
    }

    void ResumeAllThreads(){
        if (!CanSuspend){
            return;
        }

        pthread_mutex_unlock(&pauser);

        // wait for all other threads to exit paused state
        while (CountSuspended > 0){
            pthread_yield();
        }
        assert(CountSuspended == 0);
        pthread_mutex_unlock(&leader);
    }

    void* thread_started(void* args){
        thread_passthrough_args* pt_args = (thread_passthrough_args*)args;
        tool_thread_init(pthread_self());
        
        return pt_args->fcn(pt_args->args);
    }

    int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
        void *(*start_routine) (void*), void *arg) __THROWNL {

        static int (*pthread_create_ptr)(pthread_t *thread, const 
          pthread_attr_t *attr, void *(*start_routine)(void*), void*arg)
          = (int (*)(pthread_t *thread, const pthread_attr_t* attr, 
          void *(*start_routine)(void*), void*))dlsym(RTLD_NEXT, 
          "pthread_create");

        // TODO: keep this somewhere and destroy it. it currently is a mem leak
        thread_passthrough_args* pt_args = (thread_passthrough_args*)malloc(
          sizeof(thread_passthrough_args));
        pt_args->fcn = start_routine;
        pt_args->args = arg;

        return pthread_create_ptr(thread, attr, thread_started, pt_args);
    }

    int pthread_join(pthread_t thread, void **value_ptr){
        pthread_t jthread = thread;

        int (*join_ptr)(pthread_t, void**) = (int (*)(pthread_t, void**))dlsym(
          RTLD_NEXT, "pthread_join");
        int ret = join_ptr(thread, value_ptr);

        tool_thread_fini(jthread);
        return ret;
    }


    // Debugging signal handlers
    static void illegal_instruction_handler(int signo, siginfo_t* siginf, void*
      context) {
        char err[8] = "deadbee";
        switch(siginf->si_code){
            case ILL_ILLOPC:
                strcpy(err, "OPC"); break;
            case ILL_ILLOPN:
                strcpy(err, "OPN"); break;
            case ILL_ILLADR:
                strcpy(err, "ADR"); break;
            case ILL_ILLTRP:
                strcpy(err, "TRP"); break;
            case ILL_PRVOPC:
                strcpy(err, "PRVOPC"); break;
            case ILL_PRVREG:
                strcpy(err, "PRVREG"); break;
            case ILL_COPROC:
                strcpy(err, "COPROC"); break;
            case ILL_BADSTK:
                strcpy(err, "BADTSK"); break;
        }
        fprintf(stderr, "Recieved signal %d SIGILL? with code %s, %d at " 
          "address 0x%llx\n", signo, err, siginf->si_code, siginf->si_addr);
        char* ops = (char*)siginf->si_addr;
        fprintf(stderr, "%hhx %hhx %hhx %hhx\n", ops[0], ops[1], ops[2], 
          ops[3]);
        exit(1);
    }

    void print_backtrace() {
        int BT_SIZE = 10;

        void* bt[BT_SIZE];

        int n = backtrace(bt, BT_SIZE);
        for(int i = 0; i < n; ++i) {
            fprintf(stderr, "0x%llx\n", bt[i]);
        }

        char** symbols = backtrace_symbols(bt, n);
        for(int i = 0; i < n; ++i) {
            fprintf(stderr, "%s\n", symbols[i]);
        }
    }

    static void interrupt_handler(int signo, siginfo_t* siginf, void* context) {
        fprintf(stderr, "Thread %#llx Received signal %d SIGINT\n", 
          pthread_self(), signo);
        fprintf(stderr, "At address 0x%llx\n", siginf->si_addr);
        print_backtrace();
        exit(1);
    }
    
    static void segfault_handler(int signo, siginfo_t* siginf, void* context)
    {
        fprintf(stderr, "Received signal %d SIGSEGV\n", signo);
        fprintf(stderr, "At address 0x%llx\n", siginf->si_addr);

       /* Debug info for more complex back traces 
        fprintf(stderr, "ACC:\n");
        register int64_t* sp asm ("rsp");
        for(int i = 0; i < 512; ++i) {
            fprintf(stderr, "%d: 0x%llx\n", i, (*(sp + i)));
        }
        fprintf(stderr, "ACC end\n");
       */

        print_backtrace();

        char err[8] = "deadbee";
        switch(siginf->si_code){
            case SEGV_MAPERR: strcpy(err, "MAPERR"); break;
            case SEGV_ACCERR: strcpy(err, "ACCERR"); break;
        }
        fprintf(stderr, "Code %d: %s\n", siginf->si_code, err);

        exit(1);
        //char* ops = (char*)siginf->si_addr;
        //fprintf(stderr, "%hhx %hhx %hhx %hhx\n", ops[0], ops[1], ops[2], ops[3]);

    }
    
    // debug is false by default
    void init_signal_handlers(bool debug) {
    
        struct sigaction illAction;
        illAction.sa_sigaction = illegal_instruction_handler;
        illAction.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGILL, &illAction, NULL);
    
        struct sigaction segAction;
        segAction.sa_sigaction = segfault_handler;
        segAction.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGSEGV, &segAction, NULL);

        if (debug) {
            struct sigaction intAction;
            intAction.sa_sigaction = interrupt_handler;
            intAction.sa_flags = SA_SIGINFO | SA_NODEFER;
            sigaction(SIGINT, &intAction, NULL);
        }
    }
};
