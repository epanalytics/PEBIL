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

#ifndef _ThreadedCommon_hpp_
#define _ThreadedCommon_hpp_

#include <set>
#include <signal.h>

// thread handling
extern "C" {
    void SuspendHandler(int signum);
    void InitializeSuspendHandler(); 
    void SuspendAllThreads(uint32_t size, std::set<thread_key_t>::iterator b, 
      std::set<thread_key_t>::iterator e);
    void ResumeAllThreads();

    typedef struct {
        void* args;
        void* (*fcn)(void*);
    } thread_passthrough_args;

    void* thread_started(void* args);
    int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
        void *(*start_routine) (void*), void *arg);
    int pthread_join(pthread_t thread, void **value_ptr);

    // Debugging signal handlers
    static void illegal_instruction_handler(int signo, siginfo_t* siginf, void*
      context);
    void print_backtrace();
    static void segfault_handler(int signo, siginfo_t* siginf, void* context);
    void init_signal_handlers();
};

#endif //_ThreadedCommon_hpp_

