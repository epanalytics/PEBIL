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

#ifndef _Debug_h_
#define _Debug_h_

#include <iostream>

// debugging macros -- these can produce copious amounts of output
#define WARNING_SEVERITY 7

//#define DEVELOPMENT
//#define DEBUG_MEMTRACK
//#define DEBUG_OPERAND
//#define DEBUG_OPTARGET
//#define DEBUG_OPCODE
//#define DEBUG_HASH
//#define DEBUG_NOTE
//#define DEBUG_LINEINFO
//#define DEBUG_BASICBLOCK
//#define DEBUG_HASHCODE
//#define DEBUG_CFG
//#define DEBUG_LOOP
//#define DEBUG_INST
//#define DEBUG_ANCHOR
//#define DEBUG_FUNC_RELOC
//#define DEBUG_JUMP_TABLE
//#define DEBUG_POINT_CHAIN
//#define DEBUG_LEAF_OPT
//#define DEBUG_DATA_PLACEMENT
//#define DEBUG_ADDR_ALIGN
//#define DEBUG_BLOAT_FILTER
//#define DEBUG_LOADADDR
//#define DEBUG_LIVE_REGS

// some common macros to help debug instrumentation
//#define RELOC_MOD_OFF 0
//#define RELOC_MOD 2
//#define TURNOFF_FUNCTION_RELOCATION
//#define BLOAT_MOD_OFF 0
//#define BLOAT_MOD     2
//#define TURNOFF_FUNCTION_BLOAT
//#define SWAP_MOD_OFF 0
//#define SWAP_MOD     2
#define SWAP_VERBOSE
//#define SWAP_FUNCTION_ONLY "raise"
//#define TURNOFF_INSTRUCTION_SWAP
#define ANCHOR_SEARCH_BINARY
//#define PRINT_INSTRUCTION_DETAIL 
//#define VALIDATE_ANCHOR_SEARCH
//#define FILL_RELOCATED_WITH_INTERRUPTS
//#define JUMPTABLE_USE_REGISTER_OPS
//#define THREAD_SAFE
//#define NO_REG_ANALYSIS
#define PROTECT_RAW_SNIPPETS
#define OPTIMIZE_NONLEAF
#define INSTRUCTION_PRINT_SIZE (64)

#ifdef DEBUG_MEMTRACK
#include <MemTrack.h>
#define PRINT_DEBUG_MEMTRACK(...) fprintf(stdout,"MEMTRACK : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define PRINT_MEMTRACK_STATS(...) \
    PRINT_DEBUG_MEMTRACK("-----------------------------------------------------------"); \
    PRINT_DEBUG_MEMTRACK("Memory Stats @ line %d in file %s in function %s", ## __VA_ARGS__); \
    MemTrack::TrackListMemoryUsage((double)1.00); \
    PRINT_DEBUG_MEMTRACK("-----------------------------------------------------------");
#define DEBUG_MEMTRACK(...) __VA_ARGS__
#else
#define PRINT_DEBUG_MEMTRACK(...)
#define PRINT_MEMTRACK_STATS(...)
#define DEBUG_MEMTRACK(...)
#endif

#ifdef DEBUG_OPCODE
#define PRINT_DEBUG_OPCODE(...) fprintf(stdout,"OPCODE : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_OPCODE(...)
#endif

#ifdef DEBUG_OPERAND
#define PRINT_DEBUG_OPERAND(...) fprintf(stdout,"OPERAND : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_OPERAND(...)
#endif

#ifdef DEBUG_OPTARGET
#define PRINT_DEBUG_OPTARGET(...) fprintf(stdout,"OPTARGET : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_OPTARGET(...)
#endif

#ifdef DEBUG_HASH
#define PRINT_DEBUG_HASH(...) fprintf(stdout,"HASH : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_HASH(...) __VA_ARGS__
#else
#define PRINT_DEBUG_HASH(...)
#define DEBUG_HASH(...)
#endif

#ifdef DEBUG_NOTE
#define PRINT_DEBUG_NOTE(...) fprintf(stdout,"NOTE : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_NOTE(...) __VA_ARGS__
#else
#define PRINT_DEBUG_NOTE(...)
#define DEBUG_NOTE(...)
#endif

#ifdef DEBUG_LINEINFO
#define PRINT_DEBUG_LINEINFO(...) fprintf(stdout,"LINEINFO : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_LINEINFO(...) __VA_ARGS__
#else
#define PRINT_DEBUG_LINEINFO(...)
#define DEBUG_LINEINFO(...)
#endif

#ifdef DEBUG_BASICBLOCK
#define PRINT_DEBUG_BASICBLOCK(...) fprintf(stdout,"BASICBLOCK : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_BASICBLOCK(...)
#endif

#ifdef DEBUG_HASHCODE
#define PRINT_DEBUG_HASHCODE(...) fprintf(stdout,"HASHCODE : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_HASHCODE(...) __VA_ARGS__
#else
#define PRINT_DEBUG_HASHCODE(...)
#define DEBUG_HASHCODE(...)
#endif

#ifdef DEBUG_CFG
#define PRINT_DEBUG_CFG(...) fprintf(stdout,"CFG : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_CFG(...) __VA_ARGS__
#else
#define PRINT_DEBUG_CFG(...)
#define DEBUG_CFG(...)
#endif

#ifdef DEBUG_LOOP
#define PRINT_DEBUG_LOOP(...) fprintf(stdout,"LOOP : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_LOOP(...) __VA_ARGS__
#else
#define PRINT_DEBUG_LOOP(...)
#define DEBUG_LOOP(...)
#endif

#ifdef DEBUG_INST
#define PRINT_DEBUG_INST(...) fprintf(stdout,"INST : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_INST(...) __VA_ARGS__
#else
#define PRINT_DEBUG_INST(...)
#define DEBUG_INST(...)
#endif

#ifdef DEBUG_ANCHOR
#define PRINT_DEBUG_ANCHOR(...) fprintf(stdout,"ANCHOR : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_ANCHOR(...) __VA_ARGS__
#else
#define PRINT_DEBUG_ANCHOR(...)
#define DEBUG_ANCHOR(...)
#endif

#ifdef DEBUG_FUNC_RELOC
#define PRINT_DEBUG_FUNC_RELOC(...) fprintf(stdout,"FUNC_RELOC : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_FUNC_RELOC(...) __VA_ARGS__
#else
#define PRINT_DEBUG_FUNC_RELOC(...)
#define DEBUG_FUNC_RELOC(...)
#endif

#ifdef DEBUG_JUMP_TABLE
#define PRINT_DEBUG_JUMP_TABLE(...) fprintf(stdout,"JUMP_TABLE : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_JUMP_TABLE(...)
#endif

#ifdef DEBUG_POINT_CHAIN
#define PRINT_DEBUG_POINT_CHAIN(...) fprintf(stdout,"POINT_CHAIN : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_POINT_CHAIN(...)
#endif

#ifdef DEBUG_LEAF_OPT
#define PRINT_DEBUG_LEAF_OPT(...) fprintf(stdout,"LEAF_OPT : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_LEAF_OPT(...)
#endif

#ifdef DEBUG_DATA_PLACEMENT
#define PRINT_DEBUG_DATA_PLACEMENT(...) fprintf(stdout,"DATA_PLACEMENT : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_DATA_PLACEMENT(...)
#endif

#ifdef DEBUG_ADDR_ALIGN
#define PRINT_DEBUG_ADDR_ALIGN(...) fprintf(stdout,"ADDR_ALIGN : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#else
#define PRINT_DEBUG_ADDR_ALIGN(...)
#endif

#ifdef DEBUG_BLOAT_FILTER
#define PRINT_DEBUG_BLOAT_FILTER(...) fprintf(stdout,"BLOAT_FILTER : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_BLOAT_FILTER(...) __VA_ARGS__
#else
#define PRINT_DEBUG_BLOAT_FILTER(...)
#define DEBUG_BLOAT_FILTER(...)
#endif


#ifdef DEBUG_LOADADDR
#define PRINT_DEBUG_LOADADDR(...) fprintf(stdout,"LOADADDR : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define DEBUG_LOADADDR(...) __VA_ARGS__
#else
#define PRINT_DEBUG_LOADADDR(...)
#define DEBUG_LOADADDR(...)
#endif

#define PRINT_REG_LIST_BASIS(__list, __elts, __i)         \
    PRINT_INFO(); \
    PRINT_OUT("instruction %d %s list: ", __i, #__list);      \
    for (uint32_t __j = 0; __j < __elts; __j++){\
    if (__list[__i].containsRegister(__j)){\
    PRINT_OUT("reg:%d ", __j);\
    }\
    }\
    PRINT_OUT("\n");

#ifdef DEBUG_LIVE_REGS
#define PRINT_DEBUG_LIVE_REGS(...) fprintf(stdout,"LIVE_REGS : "); \
    fprintf(stdout,## __VA_ARGS__); \
    fprintf(stdout,"\n"); \
    fflush(stdout);
#define PRINT_REG_LIST_R PRINT_REG_LIST_BASIS
#define PRINT_REG_LIST PRINT_REG_LIST_BASIS
#define DEBUG_LIVE_REGS(...) __VA_ARGS__
#else
#define PRINT_DEBUG_LIVE_REGS(...)
#define DEBUG_LIVE_REGS(...)
#define PRINT_REG_LIST(...)
#define PRINT_REG_LIST_R PRINT_REG_LIST_BASIS
#endif

#define BACKTRACE_SIZE 32
static void* _backtraceArray[BACKTRACE_SIZE];
static size_t _backtraceSize;
static char** _backtraceStrings;
static int _arrayBacktraceIterator;

#define ASSERT(__str) \
    if (!(__str)){ _backtraceSize = backtrace(_backtraceArray, BACKTRACE_SIZE); _backtraceStrings = backtrace_symbols(_backtraceArray, _backtraceSize); \
        fprintf(stderr, "assert fail at line %d in file %s, function %s\n", __LINE__, __FILE__,__FUNCTION__); \
        for (_arrayBacktraceIterator = 0; _arrayBacktraceIterator < _backtraceSize; _arrayBacktraceIterator++){ fprintf(stderr, "\t%s\n", _backtraceStrings[_arrayBacktraceIterator]); } \
        free(_backtraceStrings);\
        assert(__str); }
//#define ASSERT(__str)

#ifdef  DEVELOPMENT
#define PRINT_DEBUG(...) fprintf(stdout,"----------- DEBUG : "); \
                         fprintf(stdout,## __VA_ARGS__); \
                         fprintf(stdout,"\n"); \
                         fflush(stdout);
#define DEBUG(...) __VA_ARGS__
#define DEBUG_MORE(...)
#define TIMER(...) __VA_ARGS__
#define INNER_TIMER(...) __VA_ARGS__
#else //DEVELOPMENT
#define PRINT_DEBUG(...)
#define DEBUG(...)
#define DEBUG_MORE(...)
#define TIMER(...) __VA_ARGS__
#define INNER_TIMER(...) 
#endif // DEVELOPMENT

#endif // _Debug_h_
