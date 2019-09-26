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


// stuff in this file can be shared with both sides of any tool
#ifndef _Metasim_hpp_
#define _Metasim_hpp_

#include <iostream>
#include <set>

#ifndef debug(...)
//#define debug(...) __VA_ARGS__
#define debug(...)
#endif

typedef uint64_t image_key_t;
typedef pthread_t thread_key_t;

typedef enum {
    CounterType_undefined = 0,
    CounterType_instruction,
    CounterType_basicblock,
    CounterType_loop,
    CounterType_function,
    CounterType_total
} CounterTypes;

static const char* CounterTypeNames[CounterType_total] = {
    "undefined",
    "instruction",
    "basicblock",
    "loop"
    "function"
};

typedef enum {
    PointType_undefined = 0,
    PointType_blockcount,
    PointType_buffercheck,
    PointType_bufferinc,
    PointType_bufferfill,
    PointType_functionEntry,
    PointType_functionExit,
    PointType_total
} PointTypes;

#define DYNAMIC_POINT_SIZE_LIMIT 128
typedef struct DynamicInst_s {
    uint64_t VirtualAddress;
    uint64_t ProgramAddress;
    uint64_t Key;
    uint64_t Flags;
    uint32_t Size;
    uint8_t  OppContent[DYNAMIC_POINT_SIZE_LIMIT];
    bool IsEnabled;
} DynamicInst;

#define GENERATE_KEY(__bid, __typ) ((__typ & 0xf) | (__bid << 4))
#define GET_BLOCKID(__key) ((__key >> 4))
#define GET_TYPE(__key) ((__key & 0xf))

#endif //_Metasim_hpp_

