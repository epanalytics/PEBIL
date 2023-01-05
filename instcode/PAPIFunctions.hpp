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

#ifndef _PAPIFunctions_hpp_
#define _PAPIFunctions_hpp_

#include <sys/socket.h>
#include <sys/un.h>
#include <string>

#define MAX_HWC 32

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

typedef long long values_t[MAX_HWC];

typedef struct PAPIStats_s {
    TimerStats timerStats;
    int events[MAX_HWC];
    values_t* tmpValues;
    values_t* accumValues;
    int num;
    int papiMeasurementsStarted;
    int currentlyMeasuring;
    int eventSet;
    int eventCode;
    std::set<int> activeFunctions;
} PAPIStats;

#endif
