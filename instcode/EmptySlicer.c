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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef VERBOSE_SLICER
pthread_t pebil_slicer_thread_id = 0;
bool pebil_slicer_recursion_check = false;
time_t pebil_slicer_start_time = 0;

void pebil_slicer_verbose_start(const char* toolName) {
    time_t startTime = time(NULL);
    fprintf(stdout, "In epa_pebil_start for %s - %s", toolName, 
      ctime(&startTime));
    pebil_slicer_start_time = startTime;
    pthread_t thisThread = pthread_self();
    if (!pebil_slicer_thread_id)
        pebil_slicer_thread_id = thisThread;
    if (pebil_slicer_thread_id != thisThread)
        fprintf(stdout, "WARNING: Multiple threads are calling "
          "epa_pebil_start: %#llx, %#llx\n", pebil_slicer_thread_id, 
          thisThread);
    if (pebil_slicer_recursion_check)
        fprintf(stdout, "WARNING: epa_pebil_start is called before "
          "being paused\n");
    pebil_slicer_recursion_check = true;
    return;
}

void pebil_slicer_verbose_pause(const char* toolName) {
    time_t endTime = time(NULL);
    time_t elapsedTime = 0;
    if (pebil_slicer_start_time)
        elapsedTime = endTime - pebil_slicer_start_time;
    pebil_slicer_start_time = 0;
    fprintf(stdout, "In epa_pebil_pause for %s (%llus) - %s", toolName, 
      elapsedTime, ctime(&endTime));
    pthread_t thisThread = pthread_self();
    if (!pebil_slicer_thread_id)
        pebil_slicer_thread_id = thisThread;
    if (pebil_slicer_thread_id != thisThread)
        fprintf(stdout, "WARNING: Multiple threads are calling "
          "epa_pebil_pause: %#llx, %#llx\n", pebil_slicer_thread_id, 
          thisThread);
    if (!pebil_slicer_recursion_check)
        fprintf(stdout, "WARNING: epa_pebil_pause is called before "
          "being started\n");
    pebil_slicer_recursion_check = false;
}
#endif

void epa_pebil_start() {
#ifdef VERBOSE_SLICER
    pebil_slicer_verbose_start("NO TOOL");
#endif
    return;
}

void epa_pebil_start_() { epa_pebil_start(); return; }

void epa_pebil_pause() {
#ifdef VERBOSE_SLICER
    pebil_slicer_verbose_pause("NO TOOL");
#endif        
    return;
}

void epa_pebil_pause_() { epa_pebil_pause(); return; }
