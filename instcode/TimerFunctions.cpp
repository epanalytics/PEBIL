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

/*
 * Time spent in each code section
 *
 * file per rank
 * function: total
 *   - per thread time
 * Timer
 */

#include <InstrumentationCommon.hpp>
#include <DataManager.hpp>
#include <DynamicInstrumentation.hpp>
#include <Metasim.hpp>
#include <ThreadedCommon.hpp>
#include <TimerFunctions.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>

using namespace std;

DataManager<TimerStats*>* AllData = NULL;
DynamicInstrumentation* DynamicPoints = NULL;
static std::set<uint64_t> EntryExitKeys;

// by default, do not shut off timing instrumentation.
// please set FTIMER_SHUTOFF to something other than zero to enable
// timer shutoff.
static uint32_t shutoffTimers=0;
// by default, the timer tool allows 100 invocations of the code section
// and then averages the time per visit to determine whether to shut off
// timing measurement. please set FTIMER_ITERS to control the number of
// iterations.
static uint32_t shutoffIters=100;
// by default, the timer shuts of the timing for a code section if the per
// visit time is less than 5000 microseconds.
// please set FTIMER_THRESHOLD env variable to control the number of
// microseconds per visit.
static uint32_t timingThreshold=5000;
// By default, shut off code sections that are exited but not recorded as
// entered. Otherwise, this keeps track of # times this happens per thread
static uint32_t trackUnenteredSections=0;
static uint64_t timerCPUFreq=3200000000;
// Note that if the env variable is not defined, we default to what is defined
// here:
#define CLOCK_RATE_HZ 3200000000

inline uint64_t read_timestamp_counter(){
    unsigned low, high;
    __asm__ volatile ("rdtsc" : "=a" (low), "=d"(high));
    return ((unsigned long long)low | (((unsigned long long)high) << 32));
}

static double diffTime(struct timeval t1, struct timeval t2)
{
    struct timeval diff;
    if(t2.tv_usec < t1.tv_usec) {
            diff.tv_usec = 1000000 + t2.tv_usec - t1.tv_usec;
            diff.tv_sec = t2.tv_sec - t1.tv_sec - 1;
    } else {
            diff.tv_usec = t2.tv_usec - t1.tv_usec;
            diff.tv_sec = t2.tv_sec - t1.tv_sec;
    }

    double time = (double)diff.tv_sec + (diff.tv_usec / 1000000.0);
    return time;
}

/*
 * When a new image is added, called once per existing thread
 * When a new thread is added, called once per loaded image
 *
 * timers: some pre-existing data
 * typ: ThreadTyp when called via AddThread
 *      ImageTyp when called via AddImage
 * iid: image the new data will be for
 * tid: thread the new data will be for
 * firstimage: key of first image created
 * 
 */
TimerStats* GenerateTimerStats(TimerStats* timers, uint32_t typ, image_key_t iid, thread_key_t tid, image_key_t firstimage) {

    TimerStats* retval;
    retval = new TimerStats();

    retval->master = timers->master && typ == DataManagerType_Image;
    //retval->master = timers->master && typ == AllData->ImageType;
    retval->application = timers->application;
    retval->extension = timers->extension;
    retval->sectionCount = timers->sectionCount;
    retval->sectionNames = timers->sectionNames;
    retval->sectionHashes = timers->sectionHashes;
    retval->sectionTimerAccum = new uint64_t[retval->sectionCount];
    retval->sectionTimerLast = new uint64_t[retval->sectionCount];
    retval->inSection = new uint32_t[retval->sectionCount];
    retval->sectionEntryCounts = new uint64_t[retval->sectionCount];
    retval->sectionShutoff = new uint32_t[retval->sectionCount]; 
    retval->unenteredSections = new uint64_t[retval->sectionCount];
    retval->entryType = timers->entryType;
    retval->exitType = timers->exitType;

    memset(retval->sectionTimerAccum, 0, sizeof(*retval->sectionTimerAccum) *       retval->sectionCount);
    memset(retval->sectionTimerLast, 0, sizeof(*retval->sectionTimerLast) *         retval->sectionCount);
    memset(retval->inSection, 0, sizeof(*retval->inSection) * 
      retval->sectionCount);
    memset(retval->sectionEntryCounts, 0, sizeof(*retval->sectionEntryCounts)       * retval->sectionCount);
    memset(retval->sectionShutoff, 0, sizeof(*retval->sectionShutoff) * 
      retval->sectionCount);
    memset(retval->unenteredSections, 0, sizeof(*retval->unenteredSections) 
      * retval->sectionCount);

    retval->appTimeStart = timers->appTimeStart;
    retval->appTimeOfDayStart = timers->appTimeOfDayStart;

    // read in key environment variables
    if (!ReadEnvUint32("FTIMER_SHUTOFF", &shutoffTimers)){
        shutoffTimers = 0;
    }

    if (!ReadEnvUint32("FTIMER_TRACK_UNENTERED", &trackUnenteredSections)){
        trackUnenteredSections = 0;
    }


    // see if the FTIMER_CPU_FREQ env var is defined
    char * ftimeCPU = getenv("FTIMER_CPU_FREQ");
    if (ftimeCPU != NULL) {

        std::stringstream strStream;
        strStream << ftimeCPU;
        strStream >> timerCPUFreq;
        inform << "Got custom FTIMER_CPU_FREQ ***(in Hz)** from the user :: " 
          << timerCPUFreq << endl;
    } else {
        inform << "***Using the default CPU clock rate to calculate timings****"
          << CLOCK_RATE_HZ << endl;
        timerCPUFreq=CLOCK_RATE_HZ;
    }

    if(shutoffTimers) {
        if (!ReadEnvUint32("FTIMER_ITERS", &shutoffIters)){
            shutoffIters=100;
        }

        if (!ReadEnvUint32("FTIMER_THRESHOLD", &timingThreshold)){
            timingThreshold=5000;
        }

        //warn << "Dynamic Turning off of Function Timers is enabled." << ENDL;
        //warn << "Number of iterations to consider before averaging time per
        // visit: " << shutoffIters << ENDL;
        //warn << "Timer per visit threshold is at: " << timingThreshold
        //  << " micro-seconds. " << ENDL;

    }

    return retval;
}

void DeleteTimerStats(TimerStats* timers){
    delete timers->sectionTimerAccum;
    delete timers->sectionTimerLast;
    delete timers->inSection;
    delete timers->sectionEntryCounts;
    delete timers->sectionShutoff;
    delete timers->unenteredSections;
}

uint64_t ReferenceTimerStats(TimerStats* timers){
    return (uint64_t)timers;
}

extern "C"
{

    void pebil_slicer_verbose_start(const char*);
    void pebil_slicer_verbose_pause(const char*);
    void epa_pebil_start() {
#ifdef VERBOSE_SLICER
        pebil_slicer_verbose_start("FTMINST");
#endif
        DynamicPoints->SetDynamicPoints(EntryExitKeys, true);
        return;
    }

    void epa_pebil_start_() { epa_pebil_start(); return; }

    void epa_pebil_pause() {
#ifdef VERBOSE_SLICER
        pebil_slicer_verbose_pause("FTMINST");
#endif
        DynamicPoints->SetDynamicPoints(EntryExitKeys, false);
        return;
    }

    void epa_pebil_pause_() { epa_pebil_pause(); return; }

    // start timer
    int32_t section_entry(uint32_t sectionIndex, image_key_t* key) {
        thread_key_t tid = pthread_self();

        TimerStats* timers = AllData->GetData(*key, pthread_self());
        assert(timers != NULL);
        assert(timers->sectionTimerLast != NULL);

        if(timers->inSection[sectionIndex] == 0){
            timers->sectionEntryCounts[sectionIndex]++;
            timers->sectionTimerLast[sectionIndex] = read_timestamp_counter();
        }
        ++timers->inSection[sectionIndex];

        return 0;
    }

    // end timer
    int32_t section_exit(uint32_t sectionIndex, image_key_t* key) {
        thread_key_t tid = pthread_self();
        uint64_t last, now;
        static bool producedWarning = false;
        TimerStats* timers = AllData->GetData(*key, pthread_self());

        int32_t recDepth = timers->inSection[sectionIndex];
        // If exiting a section that was never "entered"
        if(recDepth == 0) {
            if(GetTaskId() == 0 && !producedWarning) {
                producedWarning = true;
                warn << "Leaving a never entered code section." << ENDL;
                if (trackUnenteredSections)
                    warn << "Check the unentered file at the end of this run "
                      "for the threads that left unentered sections." << ENDL;
                else
                    warn << "Check the unentered file at the end of this run "
                      "for a list of sections exited but never entered. " 
                      "These sections are being shut off! To prevent shutoff "
                      "and/or collect more details, set "
                      "FTIMER_TRACK_UNENTERED=1" << ENDL;
            }
            timers->inSection[sectionIndex] = 0;
            timers->unenteredSections[sectionIndex]++;
            // If we aren't tracking the unentered functions, shutoff the 
            // function timer for it
            if (!trackUnenteredSections) {
                uint64_t imageSeq = AllData->GetImageSequence(*key);
                AllData->WriteLock();
                uint64_t this_key = GENERATE_UNIQUE_KEY(sectionIndex, imageSeq,
                  PointType_functionExit);
                uint64_t corresponding_entry_key = GENERATE_UNIQUE_KEY(
                  sectionIndex, imageSeq, PointType_functionEntry);
                set<uint64_t> inits;
                inits.insert(this_key);
                inits.insert(corresponding_entry_key);
                DynamicPoints->SetDynamicPoints(inits, false); 
                timers->sectionShutoff[sectionIndex] = 1;
                AllData->UnLock();
            }
            return 0; 

        } else if(recDepth < 0) {
            if(GetTaskId() == 0) warn << "Negative call depth for " <<                        timers->sectionNames[sectionIndex] << ENDL;
            timers->inSection[sectionIndex] = 0;
            return 0;
        }

        --recDepth;
        if(recDepth == 0) {
            last = timers->sectionTimerLast[sectionIndex];
            now = read_timestamp_counter();
            timers->sectionTimerAccum[sectionIndex] += now - last;
            timers->sectionTimerLast[sectionIndex] = now;
        }
        timers->inSection[sectionIndex] = recDepth;

        if(shutoffTimers) {
            if (timers->sectionEntryCounts[sectionIndex] % shutoffIters == 0){
                // time per visit is total t
                double timeInFunction = timers->sectionTimerAccum[sectionIndex];
                double numVisits = (double)timers->sectionEntryCounts[
                  sectionIndex];
                double timePerVisit= timeInFunction / numVisits / timerCPUFreq;

                if(timePerVisit < (((double)timingThreshold)/1000000.0)) {
                    uint64_t imageSeq = AllData->GetImageSequence(*key);
                    AllData->WriteLock();
                    uint64_t this_key = GENERATE_UNIQUE_KEY(sectionIndex,
                      imageSeq, timers->exitType);
                    uint64_t corresponding_entry_key = GENERATE_UNIQUE_KEY(
                      sectionIndex, imageSeq, timers->entryType);

                    set<uint64_t> inits;
                    inits.insert(this_key);
                    inits.insert(corresponding_entry_key);
                    DynamicPoints->SetDynamicPoints(inits, false); 
                    timers->sectionShutoff[sectionIndex] = 1;
                    AllData->UnLock();
                }
            }
        }
        return 0;
    }

    // Just after MPI_Init is called
    void* tool_mpi_init() {
        return NULL;
    }

    void* tool_pre_mpi_fini() {
        return NULL;
    }

    void* tool_pre_mpi_init() {
        return NULL;
    }

    // Entry function for threads
    void* tool_thread_init(thread_key_t tid) {
        if (AllData){
            if(DynamicPoints->IsThreadedMode())
                AllData->AddThread(tid);
        } else {
            ErrorExit("Calling PEBIL thread initialization library for thread "
              << hex << tid << " but no images have been initialized.", 
              MetasimError_NoThread);
        }
        return NULL;
    }

    // Optionally? called on thread join/exit?
    void* tool_thread_fini(thread_key_t tid) {
        return NULL;
    }

    // Create mutex to ensure that Dynamics is initialized exactly once
    static pthread_mutex_t dynamic_init_mutex = PTHREAD_MUTEX_INITIALIZER;
    // initialize dynamic instrumentation
    void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool* 
      isThreadedModeFlag) {
        pthread_mutex_lock(&dynamic_init_mutex);
        if (DynamicPoints == NULL) {
            DynamicPoints = new DynamicInstrumentation();
        }
        DynamicPoints->InitializeDynamicInstrumentation(count, dyn,
          isThreadedModeFlag);
        pthread_mutex_unlock(&dynamic_init_mutex);
        return NULL;
    }

    // Create mutex to ensure that each image is initialized exactly once
    static pthread_mutex_t image_init_mutex = PTHREAD_MUTEX_INITIALIZER;
    // Called when new image is loaded
    void* tool_image_init(void* args, image_key_t* key, ThreadData* td) {
        pthread_mutex_lock(&image_init_mutex);
        TimerStats* timers = (TimerStats*)args;

        // If this is the first image, set up a data manager
        if (AllData == NULL){
            AllData = new DataManager<TimerStats*>(GenerateTimerStats, 
              DeleteTimerStats, ReferenceTimerStats);
        }

        // Check if added already
        if (AllData->allimages.count(*key) != 0) {
            pthread_mutex_unlock(&image_init_mutex);
            return NULL;
        }

        // image time
        timers->appTimeStart = read_timestamp_counter();
        gettimeofday(&timers->appTimeOfDayStart, NULL);

        // Add this image
        AllData->AddImage(timers, td, *key);

        // Remove this instrumentation
        // Must be done after the image is added, or threads may get to the 
        // instrumentation before the image is initialized
        set<uint64_t> inits;
        inits.insert(GENERATE_KEY(*key, PointType_inits));
        DynamicPoints->SetDynamicPoints(inits, false);

        // Get all func entry and func exit instrumentation points so that the 
        // user can turn them on/off
        std::set<uint64_t> keys;
        DynamicPoints->GetAllDynamicKeys(keys);
        assert(EntryExitKeys.empty());
        for (auto it = keys.begin(); it != keys.end(); it++) {
            uint64_t k = (*it);
            if (GET_TYPE(k) == PointType_functionEntry || 
              GET_TYPE(k) == PointType_functionExit) {
                EntryExitKeys.insert(k);
            }
        }

        // If EPA_SLICER_START_OFF is set, then turn inst off
        uint32_t startOff = 0;
        (void) ReadEnvUint32("EPA_SLICER_START_OFF", &startOff);
        if (startOff != 0)
            DynamicPoints->SetDynamicPoints(EntryExitKeys, false);

        pthread_mutex_unlock(&image_init_mutex);
        return NULL;
    }

    // 
    void* tool_image_fini(image_key_t* key) {

        image_key_t iid = *key;

        // Only print one file with data from all images
        static bool finalized = false;
        if (finalized)
            return NULL;

        finalized = true;

        if (DynamicPoints != NULL) {
            delete DynamicPoints;
        }

        if (AllData == NULL){
            ErrorExit("data manager does not exist. no images were intialized",
              MetasimError_NoImage);
            return NULL;
        }

        TimerStats* timers = AllData->GetData(iid, pthread_self());
        if (timers == NULL){
            ErrorExit("Cannot retrieve image data using key " << dec << (*key),
              MetasimError_NoImage);
            return NULL;
        }

        if (!timers->master){
            printf("Image is not master, skipping\n");
            return NULL;
        }


        uint64_t appTimeEnd = read_timestamp_counter();
        struct timeval tvEnd;
        gettimeofday(&tvEnd, NULL);

        // print times
        char outFileName[1024];
        sprintf(outFileName, "%s.meta_%0d.%s", timers->application, GetTaskId(),
          timers->extension);

        // print unentered functions
        char unenteredFileName[1024];
        sprintf(unenteredFileName, "%s.unentered_%0d.%s", timers->application, 
          GetTaskId(), timers->extension);

        FILE* outFile = fopen(outFileName, "w");
        if (!outFile){
            cerr << "error: cannot open output file %s" << outFileName << ENDL;
            exit(-1);
        }

        FILE* unOutFile = fopen(unenteredFileName, "w");
        if (!unOutFile){
            cerr << "error: cannot open output file %s" << unenteredFileName 
              << ENDL;
            exit(-1);
        }

        fprintf(outFile, "App timestamp time: %lld %lld %f\n",
          timers->appTimeStart, appTimeEnd,
          (double)(appTimeEnd - timers->appTimeStart) / timerCPUFreq);
        fprintf(outFile, "App timeofday time: %lld %lld %f\n",
          timers->appTimeOfDayStart.tv_sec, tvEnd.tv_sec,
          diffTime(timers->appTimeOfDayStart, tvEnd));

        // for each image
        //   for each function
        //     for each thread
        //       print time
        for (set<image_key_t>::iterator iit = AllData->allimages.begin();
          iit != AllData->allimages.end(); ++iit) {

            TimerStats* imageData = AllData->GetData(*iit, pthread_self());

            char** sectionNames = imageData->sectionNames;
            uint64_t sectionCount = imageData->sectionCount;

            for (uint64_t sectionIndex = 0; sectionIndex < sectionCount;
              ++sectionIndex) {
                char* fname;
                bool unentered = false;
                fname = sectionNames[sectionIndex];
                fprintf(outFile, "\n%s:\t", fname);
                if (trackUnenteredSections)
                    fprintf(unOutFile, "\n%s:\t", fname);

                for (set<thread_key_t>::iterator tit = 
                  AllData->allthreads.begin(); tit != 
                  AllData->allthreads.end(); ++tit) {

                    TimerStats* timers = AllData->GetData(*iit, *tit);

                    thread_key_t thread = AllData->GetThreadSequence(*tit);
                    double time = (double)(timers->sectionTimerAccum[
                      sectionIndex]) / timerCPUFreq;
                    uint64_t entries = timers->sectionEntryCounts[sectionIndex];
                    uint64_t funcHash = timers-> sectionHashes[sectionIndex];
                    uint64_t imgHash = AllData->GetImageSequence(*iit);
                    if(timers->sectionShutoff[sectionIndex]==1) {
                        fprintf(outFile, "\tThread: %d\tTime: %f\tEntries: "
                          "%lld\tHash: 0x%llx\tImage: %d*\t",
                          thread, time, entries, funcHash, imgHash);
                    } else {
                        fprintf(outFile, "\tThread: %d\tTime: %f\tEntries: "
                          "%lld\tHash: 0x%llx\tImage: %d\t",
                          thread, time, entries, funcHash, imgHash);
                    }
                    // If tracking unentered functions, then print each function
                    // and number of "warnings" per thread
                    if (trackUnenteredSections) {
                        fprintf(unOutFile, "\tThread: %d\tUnentered: "
                          "%lld\tHash: 0x%llx\tImage: %d\t",
                          AllData->GetThreadSequence(*tit), 
                          timers->unenteredSections[sectionIndex], timers->
                          sectionHashes[sectionIndex],
                          AllData->GetImageSequence(*iit));
                    }
                    if (timers->unenteredSections[sectionIndex])
                        unentered = true;
                }

                // If not tracking, just print list of unentered functions
                if (unentered && !trackUnenteredSections)
                    fprintf(unOutFile, "%s\n", fname);
            }
        }

        fflush(outFile);
        fclose(outFile);
        fflush(unOutFile);
        fclose(unOutFile);

        return NULL;
    }
};

// helpers borrowed from Simulation.cpp

bool ParsePositiveInt32(string token, uint32_t* value){
    return ParseInt32(token, value, 1);
}

// returns true on success... allows things to continue on failure if desired
bool ParseInt32(string token, uint32_t* value, uint32_t min){
    int32_t val;
    uint32_t mult = 1;
    bool ErrorFree = true;

    istringstream stream(token);
    if (stream >> val){
        if (!stream.eof()){
            char c;
            stream.get(c);

            c = ToLowerCase(c);
            if (c == 'k'){
                mult = KILO;
            } else if (c == 'm'){
                mult = MEGA;
            } else if (c == 'g'){
                mult = GIGA;
            } else {
                ErrorFree = false;
            }

            if (!stream.eof()){
                stream.get(c);

                c = ToLowerCase(c);
                if (c != 'b'){
                    ErrorFree = false;
                }
            }
        }
    }

    if (val < min){
        ErrorFree = false;
    }

    (*value) = (val * mult);
    return ErrorFree;
}

// returns true on success... allows things to continue on failure if desired
bool ParsePositiveInt32Hex(string token, uint32_t* value){
    int32_t val;
    bool ErrorFree = true;

    istringstream stream(token);

    char c1, c2;
    stream.get(c1);
    if (!stream.eof()){
        stream.get(c2);
    }

    if (c1 != '0' || c2 != 'x'){
        stream.putback(c1);
        stream.putback(c2);        
    }

    stringstream ss;
    ss << hex << token;
    if (ss >> val){
    }

    if (val <= 0){
        ErrorFree = false;
    }

    (*value) = val;
    return ErrorFree;
}


char ToLowerCase(char c){
    if (c < 'a'){
        c += ('a' - 'A');
    }
    return c;
}

bool ReadEnvUint32(string name, uint32_t* var){
    char* e = getenv(name.c_str());
    if (e == NULL){
        return false;
        inform << "unable to find " << name << " in environment" << ENDL;
    }
    string s (e);
    if (!ParseInt32(s, var, 0)){
        return false;
        inform << "unable to parse " << name << " in environment" << ENDL;
    }
    return true;
}

