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
 * Time spent in each function
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
#include <LoopTimer.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string>
#include <cstring>

using namespace std;

DataManager<LoopTimers*>* AllData = NULL;
DynamicInstrumentation* DynamicPoints = NULL;
static std::set<uint64_t> EntryExitKeys;

// by default, do not shut off loop timing instrumentation.
// please set LTIMER_SHUTOFF to something other than zero to enable
//  function timer shutoff.
static uint32_t shutoffLoopTimers=0;
// by default, the function timer tool allows 100 invocations of the
//  loop and then averages the time per visit to determine 
//  whether to shut off timing measurement. please set LTIMER_ITERS
//  to control the number of iterations.
static uint32_t shutoffIters=100;
// by default, the loop timer shuts of the timing for function if
//  the per visit time is less than 800 microseconds.
// please set LTIMER_THRESHOLD env variable to control the number of
// microseconds per visit.
static uint32_t timingThreshold=800;
// TODO implement trackUnenetedLoops??
// By default, shut off loop that are exited but not recorded as entered
// Otherwise, this keeps track of # times this happens per thread
//static uint32_t trackUnenteredLoops=0;
//static uint64_t timerCPUFreq=3200000000;

// HPE EPYC: note that if the env variable is not defined, we default to 
//    what is defined here:
static uint32_t timerCPUFreq=2200000000;

// HPE Epyc
#define CLOCK_RATE_HZ 2200000000
// Clark
//#define CLOCK_RATE_HZ 2600079000

// Xeon Phi Max Rate
//#define CLOCK_RATE_HZ 1333332000
inline uint64_t read_timestamp_counter(){
    unsigned low, high;
    __asm__ volatile ("rdtsc" : "=a" (low), "=d"(high));
    return ((unsigned long long)low | (((unsigned long long)high) << 32));
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
LoopTimers* GenerateLoopTimers(LoopTimers* timers, uint32_t typ, image_key_t iid, thread_key_t tid, image_key_t firstimage) {

    LoopTimers* retval;
    retval = new LoopTimers();

    retval->master = timers->master && typ == DataManagerType_Image;
    retval->application = timers->application;
    retval->extension = timers->extension;
    retval->loopCount = timers->loopCount;
    retval->loopHashes = timers->loopHashes;
    retval->loopTimerAccum = new uint64_t[retval->loopCount];
    retval->loopTimerLast = new uint64_t[retval->loopCount];
    retval->entryCounts = new uint64_t[retval->loopCount];
    retval->loopShutoff = new uint64_t[retval->loopCount];

    memset(retval->loopTimerAccum, 0, sizeof(uint64_t) * retval->loopCount);
    memset(retval->loopTimerLast, 0, sizeof(uint64_t) * retval->loopCount);
    memset(retval->entryCounts, 0, sizeof(uint64_t) * retval->loopCount);
    memset(retval->loopShutoff, 0, sizeof(uint64_t) * retval->loopCount);

    // read in key environment variables
    if (!ReadEnvUint32("LTIMER_SHUTOFF", &shutoffLoopTimers)) {
        shutoffLoopTimers = 0;
    }
    /*if (!ReadEnvUint32("LTIMER_TRACK_UNENTERED", &trackUnenteredLoops)){
        trackUnenteredLoops = 0;
    }*/

    // see if LTIMER_CPU_FREQ env var is defined
    char * ltimeCPU = getenv("LTIMER_CPU_FREQ");
    if (ltimeCPU != NULL) {
        std::stringstream strStream;
        strStream << ltimeCPU;
        strStream >> timerCPUFreq;
        inform << "Got custom LTIMER_CPU_FREQ ***(in Hz)** from the user :: "
          << timerCPUFreq << endl;
    } else {
        inform << "***Using the default CPU clock rate to calculate timings****"
          << CLOCK_RATE_HZ << endl;
        timerCPUFreq=CLOCK_RATE_HZ;
    }

    if(shutoffLoopTimers) {
        if (!ReadEnvUint32("LTIMERS_ITERS", &shutoffIters)){
            shutoffIters=100;
        }
        if (!ReadEnvUint32("LTIMER_THRESHOLD", &timingThreshold)){
            timingThreshold=800;
        }
    }
    return retval;
}

void DeleteLoopTimers(LoopTimers* timers){
    delete timers->loopTimerAccum;
    delete timers->loopTimerLast;
    delete timers->entryCounts;
    delete timers->loopShutoff;
}

uint64_t ReferenceLoopTimers(LoopTimers* timers){
    return (uint64_t)timers;
}

extern "C"
{

    void epa_pebil_start() {
        DynamicPoints->SetDynamicPoints(EntryExitKeys, true);
        return;
    }
    void epa_pebil_start_() { epa_pebil_start(); return; }

    void epa_pebil_pause() {
        DynamicPoints->SetDynamicPoints(EntryExitKeys, false);
        return;
    }
    void epa_pebil_pause_() { epa_pebil_pause(); return; }

    // start timer
    int32_t loop_entry(uint32_t loopIndex, image_key_t* key) {
        thread_key_t tid = pthread_self();

        LoopTimers* timers = AllData->GetData(*key, pthread_self());
        assert(timers != NULL);
        assert(timers->loopTimerLast != NULL);
        
        timers->loopTimerLast[loopIndex] = read_timestamp_counter();
        timers->entryCounts[loopIndex]++;
        return 0;
    }

    // end timer
    int32_t loop_exit(uint32_t loopIndex, image_key_t* key) {
        thread_key_t tid = pthread_self();

        LoopTimers* timers = AllData->GetData(*key, pthread_self());
        uint64_t last = timers->loopTimerLast[loopIndex];
        uint64_t now = read_timestamp_counter();
        timers->loopTimerAccum[loopIndex] += now - last;
        // TODO Do we want to turn this on?
        //timers->loopTimerLast = now;

        if(!shutoffLoopTimers) {
            return 0;
        }
        if (timers->entryCounts[loopIndex] % shutoffIters != 0) {
            return 0;
        }
        // time per visit is total t
        double timeInFunction = timers->loopTimerAccum[loopIndex];
        double numVisits = (double)timers->entryCounts[loopIndex];
        double timePerVisit = timeInFunction / numVisits / timerCPUFreq;

        if(timePerVisit < (((double)timingThreshold)/1000000.0)) {
            uint64_t imageSeq = AllData->GetImageSequence(*key);
            AllData->WriteLock();
            uint64_t loopHash = timers->loopHashes[loopIndex];
            uint64_t this_key = GENERATE_UNIQUE_KEY(loopHash, imageSeq,
              PointType_loopExit);
            uint64_t corresponding_entry_key = GENERATE_UNIQUE_KEY(
              loopHash, imageSeq, PointType_loopEntry);

            /*warn << "Shutting off timing for loop " << loopIndex
              //<< timers->functionNames[loopIndex] 
              << ";\ntime per visit averaged over " 
              << timers->entryCounts[loopIndex] 
              << " entries is " << timePerVisit 
              << "s;\nspecified cut-off threshold is " 
              << (((double)timingThreshold)/1000000.0) 
              << "s." << ENDL;*/

            set<uint64_t>inits;
            inits.insert(this_key);
            inits.insert(corresponding_entry_key);
            DynamicPoints->SetDynamicPoints(inits, false);
            timers->loopShutoff[loopIndex] = 1;
            AllData->UnLock();
        }
        return 0;
    }

    // Just after MPI_Init is called
    void* tool_mpi_init() {
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
        LoopTimers* timers = (LoopTimers*)args;

        // If this is the first image, set up a data manager
        if (AllData == NULL){
            init_signal_handlers();
            AllData = new DataManager<LoopTimers*>(GenerateLoopTimers, 
              DeleteLoopTimers, ReferenceLoopTimers);
        }

        // Check if added already
        if (AllData->allimages.count(*key) != 0) {
            pthread_mutex_unlock(&image_init_mutex);
            return NULL;
        }

        // image time
        /*timers->appTimeStart = read_timestamp_counter();
        gettimeofday(&timers->appTimeOfDayStart, NULL);*/

        // Add this image
        AllData->AddImage(timers, td, *key);

        // Remove this instrumentation
        // Must be done after the image is added, or threads may get to the
        // instrumentation before the image is initialized
        set<uint64_t> inits;
        inits.insert(GENERATE_KEY(*key, PointType_inits));
        DynamicPoints->SetDynamicPoints(inits, false);

        // Get all loop entry and loop exit instrumentation points so that the
        // user can turn them on/off
        std::set<uint64_t> keys;
        DynamicPoints->GetAllDynamicKeys(keys);
        assert(EntryExitKeys.empty());
        for (auto it = keys.begin(); it != keys.end(); it++) {
            uint64_t k = (*it);
            if (GET_TYPE(k) == PointType_loopEntry ||
              GET_TYPE(k) == PointType_loopExit) {
                EntryExitKeys.insert(k);
            }
        }

        // If EPA_SLICER_START_OFF is set, then turn inst off
        uint32_t startOff = 0;
        // TODO EEO do we want to make this loop specific name?
        (void) ReadEnvUint32("EPA_SLICER_START_OFF", &startOff);
        if (startOff != 0) {
            DynamicPoints->SetDynamicPoints(EntryExitKeys, false);
        }

        pthread_mutex_unlock(&image_init_mutex);
        return NULL;
    }

    // 
    void* tool_image_fini(image_key_t* key) {

        image_key_t iid = *key;

        // Only print one file with data froma ll images
        // EEO this doesn't look right, need to figure out the 
        // locking around this
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

        LoopTimers* timers = AllData->GetData(iid, pthread_self());
        if (timers == NULL){
            ErrorExit("Cannot retrieve image data using key " << dec << (*key), 
              MetasimError_NoImage);
            return NULL;
        }

        if (!timers->master){
            printf("Image is not master, skipping\n");
            return NULL;
        }

        
        /*uint64_t appTimeEnd = read_timestamp_counter();
        struct timeval tvEnd;
        gettimeofday(&tvEnd, NULL);*/

        // print times
        char outFileName[1024];
        sprintf(outFileName, "%s.meta_%0d.%s", timers->application, GetTaskId(), 
          timers->extension);

        // print unentered functions
        /*char unenteredFileName, "%s.unentered_%0d.%s", timers->application,
          GetTaskId(), timers->extension);*/

        FILE* outFile = fopen(outFileName, "w");
        if (!outFile){
            cerr << "error: cannot open output file %s" << outFileName << ENDL;
            exit(-1);
        }

        /*FILE* unOutFile = fopen(unenteredFileName, "w");
        if (!unOutFile){
            cerr << "error: cannot open output file %s" << unenteredFileName
              << ENDL;
            exit(-1);
        }*/

        /*fprintf(outFile, "App timestamp time: %lld %lld %f\n",
          timers->appTimeStart, appTimeEnd,
          (double)(appTimeEnd - timers->appTimeStart) / timerCPUFreq);
        fprintf(outFile, "App timeofday time: %lld %lld %f\n",
          timers->appTimeOfDataStart.tv_sec, tvEnd.tv_sec,
          difTIme(timers->appTimeOfDayStart, tvEnd));*/ 
        // for each image
        //   for each loop
        //     for each thread
        //       print time
        for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
          iit != AllData->allimages.end(); ++iit) {

            LoopTimers* imageData = AllData->GetData(*iit, pthread_self());

            uint64_t imgHash = *iit;
            uint64_t* loopHashes = imageData->loopHashes;
            uint64_t loopCount = imageData->loopCount;

            for (uint64_t loopIndex = 0; loopIndex < loopCount; ++loopIndex){
                uint64_t loopHash = loopHashes[loopIndex];
                fprintf(outFile, "0x%llx:0x%llx:\n", imgHash, loopHash);
 
                for (set<thread_key_t>::iterator tit = 
                  AllData->allthreads.begin(); tit != AllData->allthreads.end(); 
                  ++tit) {

                    LoopTimers* timers = AllData->GetData(*iit, *tit);

                    thread_key_t thread = *tit;
                    double time = (double)(timers->loopTimerAccum[loopIndex]) 
                      / timerCPUFreq;
                    uint64_t entries = timers->entryCounts[loopIndex];
                    // uint64_t loopHash defined above
                    // uin64_t imgHash defined even further up
                    if(timers->loopShutoff[loopIndex]==1) {
                        fprintf(outFile, "\tThread: 0x%llx\tTime: %f\tEntries: "
                          "%lld\tHash: 0x%llx\tImage: %d*\n", 
                          thread, time, entries, loopHash, imgHash);
                    } else {
                        fprintf(outFile, "\tThread: %d\tTime: %f\tEntries: "
                          "%lld\tHash: 0x%llx\tImage: %d\n",
                          thread, time, entries, loopHash, imgHash);
                    }
                }
            }
        }

        fflush(outFile);
        fclose(outFile);

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

