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

#include <ReuseDistCommon.hpp>


// These control reuse distance calculations. Activate this feature by setting 
// METASIM_REUSE_WINDOW to something other than 0. The design of the reuse 
// distance tool is such that tracking a large window size isn't a lot more 
// expensive than a small size. Also this will be rendered relatively useless
// unless the sampling period (METASIM_SAMPLE_ON) is somewhat large relative 
// to METASIM_REUSE_WINDOW.
static uint32_t ReuseWindow = 0;
static uint32_t ReuseBin = 0;
static const uint64_t ReuseCleanupMin = 10000000;
static const double ReusePrintScale = 1.5;
static const uint32_t ReuseIndivPrint = 32;

static uint32_t LoadStoreLogging = 0;

// global data
static uint32_t CountMemoryHandlers = 0;
static uint32_t CountReuseHandlers = 0;
static int32_t ReuseHandlerIndex = 0;

static SamplingMethod* Sampler = NULL;
static DataManager<AddressStreamStats*>* AllData = NULL;
static FastData<AddressStreamStats*, BufferEntry*>* FastStats = NULL;
static set<uint64_t>* NonmaxKeys = NULL;

// should not be used directly. kept here to be cloned by anyone who needs it
static MemoryStreamHandler** MemoryHandlers = NULL;

static ReuseDistance** ReuseDistanceHandlers = NULL;


#define synchronize(__locker) __locker->WriteLock(); for (bool __s = true;\
  __s == true; __locker->UnLock(), __s = false) 


void GetBufferIds(BufferEntry* b, image_key_t* i){
    *i = b->imageid;
}

extern "C" {
    // Called at just before image initialization
    void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool* 
      isThreadedModeFlag){
        SAVE_STREAM_FLAGS(cout);
        InitializeDynamicInstrumentation(count, dyn,isThreadedModeFlag);
        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    void* tool_mpi_init(){
        return NULL;
    }

    void* tool_thread_init(thread_key_t tid){
        SAVE_STREAM_FLAGS(cout);
        if (AllData){
            if(isThreadedMode())
                AllData->AddThread(tid);
            InitializeSuspendHandler();

            assert(FastStats);
            if(isThreadedMode())
                FastStats->AddThread(tid);
        } else {
            ErrorExit("Calling PEBIL thread initialization library for thread " 
              << hex << tid << " but no images have been initialized.", 
              MetasimError_NoThread);
        }
        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    void* tool_thread_fini(thread_key_t tid){
        SAVE_STREAM_FLAGS(cout);
        inform << "Destroying thread " << hex << tid << ENDL;

        // utilizing finished threads is *buggy*
        /*
        synchronize(AllData){
            AllData->FinishThread(tid);
        }
        */
        RESTORE_STREAM_FLAGS(cout);
    }

    // initializes an image
    // The mutex assures that the image is initialized exactly once, especially 
    // in the case that multiple threads exist before this image is initialized
    // It should be unnecessary if only a single thread exists because
    // this function kills initialization points
    static pthread_mutex_t image_init_mutex = PTHREAD_MUTEX_INITIALIZER;
    void* tool_image_init(void* s, image_key_t* key, ThreadData* td){
        SAVE_STREAM_FLAGS(cout);
        AddressStreamStats* stats = (AddressStreamStats*)s;

        assert(stats->Initialized == true);

        pthread_mutex_lock(&image_init_mutex);

        // initialize AllData once per address space
        if (AllData == NULL){
            init_signal_handlers();
            ReadSettings();
            AllData = new DataManager<AddressStreamStats*>(GenerateStreamStats,
              DeleteStreamStats, ReferenceStreamStats);
        }
        assert(AllData);

        // Once per image
        if(AllData->allimages.count(*key) == 0){
            // Initialize image with AllData
            AllData->AddImage(stats, td, *key);

            // Once per address space, initialize FastStats
            // This must be done after AllData has exactly one image, 
            // thread initialized
            if (FastStats == NULL){
                FastStats = new FastData<AddressStreamStats*, BufferEntry*>(
                  GetBufferIds, AllData, BUFFER_CAPACITY(stats));
            }
            assert(FastStats);

            FastStats->AddImage();
            stats->threadid = AllData->GenerateThreadKey();
            stats->imageid = *key;
    
            // Get all dynamic point keys and possibly disable them
            synchronize(AllData){
                if (NonmaxKeys == NULL){
                    NonmaxKeys = new set<uint64_t>();
                }
    
                set<uint64_t> keys;
                GetAllDynamicKeys(keys);
                for (set<uint64_t>::iterator it = keys.begin(); it != 
                  keys.end(); it++){
                    uint64_t k = (*it);
                    if (GET_TYPE(k) == PointType_bufferfill && 
                      AllData->allimages.count(k) == 0){
                        NonmaxKeys->insert(k);
                    }
                }
 
                if (Sampler->SampleOn == 0){
                    inform << "Disabling all simulation-related instrumentation"
                      " because METASIM_SAMPLE_ON is set to 0" << ENDL;
                    set<uint64_t> AllSimPoints;
                    for (set<uint64_t>::iterator it = NonmaxKeys->begin(); 
                      it != NonmaxKeys->end(); it++){
                        AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
                          PointType_buffercheck));
                        AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
                          PointType_bufferinc));
                        AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
                          PointType_bufferfill));
                    }
                    SetDynamicPoints(AllSimPoints, false);
                    NonmaxKeys->clear();
                }
    
                AllData->SetTimer(*key, 0);
            }

            // Kill initialization points for this image
            set<uint64_t> inits;
            inits.insert(*key);
            debug(inform << "Removing init points for image " << hex << (*key) 
              << ENDL);
            SetDynamicPoints(inits, false); 

        }

        pthread_mutex_unlock(&image_init_mutex);

        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    
    static void ProcessReuseBuffer(ReuseDistance* rd, uint32_t numElements, image_key_t iid, thread_key_t tid){

        uint32_t threadSeq = AllData->GetThreadSequence(tid);
        uint32_t numProcessed = 0;

        AddressStreamStats** faststats = FastStats->GetBufferStats(tid);
        uint32_t bufcur = 0;
        for (bufcur = 0; bufcur < numElements; bufcur++){
            debug(assert(faststats[bufcur]));
            debug(assert(faststats[bufcur]->Stats));

            AddressStreamStats* stats = faststats[bufcur];

            BufferEntry* reference = BUFFER_ENTRY(stats, bufcur);

            if (reference->imageid == 0){
                debug(assert(AllData->CountThreads() > 1));
                continue;
            }

            ReuseEntry entry = ReuseEntry();
            entry.id = stats->Hashes[stats->BlockIds[reference->memseq]];
            entry.address=reference->address ;
            rd->Process(entry);
            numProcessed++;
        }
    }

    static void* process_thread_buffer(image_key_t iid, thread_key_t tid){

#define DONE_WITH_BUFFER(...) BUFFER_CURRENT(stats) = 0;  return NULL;

        assert(iid);
        if (AllData == NULL){
            ErrorExit("data manager does not exist. no images were initialized",
              MetasimError_NoImage);
            return NULL;
        }

        // Buffer is shared between all images
        debug(inform << "Getting data for image " << hex << iid << " thread " 
          << tid << ENDL);
        AddressStreamStats* stats = (AddressStreamStats*)AllData->GetData(iid, 
          tid);
        if (stats == NULL){
            ErrorExit("Cannot retreive image data using key " << dec << iid, 
              MetasimError_NoImage);
            return NULL;
        }

        uint64_t numElements = BUFFER_CURRENT(stats);
        uint64_t capacity = BUFFER_CAPACITY(stats);
        uint32_t threadSeq = AllData->GetThreadSequence(tid);

        debug(inform << "Thread " << hex << tid << TAB << "Image " << hex 
          << iid << TAB << "Counter " << dec << numElements << TAB 
          << "Capacity " << dec << capacity << TAB << "Total " << dec 
          << Sampler->AccessCount << ENDL);

        bool isSampling;
        // Check if we are sampling
        synchronize(AllData){
            isSampling = Sampler->CurrentlySampling();
            if (NonmaxKeys->empty()){
                AllData->UnLock();
                DONE_WITH_BUFFER();
            }
        }

        synchronize(AllData){
            if (isSampling){
                BufferEntry* buffer = &(stats->Buffer[1]);
                // Refresh FastStats so it can be used
                FastStats->Refresh(buffer, numElements, tid);
                //Don't need to check if ReuseDistance is set anymore
                ReuseDistance* rd=NULL;
                rd = stats->RHandlers[ReuseHandlerIndex];
                ProcessReuseBuffer(rd, numElements, iid, tid);       
                // Update the GroupCounters for sampling purposes
                for(uint32_t i = 0; i < (stats->BlockCount); i++) {
                    uint32_t idx = i;
                    if (stats->Types[i] == CounterType_instruction) {
                        idx = stats->Counters[i];
                    }

                    uint64_t blocksGroupId = stats->GroupIds[i]; 
                    uint64_t blockCount = stats->Counters[idx];
                    if(stats->GroupCounters[blocksGroupId] < blockCount) {
                        stats->GroupCounters[blocksGroupId] = blockCount;
                    }
                }               
            } 
        }

        // Turn sampling on/off
        synchronize(AllData){
            if (isSampling){
                set<uint64_t> MemsRemoved;
                AddressStreamStats** faststats = FastStats->GetBufferStats(tid);
                for (uint32_t j = 0; j < numElements; j++){
                    AddressStreamStats* s = faststats[j];
                    BufferEntry* reference = BUFFER_ENTRY(s, j);

                    debug(inform << "Memseq " << dec << reference->memseq << 
                      " has " << s->Stats[0]->GetAccessCount(reference->memseq)
                      << ENDL);

                    uint32_t bbid = s->BlockIds[reference->memseq];

                    // if max block count is reached, disable all buffer-related
                    // points related to this block
                    uint32_t idx = bbid;
                    uint32_t gidx = stats->GroupIds[bbid];

                    if (s->Types[bbid] == CounterType_instruction){
                        idx = s->Counters[bbid];
                    }

                    debug(inform << "Slot " << dec << j << TAB << "Thread " 
                      << dec << AllData->GetThreadSequence(pthread_self())
                      << TAB << "Block " << bbid << TAB << "Index " << idx
                      << TAB << "Group " << stats->GroupIds[bbid]
                      << TAB << "Counter " << s->Counters[bbid]
                      << TAB << "Real " << s->Counters[idx]
                      << TAB << "GroupCount " << stats->GroupCounters[gidx]
                      << ENDL);

                    if (Sampler->ExceedsAccessLimit(s->Counters[idx]) || 
                      (Sampler->ExceedsAccessLimit(stats->GroupCounters[gidx]))
                      ) {

                        uint64_t k1 = GENERATE_KEY(gidx, PointType_buffercheck);
                        uint64_t k2 = GENERATE_KEY(gidx, PointType_bufferinc);
                        uint64_t k3 = GENERATE_KEY(gidx, PointType_bufferfill);

                        if (NonmaxKeys->count(k3) > 0){

                            if (MemsRemoved.count(k1) == 0){
                                MemsRemoved.insert(k1);
                            }
                            assert(MemsRemoved.count(k1) == 1);

                            if (MemsRemoved.count(k2) == 0){
                                MemsRemoved.insert(k2);
                            }
                            assert(MemsRemoved.count(k2) == 1);

                            if (MemsRemoved.count(k3) == 0){
                                MemsRemoved.insert(k3);
                            }
                            assert(MemsRemoved.count(k3) == 1);

                            NonmaxKeys->erase(k3);
                            assert(NonmaxKeys->count(k3) == 0);
                        }
                    }
                }
                if (MemsRemoved.size()){
                    assert(MemsRemoved.size() % 3 == 0);
                    debug(inform << "REMOVING " << dec << (MemsRemoved.size() 
                      / 3) << " blocks" << ENDL);
                    SuspendAllThreads(AllData->CountThreads(), 
                      AllData->allthreads.begin(), AllData->allthreads.end());
                    SetDynamicPoints(MemsRemoved, false);
                    ResumeAllThreads();
                }

                if (Sampler->SwitchesMode(numElements)){
                    SuspendAllThreads(AllData->CountThreads(), 
                      AllData->allthreads.begin(), AllData->allthreads.end());
                    SetDynamicPoints(*NonmaxKeys, false);
                    ResumeAllThreads();
                }

            } else { // if not samping
                if (Sampler->SwitchesMode(numElements)){
                    SuspendAllThreads(AllData->CountThreads(), 
                      AllData->allthreads.begin(), AllData->allthreads.end());
                    SetDynamicPoints(*NonmaxKeys, true);
                    ResumeAllThreads();
                }

                // reuse distance handler needs to know that we passed over 
                // asome addresses
                if (ReuseWindow){
                    ReuseDistance* r = stats->RHandlers[ReuseHandlerIndex];
                    r->SkipAddresses(numElements);
                }
            }

            Sampler->IncrementAccessCount(numElements);
        }

        DONE_WITH_BUFFER();
    }

    // conditionally called at first memop in each block
    void* process_buffer(image_key_t* key){
        // forgo this since we shouldn't be printing anything during production
        SAVE_STREAM_FLAGS(cout);

        image_key_t iid = *key;
        process_thread_buffer(iid, pthread_self());

        RESTORE_STREAM_FLAGS(cout);
    }

    // Called when the application exits. Collect the rest of the addresses in 
    // the buffer
    void* tool_image_fini(image_key_t* key){
        image_key_t iid = *key;

        AllData->SetTimer(iid, 1);
        SAVE_STREAM_FLAGS(cout);

#ifdef MPI_INIT_REQUIRED
        if (!IsMpiValid()){
            warn << "Process " << dec << getpid() << " did not execute "
              << "MPI_Init, will not print execution count files" << ENDL;
            RESTORE_STREAM_FLAGS(cout);
            return NULL;
        }
#endif

        if (AllData == NULL){
            ErrorExit("data manager does not exist. no images were "
              "initialized", MetasimError_NoImage);
            return NULL;
        }

        AddressStreamStats* stats = (AddressStreamStats*)AllData->GetData(iid, 
          pthread_self());
        if (stats == NULL){
            ErrorExit("Cannot retreive image data using key " << dec << (*key),
              MetasimError_NoImage);
            return NULL;
        }

        // only print stats when the master image exits
        if (!stats->Master){
            RESTORE_STREAM_FLAGS(cout);
            return NULL;
        }

        // clear all threads' buffers
        for (set<thread_key_t>::iterator it = AllData->allthreads.begin(); 
          it != AllData->allthreads.end(); it++){
            process_thread_buffer(iid, (*it));
        }

        // Create the Reuse Report(s)
        string oFile;
        const char* fileName;
  
        if (ReuseWindow){
            ofstream ReuseDistFile;
            ReuseDistFileName(stats, oFile);
            fileName = oFile.c_str();
            inform << "Printing reuse distance results to " << fileName << ENDL;
            TryOpen(ReuseDistFile, fileName);

            for (set<image_key_t>::iterator iit = AllData->allimages.begin(); iit != AllData->allimages.end(); iit++){
                for(DataManager<AddressStreamStats*>::iterator it = AllData->begin(*iit); it != AllData->end(*iit); ++it) {

                    thread_key_t thread = it->first;
                    AddressStreamStats* s = it->second;
                    ReuseDistFile << "IMAGE" << TAB << hex << (*iit) << TAB << "THREAD" << TAB << dec << AllData->GetThreadSequence(thread) << ENDL;
            
                    ReuseDistance* rd = s->RHandlers[ReuseHandlerIndex];
                    assert(rd);
                    inform << "Reuse distance bins for " << hex << s->Application << " Thread " << AllData->GetThreadSequence(thread) << ENDL;
                    rd->Print();
                    rd->Print(ReuseDistFile, true);
                }
            }
            ReuseDistFile.close();
        }
        double t = (AllData->GetTimer(*key, 1) - AllData->GetTimer(*key, 0));
        inform << "CXXX--ReuseDistance Total Execution time for instrumented application " 
          << t << ENDL;
        if(NonmaxKeys){
            delete NonmaxKeys;
        }
        RESTORE_STREAM_FLAGS(cout);
    } // end of tool_image_fini function
}; // end of extern C



void ReuseDistFileName(AddressStreamStats* stats, string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".dist");
}

char ToLowerCase(char c){
    if (c < 'a'){
        c += ('a' - 'A');
    }
    return c;
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

uint64_t ReferenceStreamStats(AddressStreamStats* stats){
    return (uint64_t)stats;
}

void DeleteStreamStats(AddressStreamStats* stats){
    if (!stats->Initialized){
        // TODO: delete buffer only for thread-initialized structures?

        delete[] stats->Counters;

        for (uint32_t i = 0; i < CountMemoryHandlers; i++){
            delete stats->Stats[i];
            delete stats->Handlers[i];
        }
        delete[] stats->Stats;
    }
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

SamplingMethod::SamplingMethod(uint32_t limit, uint32_t on, uint32_t off){
    AccessLimit = limit;
    SampleOn = on;
    SampleOff = off;

    AccessCount = 0;
}

SamplingMethod::~SamplingMethod(){
}

void SamplingMethod::Print(){
    inform << "SamplingMethod:" << TAB << "AccessLimit " << AccessLimit 
      << " SampleOn " << SampleOn << " SampleOff " << SampleOff << ENDL;
}

void SamplingMethod::IncrementAccessCount(uint64_t count){
    AccessCount += count;
}

bool SamplingMethod::SwitchesMode(uint64_t count){
    return (CurrentlySampling(0) != CurrentlySampling(count));
}

bool SamplingMethod::CurrentlySampling(){
    return CurrentlySampling(0);
}

bool SamplingMethod::CurrentlySampling(uint64_t count){
    uint32_t PeriodLength = SampleOn + SampleOff;

    bool res = false;
    if (SampleOn == 0){
        return res;
    }

    if (PeriodLength == 0){
        res = true;
    }
    if ((AccessCount + count) % PeriodLength < SampleOn){
        res = true;
    }
    return res;
}

bool SamplingMethod::ExceedsAccessLimit(uint64_t count){
    bool res = false;
    if (AccessLimit > 0 && count > AccessLimit){
        res = true;
    }
    return res;
}

MemoryStreamHandler::MemoryStreamHandler(){
    pthread_mutex_init(&mlock, NULL);
}
MemoryStreamHandler::~MemoryStreamHandler(){
}

bool MemoryStreamHandler::TryLock(){
    return (pthread_mutex_trylock(&mlock) == 0);
}

bool MemoryStreamHandler::Lock(){
    return (pthread_mutex_lock(&mlock) == 0);
}

bool MemoryStreamHandler::UnLock(){
    return (pthread_mutex_unlock(&mlock) == 0);
}


// called for every new image and thread
AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, uint32_t typ,
  image_key_t iid, thread_key_t tid, image_key_t firstimage){
 
    assert(stats);
    AddressStreamStats* s = stats;

    // allocate Counters contiguously with AddressStreamStats. Since the 
    // address of AddressStreamStats is the address of the thread data, this 
    // allows us to avoid an extra memory ref on Counter updates
    if (typ == AllData->ThreadType){
        AddressStreamStats* s = stats;
        stats = (AddressStreamStats*)malloc(sizeof(AddressStreamStats) + 
          (sizeof(uint64_t) * stats->BlockCount));
        assert(stats);
        memcpy(stats, s, sizeof(AddressStreamStats));
        stats->Initialized = false;
    }
    assert(stats);
    stats->threadid = tid;
    stats->imageid = iid;

    // every thread and image gets its own statistics
    if(stats->MemopCount > stats->BlockCount) {
        stats->AllocCount = stats->MemopCount;
    } else {
        stats->AllocCount = stats->BlockCount;
    }

    // Initialize Address Stream Handler (MemoryHandler)
    stats->Stats = new StreamStats*[CountMemoryHandlers];
    bzero(stats->Stats, sizeof(StreamStats*) * CountMemoryHandlers);    

    if (typ == AllData->ThreadType || (iid == firstimage)){
        stats->Handlers = new MemoryStreamHandler*[CountMemoryHandlers];   
    
        // all images within a thread share a set of memory handlers, but 
        //they don't exist for any image
        if (ReuseWindow){
            // We have a set of reuse handlers (reuse, spatial) per thread
            stats->RHandlers = new ReuseDistance*[CountReuseHandlers]; 
            stats->RHandlers[ReuseHandlerIndex] = new ReuseDistance(ReuseWindow, ReuseBin);
        } 
    }
    else{
        AddressStreamStats * fs = AllData->GetData(firstimage, tid);
        stats->Handlers = fs->Handlers;
    }

    // each thread gets its own buffer
    if (typ == AllData->ThreadType){
        stats->Buffer = new BufferEntry[BUFFER_CAPACITY(stats) + 1];
        bzero(BUFFER_ENTRY(stats, 0), (BUFFER_CAPACITY(stats) + 1) * 
          sizeof(BufferEntry));
        BUFFER_CAPACITY(stats) = BUFFER_CAPACITY(s);
        BUFFER_CURRENT(stats) = 0;
    } else if (iid != firstimage){
        AddressStreamStats* fs = AllData->GetData(firstimage, tid);
        stats->Buffer = fs->Buffer;
    }


    // each thread/image gets its own counters
    if (typ == AllData->ThreadType){
        uint64_t tmp64 = (uint64_t)(stats) + (uint64_t)(sizeof(
          AddressStreamStats));
        stats->Counters = (uint64_t*)(tmp64);

        // keep all CounterType_instruction in place
        memcpy(stats->Counters, s->Counters, sizeof(uint64_t) * s->BlockCount);
        for (uint32_t i = 0; i < stats->BlockCount; i++){
            if (stats->Types[i] != CounterType_instruction){
                stats->Counters[i] = 0;
            }
        }
    }

    return stats;
}

void ReadSettings(){

    if (!ReadEnvUint32("METASIM_REUSE_WINDOW", &ReuseWindow)){
        ReuseWindow = 1; //if someone's using the tool, they must want data
    }
    if (!ReadEnvUint32("METASIM_REUSE_BIN", &ReuseBin)){
        ReuseBin = 1;
    }
    
    if(!ReadEnvUint32("METASIM_LOAD_LOG",&LoadStoreLogging)){
        LoadStoreLogging = 0;
    }
    ReuseHandlerIndex=0;
    CountReuseHandlers++;
    ReuseDistanceHandlers = new ReuseDistance*[CountReuseHandlers];
    ReuseDistanceHandlers[ReuseHandlerIndex] = new ReuseDistance(ReuseWindow, ReuseBin);

    uint32_t SampleMax;
    uint32_t SampleOn;
    uint32_t SampleOff;
    if (!ReadEnvUint32("METASIM_SAMPLE_MAX", &SampleMax)){
        SampleMax = DEFAULT_SAMPLE_MAX;
    }
    if (!ReadEnvUint32("METASIM_SAMPLE_OFF", &SampleOff)){
        SampleOff = DEFAULT_SAMPLE_OFF;
    }
    if (!ReadEnvUint32("METASIM_SAMPLE_ON", &SampleOn)){
        SampleOn = DEFAULT_SAMPLE_ON;
    }

    Sampler = new SamplingMethod(SampleMax, SampleOn, SampleOff);
    Sampler->Print();
}

