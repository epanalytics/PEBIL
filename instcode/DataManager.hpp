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

#ifndef _DataManager_hpp_
#define _DataManager_hpp_
#include <assert.h>
#include <set>

#define DataMap pebil_map_type
#define ThreadHashShift (16)
#define ThreadHashMod   (0x3ffff)

#ifndef debug
//#define debug(...) __VA_ARGS__
#define debug(...)
#endif

typedef uint64_t image_key_t;
typedef pthread_t thread_key_t;

enum DataManagerTypes {
    DataManagerType_Thread = 0,
    DataManagerType_Image,
    DataManagerType_Total
};

// data management support
template <class T> class DataManager {
protected:
    uint32_t currentimageseq;
    DataMap <image_key_t, uint32_t> imageseq;

private:

    // Used to make sure reads cannot happen while a write is in progress
    pthread_rwlock_t rwlock;
    pthread_rwlockattr_t rwlock_attr;

    // image_key_t -> thread_key_t -> T
    DataMap <image_key_t, DataMap<thread_key_t, T> > datamap;

    // Used to generate a new data from a template T
    T (*datagen)(T, uint32_t, image_key_t, thread_key_t, image_key_t);
    void (*datadel)(T);
    uint64_t (*dataref)(T);

    DataMap <image_key_t, DataMap<uint32_t, double> > timers;

    uint32_t currentthreadseq;
    DataMap <thread_key_t, uint32_t> threadseq;

    image_key_t firstimage;

    // map from image keys to each image's threaddata hashtable
    DataMap <image_key_t, ThreadData*> threaddata;

    uint32_t HashThread(thread_key_t tid){
        return (tid >> ThreadHashShift) & ThreadHashMod;
    }

    // initialize threaddata hashtable for this image/thread
    uint64_t SetThreadData(image_key_t iid, thread_key_t tid, uint32_t typ){
        uint32_t h = 0;
        //if (typ != ImageType)
          h = HashThread(tid);

        // image must have already been added
        // thread must have already been added
        assert(threaddata.count(iid) == 1);
        assert(datamap.count(iid) == 1);
        assert(datamap[iid].count(tid) == 1);

        ThreadData* td = threaddata[iid];

        uint32_t actual = h;

        while (td[actual].id != 0){
            actual = (actual + 1) % (ThreadHashMod + 1);
        }
        T d = datamap[iid][tid];
        td[actual].id = (uint64_t)tid;
        td[actual].data = (uint64_t)dataref(d);

 /* 
        if (typ == DataManagerType_Image){
            warn << "Image " << std::hex << iid << " thread " << tid << ENDL;
        } else {
            warn << "Thread " << std::hex << tid << " image " << iid << ENDL;
        }
        warn
            << " setting up thread data for " << tid << " at index "
            << std::dec << actual << TAB << std::hex << td << "(" 
            << threadseq[tid] << ")"
            << " -> " << std::hex << td[actual].data
            << ENDL;
  */
        // just fail if there was a collision. it makes writing tools much easier so we see how well this works for now
        if (actual != h){
            warn << "Collision placing thread-specific data for " << tid << ": slot " << std::dec << h << " already taken" << ENDL;
      exit(-1);
        }
        assert(actual == h);
        return td[actual].data;
    }

    void RemoveThreadData(image_key_t iid, thread_key_t tid){
        uint32_t h = HashThread(tid);

        assert(threaddata.count(iid) == 1);

        ThreadData* td = threaddata[iid];

        uint32_t actual = h;
        while (td[actual].id != tid) {
            actual = (actual + 1) % (ThreadHashMod + 1);
        }
        td[actual].id = 0;
        td[actual].data = 0;
    }

    void RemoveData(image_key_t iid, thread_key_t tid){
        assert(datamap.count(iid) == 1);
        assert(datamap[iid].count(tid) == 1);

        T data = datamap[iid][tid];
        datadel(data);
        datamap[iid].erase(tid);
    }

    void RemoveThread() {
        RemoveThread(pthread_self());
    }

    void RemoveThread(thread_key_t tid){
        WriteLock();
        //assert(false);
        assert(donethreads.count(tid) == 1);

        for (std::set<image_key_t>::iterator iit = allimages.begin(); iit !=
          allimages.end(); iit++){
            assert(datamap[(*iit)].size() > 0);
            assert(datamap[(*iit)].count(tid) == 1);
            RemoveData((*iit), tid);
            RemoveThreadData((*iit), tid);
        }
        donethreads.erase(tid);
        UnLock();
    }

public:

    typedef typename DataMap<thread_key_t, T>::iterator iterator;

    iterator begin(image_key_t img) {
        return datamap[img].begin();
    }
    iterator end(image_key_t img) {
        return datamap[img].end();
    }

    std::set<thread_key_t> allthreads;
    std::set<thread_key_t> donethreads;
    std::set<image_key_t> allimages;

    DataManager(T (*g)(T, uint32_t, image_key_t, thread_key_t, image_key_t), void (*d)(T), uint64_t (*r)(T)){
        datagen = g;
        datadel = d;
        dataref = r;

        // Set to prefer to prevent starvation at thread initialization
        pthread_rwlockattr_init(&rwlock_attr);
        pthread_rwlockattr_setkind_np(&rwlock_attr,
          PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
        pthread_rwlock_init(&rwlock, &rwlock_attr);

        WriteLock();
        currentthreadseq = 0;
        threadseq[GenerateThreadKey()] = currentthreadseq++;

        currentimageseq = 0;
        firstimage = 0;
        UnLock();
    }

    virtual ~DataManager(){
        // Finish any unfinished threads
        for (std::set<thread_key_t>::iterator tit = allthreads.begin();
          tit != allthreads.end(); tit++) {
            if (ThreadLives(*tit)) {
                FinishThread(*tit);
            }
            RemoveThread(*tit);
        }

        WriteLock();
        datamap.clear();
        threaddata.clear();

        UnLock();
    }

    bool WriteLock(){
        bool res = (pthread_rwlock_wrlock(&rwlock) == 0);
        return res;
    }

    bool ReadLock(){
        bool res = (pthread_rwlock_rdlock(&rwlock) == 0);
        return res;
    }

    bool UnLock(){
        bool res = (pthread_rwlock_unlock(&rwlock) == 0);
        return res;
    }

    // these can only be called correctly by the current thread
    virtual thread_key_t GenerateThreadKey(){
        return pthread_self();
    }

    image_key_t GetFirstImage() {
        return firstimage;
    }

    virtual uint32_t GetThreadSequence(thread_key_t tid){
        ReadLock();
        if (threadseq.count(tid) != 1){
            inform << "Thread not available!?! " << std::hex << tid << ENDL;
        }
        assert(threadseq.count(tid) == 1 && 
          "thread must be added with AddThread method");
        uint32_t ret = threadseq[tid];
        UnLock();
        return ret;
    }

    uint32_t GetImageSequence(image_key_t iid){
        ReadLock();
        assert(imageseq.count(iid) == 1 && 
          "image must be added with AddImage method");
        uint32_t ret = imageseq[iid];
        UnLock();
        return ret;
    }

    void FinishThread(thread_key_t tid){
        WriteLock();
        assert(donethreads.count(tid) == 0 && 
          "Finishing a thread that has already been finished");
        donethreads.insert(tid);
        UnLock();
    }

    bool ThreadLives(thread_key_t tid){
        ReadLock();
        if (allthreads.count(tid) == 0){
            UnLock();
            return false;
        }
        if (donethreads.count(tid) > 0){
            UnLock();
            return false;
        }
        UnLock();
        return true;
    }

    // Adds tid to threads to be tracked
    // If there are images initialized, creates initial data for each
    // No pre-conditions
    virtual void AddThread(thread_key_t tid){
        WriteLock();

        // If it's been initialized before, just return
        if(allthreads.count(tid) > 0) {
            UnLock();
            return;
        }

        if(threadseq.count(tid) == 0) {
            threadseq[tid] = currentthreadseq++;
        }

        // Setup data for any previously initialized images
        for (std::set<image_key_t>::iterator iit = allimages.begin(); iit !=
          allimages.end(); iit++){

            // This image must have been initialized
            // The thread must have not
            // There must have been some other thread that initialized this
            // image
            assert(datamap[(*iit)].size() > 0);
            assert(datamap[(*iit)].count(tid) == 0);
            assert(allthreads.size() > 0);

            std::set<thread_key_t>::iterator tit = allthreads.begin();

            // Generate thread data for this image using some other thread's
            // data as a template
            datamap[*iit][tid] = datagen(datamap[*iit][*tit], 
              DataManagerType_Thread, *iit, tid, firstimage);
            // initialize the thread hashtable data for this image
            SetThreadData((*iit), tid, DataManagerType_Thread);
        }
        allthreads.insert(tid);
        UnLock();
    }

    void AddThread(){
        AddThread(pthread_self());
    }

    // Sets time (units in microseconds)
    virtual void SetTimer(image_key_t iid, uint32_t idx){
        double t;
        ptimer(&t);

        WriteLock();
        if (timers.count(iid) == 0){
            timers[iid] = DataMap<uint32_t, double>();
        }
        assert(timers.count(iid) == 1);
        timers[iid][idx] = t;
        UnLock();
    }

    virtual double GetTimer(image_key_t iid, uint32_t idx){
        ReadLock();
        assert(timers.count(iid) == 1 && "Timers not created for this image");
        assert(timers[iid].count(idx) == 1);
        double t = timers[iid][idx];
        UnLock();
        return t;
    }

    // Add an image
    // The calling thread may or not have been initialized
    // This image must not have been added before
    virtual image_key_t AddImage(T data, ThreadData* t, image_key_t iid){

        ReadLock();
        assert(allimages.count(iid) == 0 && "Image has already been added");
        UnLock();

        // First initialize the thread (calls WriteLock())
        thread_key_t tid = pthread_self();
        AddThread(tid);

        WriteLock();
        // Initialize basic image data
        imageseq[iid] = currentimageseq++;
        allimages.insert(iid);
        assert(allimages.count(iid) == 1);
        datamap[iid] = DataMap<thread_key_t, T>();
        if (firstimage == 0)
            firstimage = iid;

        // Connect thread data to thread hashtable
        assert(threaddata.count(iid) == 0);
        threaddata[iid] = t;

        // create data for every thread
        for (std::set<thread_key_t>::iterator it = allthreads.begin(); it !=
          allthreads.end(); it++){
            uint32_t type = DataManagerType_Thread;
            if(*it == tid)
                type = DataManagerType_Image;

            datamap[iid][(*it)] = datagen(data, type, iid, (*it), firstimage);
            SetThreadData(iid, *it, type);
        }


//        uint64_t dataloc = SetThreadData(iid, tid, DataManagerType_Image);
/*
        // FIXME
        // This is dubious, gives all threads the same buffer to work with
        // Prevents segfaults when threads aren't initialized properly
        // i.e. a thread exists before this library is loaded and
        // then finds its way into instrumented code.
        // Instrumented code assumes threads have been initialized.
        // This means the first thread created will get data for
        // any other threads that escape initialization
        // Also could create race conditions with multiple threads using the
        // same buffer?
        if (allthreads.size() == 1){
            for (uint32_t i = 0; i < ThreadHashMod + 1; i++){
                t[i].data = dataloc;
            }
        }
*/
        UnLock();
        return iid;
    }
    // Return data for any image and this thread.
    // Probably best used when only one image exists.
    virtual T GetData(){
        // This GetData calls ReadLock()
        T retVal = GetData(pthread_self());
        return retVal;
    }

    T GetData(thread_key_t tid){
        ReadLock();
        std::set<image_key_t>::iterator iit = allimages.begin();
        assert(iit != allimages.end());
        UnLock();
        // This GetData calls ReadLock()
        T retVal = GetData(*iit, tid);
        return retVal;
    }

    // Lookup data
    // The image must have been initialized
    // The thread might have escaped initialization if it was created before
    // this library was loaded
    virtual T GetData(image_key_t iid, thread_key_t tid){
        ReadLock();
        if (datamap.count(iid) != 1){
            inform << "About to fail iid check with " << std::dec <<
              datamap.count(iid) << ENDL;
        }
        assert(datamap.count(iid) == 1 && 
          "Attempting to look up data for uninitialized image");

        if(datamap[iid].count(tid) != 1) {
            UnLock();
            AddThread(tid);
            ReadLock();
        }
        T retVal = datamap[iid][tid];
        UnLock();
        return retVal;
    }

    virtual uint32_t CountThreads(){
        ReadLock();
        uint32_t ret = allthreads.size();
        UnLock();
        return ret;
    }
    virtual uint32_t CountImages(){
        ReadLock();
        uint32_t ret = allimages.size();
        UnLock();
        return ret;
    }
};

// Premise: There is a buffer V and data T
//   T is managed by a DataManager
//   Each element in buffer V is associated with a T
//   Client code might want to access T for all elements in a buffer, e.g.
//   for item in Buffer:
//     DataManager->GetData(image_key(item), tid)
//   which involves many map lookups via GetData
//
// This class attempts to access all the data that will be needed for a filled
// buffer in the most efficient way possible by recognizing that many of the
// image_keys for sequential items will be the same, collecting all the items
// at once and storing them in an array.
//    T stats[tid][buffer index]
//
// AddThread: increases size of stats to hold new threads data
// AddImage: increments image count... not really important
// Refresh: updates stats[tid] with data for input buffer
// GetBufferStats: returns current stats[tid]
//
template <class T, class V> class FastData {
private:
    DataManager<T>* alldata;
    void (*dataid)(V, image_key_t*);
    uint32_t capacity;
    uint32_t threadcount;
    uint32_t imagecount;
    T** stats;
    // No STL containers and stats is indexed by thread...just a regular lock
    // should suffice
    pthread_mutex_t lock;

    void Lock(){ pthread_mutex_lock(&lock); }
    void UnLock(){ pthread_mutex_unlock(&lock); }

public:
    // Must be called while allData has been initialized with only a single
    // image and thread
    // @param di(buffer, id): sets id appropriately for the current dereference
    // of buffer
    // @param cap: maximum size of a V
    FastData(void (*di)(V, image_key_t*), DataManager<T>* all, uint32_t cap)
        : alldata(all), dataid(di), capacity(cap), threadcount(1), imagecount(0) {

        assert(alldata->CountThreads() == 1);
        assert(alldata->CountImages() == 1);
        assert(alldata->GetThreadSequence(pthread_self()) == 0);

        stats = new T*[threadcount];
        stats[0] = new T[capacity];
        T dat = alldata->GetData();
        for (uint32_t i = 0; i < capacity; i++){
            stats[0][i] = dat;
        }

        pthread_mutex_init(&lock, NULL);
    }

    virtual ~FastData(){
        if (stats){
            for (uint32_t i = 0; i < threadcount; i++){
                delete[] stats[i];
            }
            delete[] stats;
        }
    }

    // tid must have already been added to alldata
    // Expands stats to hold new thread data
    // If this is the only image, it also pulls data from allData
    virtual void AddThread(thread_key_t tid){
        Lock();
        uint32_t tid_index = alldata->GetThreadSequence(tid);
        uint32_t newsize = tid_index+1 > threadcount ? tid_index+1 : threadcount;

        // Grow stats and copy old data if necessary
        // Also initialize stats for any other threads which are implied to exist
        if(newsize > threadcount) {
            T** tmp = new T*[newsize];
            for (uint32_t i = 0; i < threadcount; ++i){
                tmp[i] = stats[i];
            }
            delete[] stats;
            stats = tmp;

            // initialize any new data, zeroing out any new data not for this thread
            for(uint32_t i = threadcount; i < newsize; ++i){
                stats[i] = new T[capacity];
                if(i != tid_index)
                    memset(stats[i], 0, sizeof(T) * capacity);
            }

            threadcount = newsize;
        }


        // if only one image, can't count on it being refreshed later
        if(imagecount == 1) {
            T dat = alldata->GetData(tid);
            for(uint32_t j = 0; j < capacity; ++j){
                stats[tid_index][j] = dat;
            }
        }

        UnLock();
    }

    // image must have already been added to allData
    // Increments image count
    // If first image, initializes stats
    // FIXME, this method can probably be gotten rid of
    virtual void AddImage(){
        Lock();
        imagecount++;
        if (imagecount == 1){
            assert(threadcount == 1);
            assert(imagecount == alldata->CountImages());
            assert(threadcount == alldata->CountThreads());
            for (uint32_t j = 0; j < capacity; j++){
                stats[0][j] = alldata->GetData();
            }
        }
        UnLock();
    }

    // synchronize this threads entry in stats with first num ids taken from
    // buffer using dataid
    virtual void Refresh(V buffer, uint32_t num, thread_key_t tid){
        debug(assert(imagecount > 0));
        debug(assert(threadcount > 0));
        debug(assert(num <= capacity));

        uint32_t threadseq = alldata->GetThreadSequence(tid);
        if(threadseq >= threadcount) {
            AddThread(tid);
        }
        assert(threadseq < threadcount);

        // If there's only one image, stats must already hold correct data
        if (imagecount == 1){
            return;
        }

        image_key_t i;
        image_key_t ci = 0;
        T di = NULL;

        // j = bufferidx
        // i = dataid at bufferidx
        // ci = current valid i
        // di = SimulationStats* for current thread,image
        for (uint32_t j = 0; j < num; j++, buffer++){

            dataid(buffer, &i);

            if (i == 0){
                if (alldata->CountThreads() > 1){
                    continue;
                }
                assert(false && "the only way blank buffer entries should exist is when threads get signal-interrupted mid-block");
            }

            // If not the same image as last entry, look up the data
            if (i != ci){
                ci = i;
                di = alldata->GetData(i, tid);
            }
            stats[threadseq][j] = di;

            debug(assert(stats[threadseq][j]));
        }
    };

    virtual T* GetBufferStats(thread_key_t tid){
        assert(imagecount > 0);
        assert(threadcount > 0);

        uint32_t threadseq = alldata->GetThreadSequence(tid);
        assert(threadseq < threadcount);

        return stats[threadseq];
    }

    uint32_t GetCapacity() {
        return capacity;
    }
};
#endif // _DataManager_hpp_
