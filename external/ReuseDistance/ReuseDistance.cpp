/* 
 * This file is part of the ReuseDistance tool.
 * 
 * Copyright (c) 2012, University of California Regents
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

#include <ReuseDistance.hpp>

using namespace std;

//#define REUSE_DEBUG
#ifdef REUSE_DEBUG
#define debug_assert(...) assert(__VA_ARGS__)
#else
#define debug_assert(...)
#endif

#define REUSE_PROFILE
#ifdef REUSE_PROFILE

#define CLOCK_RATE_HZ 1800000000
#define PROCESS_TREE_TIME 0
#define PROCESS_TIME 1
#define PROCESS_UPDATE_TIME 2
#define PROCESS_SLOT_TIME 3
#define ADD_SLOT_TIME 4
#define NEW_SLOT_TIME 5
#define FIND_SLOT_TIME 6
//#define REUSE_TIME 1

static double timerValues[7] = {0, 0, 0, 0, 0, 0, 0};
static string timerNames[7] = {"Find Pos Tree", "Total Process", "Process Update", "Process Slot", "Add Slot", "New Slot", "Old Slot"};

inline uint64_t read_timestamp_counter() {
    unsigned low, high;
    __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
    return ((unsigned long long)low | (((unsigned long long)high) << 32));
}

//static double diffTime(struct timeval t1, struct timeval t2) {
//    struct timeval diff;
//    if (t2.tv_usec < t1.tv_usec) {
//          diff.tv_usec = 1000000 + t2.tv_usec - t1.tv_usec;
//          diff.tv_sec = t2.tv_usec - t1.tv_sec - 1;
//    } else {
//          diff.tv_usec = t2.tv_usec - t1.tv_usec;
//          diff.tv_sec = t2.tv_usec - t1.tv_sec;
//    }
//
//    double time = (double)diff.tv_sec + (diff.tv_usec / 1000000.0);
//    return time;
//}

#define profile_declare(__timer) uint64_t t##__timer##_s, t##__timer##_e
#define profile_start(__timer) t##__timer##_s = read_timestamp_counter()
#define profile_end(__timer) t##__timer##_e = read_timestamp_counter(); \
                             timerValues[__timer] += (double)((t##__timer##_e - t##__timer##_s) / (double)(CLOCK_RATE_HZ))
#define profile_report(__timer) printf("REUSE PROFILER: Time in %s = %f\n", \
                             timerNames[__timer].c_str(), timerValues[__timer]);

#else  // not REUSE_PROFILE

#define profile_declare(...)
#define profile_start(...)
#define profile_end(...)

#endif  // if REUSE_PROFILE

inline uint64_t uint64abs(uint64_t a){
    if (a < 0x8000000000000000L){
        return a;
    } else {
        return 0 - a;
    }
}

// ReuseDistance class

void ReuseDistance::Init(uint64_t w, uint64_t b){
    capacity = w;
    binindividual = b;
    maxtracking = capacity;

    current = 0;
    sequence = 1;
    //window = newtree234();
    window = new list<ReuseEntry*>();
    assert(window);
    mwindow.clear();
// TODO: Does adding reserve help improve hash table?
    mwindow.reserve(1000000);
//    LRUDistanceAnalyzer::Init(); // Does this need a protection mechanism?
    assert(ReuseDistance::Infinity == NULL && "NULL is non-zero!?");
}

ReuseStats* ReuseDistance::GetStats(uint64_t id, bool gen){
    ReuseStats* s = stats[id];
    if (s == NULL && gen){
        s = new ReuseStats(id, binindividual, capacity, ReuseDistance::Infinity);
        stats[id] = s;
    }
    return s;
}

//uint64_t* ReuseDistance::GetPINStats(uint64_t id, bool gen)
//{
//    uint64_t* s = PINReuseStats[id];
//    if (s == NULL && gen){
//        s = new uint64_t[BIN_SIZE]; //ReuseStats(id, binindividual, capacity, ReuseDistance::Infinity);
//        PINReuseStats[id] = s;
//      
//       for(int i=0;i<BIN_SIZE;i++)
//           s[i]=0;
//      
//    }
//    return s;
//}


ReuseDistance::ReuseDistance(uint64_t w, uint64_t b){
    ReuseDistance::Init(w, b);
}

ReuseDistance::ReuseDistance(uint64_t w){
    ReuseDistance::Init(w, DefaultBinIndividual);
}

ReuseDistance::ReuseDistance(ReuseDistance* r){
    ReuseDistance::Init(r->capacity, r->binindividual);
}

ReuseDistance::~ReuseDistance(){

    for (reuse_map_type<uint64_t, ReuseStats*>::const_iterator it = stats.begin(); it != stats.end(); it++){
        uint64_t id = it->first;
        delete stats[id];
    }    

    //debug_assert(current == count234(window));
    debug_assert(current == window->size());
    while (current){
        //delete (ReuseEntry*)delpos234(window, 0);
        //back is the same as delete index 0
        window->pop_back();
        current--;
    }
    //freetree234(window); //CAUTION: Dangerous practice!! :( 
    delete window;
    window = nullptr;

}

void ReuseDistance::Print(ostream& f, bool annotate){
    //LRUDistanceAnalyzer::OutputResults();
    //uint64_t BinStats[BIN_SIZE];
    //uint64_t idTotals[PINReuseStats.size()];
    //int tot = 0;
    //for(int i=0;i<BIN_SIZE;i++)
    //   BinStats[i]=0;
    //for(int i=0; i<PINReuseStats.size();i++)
    //    idTotals[i] = 0;
    //int index = 0;
    vector <uint64_t> keys;
    for(reuse_map_type<uint64_t,ReuseStats*>::const_iterator it=stats.begin(); it!=stats.end();it++){
        keys.push_back(it->first);
    }
    sort(keys.begin(), keys.end());

//        int tempTotal = 0;
//        for(int i=0;i<BIN_SIZE;i++)
//        {
//            if(it->second[i])
//            {
//               tot+=it->second[i];
//               tempTotal+=it->second[i];
//               BinStats[i]+=it->second[i];
//            }
//        }
//        idTotals[index] = tempTotal;
//        index++;
//    }    

    uint64_t tot = 0, mis = 0;
    for (vector<uint64_t>::const_iterator it = keys.begin(); it != keys.end(); it++) {
        uint64_t id = (*it);
        ReuseStats* r= (ReuseStats*)stats[id];
        tot += r->GetAccessCount();
        mis += r->GetMissCount();
    }

    if (annotate){
        ReuseDistance::PrintFormat(f);
        ReuseStats::PrintFormat(f);

    }
    f << Describe() << "STATS"
      << TAB << dec << capacity
      << TAB << binindividual
      << TAB << maxtracking
      << TAB << keys.size()
      << TAB << tot 
      << TAB << mis //We do not seem to record misses anymore
      << ENDL;

    for (vector<uint64_t>::const_iterator it = keys.begin(); it != keys.end(); it++) {

        uint64_t id = (*it);
        ReuseStats* r= (ReuseStats*)stats[id];
    f << TAB << Describe() << "ID"
      << TAB << dec << id
      << TAB << r->GetAccessCount()
      << TAB << r->GetMissCount()
      << ENDL;

      r->Print(f);
    }

//    index = 0;
    //for(reuse_map_type<uint64_t,uint64_t*>::const_iterator it=PINReuseStats.begin(); it!=PINReuseStats.end();it++)    
    //{
    //    f << "\tREUSEID\t" << hex << it->first << "\t" << dec << idTotals[index] << "\t" << "n/a"<< "\n";
    //    for(int i=0;i<BIN_SIZE;i++)
    //    {
    //        if(it->second[i])
    //        {
    //           f << "\t\t" << ((int)(pow(2,(i-1))+1)) << "\t" << ((int)(pow(2,i))) << "\t" << it->second[i] << "\n";
    //        }
    //    }
    //    index++;
    //}
   /* 
    f<<"\n\n";
    for(int i=0;i<BIN_SIZE;i++)
    {
        if(BinStats[i])
        f<<"\n\t Bin: "<<i<<dec<<" Hits: "<<BinStats[i];
    }
    */

    profile_report(PROCESS_TREE_TIME);
//    profile_report(PROCESS_UPDATE_TIME);
    profile_report(NEW_SLOT_TIME);
    profile_report(FIND_SLOT_TIME);
    profile_report(ADD_SLOT_TIME);
    profile_report(PROCESS_SLOT_TIME);
    profile_report(PROCESS_TIME);
    return;
    
}

void ReuseDistance::Print(bool annotate){
    Print(std::cout, annotate);
}

void ReuseDistance::PrintFormat(ostream& f){
    f << "# "
      << Describe() << "STATS"
      << TAB << "<window_size>"
      << TAB << "<bin_indiv>"
      << TAB << "<max_track>"
      << TAB << "<id_count>"
      << TAB << "<tot_access>"
      << TAB << "<tot_miss>"
      << ENDL;

    f << "# "
      << TAB << Describe() << "ID"
      << TAB << "<id>"
      << TAB << "<id_access>"
      << TAB << "<id_miss>"
      << ENDL;
}

/*void ReuseDistance::Process(ReuseEntry& r){
    profile_declare(PROCESS_TREE_TIME);
    profile_declare(PROCESS_TIME);
    //profile_declare(PROCESS_UPDATE_TIME);
    profile_declare(NEW_SLOT_TIME);
    profile_declare(FIND_SLOT_TIME);
    profile_declare(ADD_SLOT_TIME);
    profile_declare(PROCESS_SLOT_TIME);
    profile_start(PROCESS_TIME);
  uint64_t addr = r.address;
//  uint64_t* BBStats= GetPINStats(r.id,true);
//  LRUDistanceAnalyzer::RecordMemAccess((void*)r.address,BBStats);
    uint64_t id = r.id;
    uint64_t mres = mwindow.count(addr);

    ReuseStats* stats = GetStats(id, true);

    int dist = 0;
    ReuseEntry* result;
//    profile_start(PROCESS_UPDATE_TIME);
    if (mres) {
        mres = mwindow[addr];
        ReuseEntry key;
        key.address = addr;
        key.__seq = mres;
        profile_start(PROCESS_TREE_TIME);
        result = findrelpos234(window, &key, &dist);
        profile_end(PROCESS_TREE_TIME);

        debug_assert(result);

        if (capacity != ReuseDistance::Infinity) {
            debug_assert(current - dist <= capacity);
        }
        stats->Update(current - dist);
    } else {
        stats->Update(ReuseDistance::Infinity);
    }
//    profile_end(PROCESS_UPDATE_TIME);

    profile_start(PROCESS_SLOT_TIME);
    ReuseEntry* slot = NULL;
    if (mres || (capacity != ReuseDistance::Infinity && current >= capacity)) {
//        profile_start(PROCESS_TREE_TIME);
        profile_start(FIND_SLOT_TIME);
        slot = (ReuseEntry*)delpos234(window, dist);
        profile_end(FIND_SLOT_TIME);
//        profile_end(PROCESS_TREE_TIME);
        debug_assert(mwindow[slot->address]);
        mwindow.erase(slot->address);
        debug_assert(count234(window) == mwindow.size());
    } else {
        slot = new ReuseEntry();
        current++;
    }

        profile_start(NEW_SLOT_TIME);
    mwindow[addr] = sequence;
        profile_end(NEW_SLOT_TIME);

    slot->__seq = sequence;
    slot->address = addr;
//    profile_start(PROCESS_TREE_TIME);
    profile_start(ADD_SLOT_TIME);
    add234(window, slot);
    profile_end(ADD_SLOT_TIME);
    profile_end(PROCESS_SLOT_TIME);

    debug_assert(count234(window) == mwindow.size());
//    profile_end(PROCESS_TREE_TIME);
    debug_assert(mwindow.size() <= current);
    sequence++;
    profile_end(PROCESS_TIME);
   return;
}*/

void ReuseDistance::Process(ReuseEntry& r){
  uint64_t addr = r.address;
//  uint64_t* BBStats= GetPINStats(r.id,true);
//  LRUDistanceAnalyzer::RecordMemAccess((void*)r.address,BBStats);
    uint64_t id = r.id;
    uint64_t mres = mwindow.count(addr);

    ReuseStats* stats = GetStats(id, true);

    int dist = 0;
    ReuseEntry* result;
    ReuseEntry* slot = NULL;
    if (mres) {
        mres = mwindow[addr];

        //result = findrelpos234(window, &key, &dist);
        list<ReuseEntry*>::iterator lastInstanceItr;
        for (auto it = window->begin(); it!=window->end();it++){
            if ((*it)->__seq == mres) {
                lastInstanceItr = it;
                break;
            }
        }

        //it==window.begin() is a dist of 1
        dist = distance(window->begin(), lastInstanceItr) + 1;

        window->erase(lastInstanceItr);
        //current--;

        result = *lastInstanceItr;
        debug_assert(result);
        mwindow[addr] = sequence;
        result->__seq = sequence;
        result->address = addr;

        if (capacity != ReuseDistance::Infinity) {
            //debug_assert(current - dist <= capacity);
            debug_assert(dist <= capacity);
        }
        //stats->Update(current - dist);
        stats->Update(dist);

        window->push_front(result);
        //current++;
    } else {
        slot = new ReuseEntry();
        mwindow[addr] = sequence;
        slot->__seq = sequence;
        slot->address = addr;
        window->push_front(slot);
        current++;

        stats->Update(ReuseDistance::Infinity);

        //change to capacity != ReuseDistance::Infinity && current >= capacity
        if (capacity != ReuseDistance::Infinity && current >= capacity) {
            auto oldestSeqItr = window->end()--;
            mwindow.erase((*oldestSeqItr)->address);
            window->erase(oldestSeqItr);
            current--;
        }
    }

    debug_assert(window->size() == mwindow.size());
    debug_assert(mwindow.size() <= current);
    sequence++;
    return;
}

void ReuseDistance::Process(ReuseEntry* rs, uint64_t count){
    for (uint32_t i = 0; i < count; i++){
        Process(rs[i]);
       // LRUDistanceAnalyzer::RecordMemAccess((void *)rs[i].address);
    }
}

void ReuseDistance::Process(vector<ReuseEntry> rs){
    for (vector<ReuseEntry>::const_iterator it = rs.begin(); it != rs.end(); it++){
        ReuseEntry r = *it;
        Process(r);
    //LRUDistanceAnalyzer::RecordMemAccess((void *)r.address);       
    }
}

void ReuseDistance::Process(vector<ReuseEntry*> rs){
    for (vector<ReuseEntry*>::const_iterator it = rs.begin(); it != rs.end(); it++){
        ReuseEntry* r = *it;
        Process((*r));
       // LRUDistanceAnalyzer::RecordMemAccess((void *)r->address);
    }
}

ReuseStats* ReuseDistance::GetStats(uint64_t id){
    return GetStats(id, false);
}

void ReuseDistance::GetIndices(std::vector<uint64_t>& ids){
    assert(ids.size() == 0);
    for (reuse_map_type<uint64_t, ReuseStats*>::const_iterator it = stats.begin(); it != stats.end(); it++){
        uint64_t id = it->first;
        ids.push_back(id);
    }
}

void ReuseDistance::GetActiveAddresses(std::vector<uint64_t>& addrs){
    assert(addrs.size() == 0);
    //debug_assert(current == count234(window));
    debug_assert(current == window->size());

    /*for (int i = 0; i < current; i++){
        ReuseEntry* r = index234(window, i);
        addrs.push_back(r->address);
    }*/
    for (auto it = window->begin();it != window->end();it++){
        ReuseEntry* r = *it;
        addrs.push_back(r->address);
    }
}

void ReuseDistance::SkipAddresses(uint64_t amount){
    sequence += amount;

    // flush the window completely
    while (current){
        //delete delpos234(window, 0);
        delete window->back();
        window->pop_back();
        current--;
    }
    mwindow.clear();
    assert(mwindow.size() == 0);
    assert(window->size() == 0);
}

// ReuseStats class

// this should be fast as possible. This code is from http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
static const uint64_t b[] = {0x2L, 0xCL, 0xF0L, 0xFF00L, 0xFFFF0000L, 0xFFFFFFFF00000000L};
static const uint32_t S[] = {1, 2, 4, 8, 16, 32};
inline uint64_t ShaveBitsPwr2(uint64_t val){
    val -= 1;
    register uint64_t r = 0; // result of log2(v) will go here
    for (int32_t i = 5; i >= 0; i--){
        if (val & b[i]){
            val = val >> S[i];
            r |= S[i];
        }
    }
    return ( (uint64_t) 2 << r);
}

uint64_t ReuseStats::GetBin(uint64_t value){
    // not a valid value
    if (value == invalid){
        return invalid;
    }
    // outside of tracking window, also invalid
    else if (maxtracking != ReuseDistance::Infinity && value > maxtracking){
        return invalid;
    }
    // valid but not tracked individually
    else if (binindividual != ReuseDistance::Infinity && value > binindividual){
        return ShaveBitsPwr2(value);
    }
    // valid and tracked individually
    return value;
}

void ReuseStats::Update(uint64_t dist){
    distcounts[GetBin(dist)] += 1;
    accesses++;
}

uint64_t ReuseStats::GetMissCount(){
    return distcounts[invalid];
}

//void ReuseStats::Print(ostream& f, reuse_map_type<uint64_t,uint64_t>& BinTotal,
//  bool annotate){
void ReuseStats::Print(ostream& f,  bool annotate){
    vector<uint64_t> keys;
    GetSortedDistances(keys);

    if (annotate){
        ReuseStats::PrintFormat(f);
    }
    int iter_count=0;
    for (vector<uint64_t>::const_iterator it = keys.begin(); it != keys.end(); it++,iter_count++){

        uint64_t d = *it;
        if (d == invalid) 
        continue;

        debug_assert(distcounts.count(d) > 0);
        uint32_t cnt = distcounts[d];

        debug_assert(cnt > 0);
        if (cnt > 0){
            uint64_t p = d / 2 + 1;
            if (binindividual == ReuseDistance::Infinity || d <= binindividual){
                p = d;
            }
            f << TAB
              << TAB << dec << p
              << TAB << d
              << TAB << cnt
              << ENDL;
              
   
              //if(BinTotal.count(p))
              //     BinTotal[p]+=cnt;
              // else
              //  BinTotal[p]=cnt;
          
        }
    }
}

void ReuseStats::PrintFormat(ostream& f){
    f << "# "
      << TAB 
      << TAB << "<bin_lower_bound>"
      << TAB << "<bin_upper_bound>"
      << TAB << "<bin_count>"
      << ENDL;
}

void ReuseStats::GetSortedDistances(vector<uint64_t>& dkeys){
    assert(dkeys.size() == 0 && "dkeys must be an empty vector");
    for (reuse_map_type<uint64_t, uint64_t>::const_iterator it = distcounts.begin(); it != distcounts.end(); it++){
        uint64_t d = it->first;
        dkeys.push_back(d);
    }
    sort(dkeys.begin(), dkeys.end());    
}

uint64_t ReuseStats::GetMaximumDistance(){
    uint64_t max = 0;
    for (reuse_map_type<uint64_t, uint64_t>::const_iterator it = distcounts.begin(); it != distcounts.end(); it++){
        uint64_t d = it->first;
        if (d > max){
            max = d;
        }
    }
    return max;
}

uint64_t ReuseStats::CountDistance(uint64_t d){
    if (distcounts.count(d) == 0){
        return 0;
    }
    return distcounts[d];
}

uint64_t ReuseStats::GetAccessCount(){
    return accesses;
}

void SpatialLocality::Init(uint64_t size, uint64_t bin, uint64_t max){
    sequence = 1;
    capacity = size;
    binindividual = bin;
    maxtracking = max;

    assert(capacity > 0 && capacity != ReuseDistance::Infinity && "window size must be a finite, positive value");
    assert((maxtracking == INFINITY_REUSE || maxtracking >= binindividual) && "max tracking must be at least as large as individual binning");
}

ReuseStats* SpatialLocality::GetStats(uint64_t id, bool gen){
    ReuseStats* s = stats[id];
    if (s == NULL && gen){
        s = new ReuseStats(id, binindividual, maxtracking, SpatialLocality::Invalid);
        stats[id] = s;
    }
    return s;
}

void SpatialLocality::GetActiveAddresses(std::vector<uint64_t>& addrs){
    assert(addrs.size() == 0);

    for (map<uint64_t, uint64_t>::const_iterator it = awindow.begin(); it != awindow.end(); it++){
        uint64_t addr = it->first;
        addrs.push_back(addr);
    }
}

void SpatialLocality::Process(ReuseEntry& r){
    uint64_t addr = r.address;
    uint64_t id = r.id;
    ReuseStats* stats = GetStats(id, true);
    debug_assert(stats);

    // find the address closest to addr
    uint64_t bestdiff = SpatialLocality::Invalid;

    if (awindow.size() > 0){

        map<uint64_t, uint64_t>::const_iterator it = awindow.upper_bound(addr);
        if (it == awindow.end()){
            it--;
        }

        // only need to check the values immediately equal, >, and < than addr
        for (uint32_t i = 0; i < 3; i++, it--){ 
            uint64_t cur = it->first;
            //uint64_t seq = it->second; what is this used for?

            uint64_t diff = uint64abs(cur - addr);
           if (diff < bestdiff && diff > 0){ //Fix bug with 0 bins
                bestdiff = diff;
            }

            if (it == awindow.begin()){
                break;
            }
        }
    }
    stats->Update(bestdiff);

    // remove the oldest address in the window
    if (swindow.size() > capacity){
        uint64_t a = swindow.front();
        swindow.pop_front();

        uint64_t v = awindow[a];
        if (v > 1){
            awindow[a] = v - 1;
        } else {
            awindow.erase(a);
        }
    }

    // insert the newest address into the window
    awindow[addr]++;
    swindow.push_back(addr);
}

void SpatialLocality::SkipAddresses(uint64_t amount){

    // flush the window completely
    while (swindow.size()){
        uint64_t a = swindow.front();
        swindow.pop_front();

        uint64_t v = awindow[a];
        if (v > 1){
            awindow[a] = v - 1;
        } else {
            awindow.erase(a);
        }
    }

    assert(awindow.size() == 0);
    assert(swindow.size() == 0);
}

void SpatialLocality::Print(ostream& f, bool annotate){

    reuse_map_type<uint64_t,uint64_t> BinTotal;
     
    vector<uint64_t> keys;
    for (reuse_map_type<uint64_t, ReuseStats*>::const_iterator it = stats.begin(); it != stats.end(); it++){
        keys.push_back(it->first);
    }
    sort(keys.begin(), keys.end());

    uint64_t tot = 0, mis = 0;
    for (vector<uint64_t>::const_iterator it = keys.begin(); it != keys.end(); it++){
        uint64_t id = (*it);
        ReuseStats* r = (ReuseStats*)stats[id];
        tot += r->GetAccessCount();
        mis += r->GetMissCount();
    }

    if (annotate){
        ReuseDistance::PrintFormat(f);
        ReuseStats::PrintFormat(f);
    }

    f << Describe() << "STATS"
      << TAB << dec << capacity
      << TAB << binindividual
      << TAB << maxtracking
      << TAB << keys.size()
      << TAB << tot
      << TAB << mis
      << ENDL;

    for (vector<uint64_t>::const_iterator it = keys.begin(); it != keys.end(); it++){
        uint64_t id = (*it);
        ReuseStats* r = (ReuseStats*)stats[id];

        f << TAB << Describe() << "ID"
          << TAB << hex << id << dec
          << TAB << r->GetAccessCount()
          << TAB << r->GetMissCount()
          << ENDL;

        //r->Print(f,BinTotal);
        r->Print(f);
    }
   /* 
    vector<uint64_t> BinTotalKeys;
    for (reuse_map_type<uint64_t, uint64_t>::const_iterator it = BinTotal.begin(); it != BinTotal.end(); it++){
        BinTotalKeys.push_back(it->first);
    }
    sort(BinTotalKeys.begin(), BinTotalKeys.end());
    uint64_t Total=0;
    for (vector<uint64_t>::const_iterator it = BinTotalKeys.begin(); it != BinTotalKeys.end(); it++)
    {
        uint64_t id = (*it);
        uint64_t range=( (2*(id-1)) - id  );
        if(id==0)
            range=0;
    f<<"\n\t Bin: "<<id<<" Range: "<<range<<" Count: "<<BinTotal[id];
    Total+=BinTotal[id];
    }
    f<<"\n\t Total Accesses: "<<Total;
    f<<endl;
     */ 
    
}


