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

inline uint64_t uint64abs(uint64_t a){
    if (a < 0x8000000000000000L){
        return a;
    } else {
        return 0 - a;
    }
}

// ReuseDistance class

const uint64_t ReuseDistance::Infinity = INFINITY_REUSE;
const uint64_t ReuseDistance::DefaultBinIndividual = 32;

void ReuseDistance::Init(uint64_t w, uint64_t b){
    capacity = w;
    binindividual = b;
    initialWarning = false;

    sequence = 1;
    window = new list<ReuseEntry*>();
    assert(window);
    mwindow.clear();
// TODO: Does adding reserve help improve hash table?
    mwindow.reserve(1000000);
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
    for (reuse_map_type<uint64_t, ReuseStats*>::const_iterator 
      it = stats.begin(); it != stats.end(); it++){
        uint64_t id = it->first;
        delete stats[id];
    }    

    for (auto it = window->begin();it != window->end();it++){
        delete *it;
    }
    window->clear();
    delete window;
    window = nullptr;
}

void ReuseDistance::Print(ostream& f, bool annotate){
    // vector of all the memops that have a distance associated with them
    vector <uint64_t> keys;
    for(reuse_map_type<uint64_t,ReuseStats*>::const_iterator it=stats.begin(); 
      it!=stats.end();it++){
        keys.push_back(it->first);
    }
    // sort the memops
    sort(keys.begin(), keys.end());

    uint64_t tot = 0, mis = 0;
    for (vector<uint64_t>::const_iterator it = keys.begin(); it != keys.end(); 
      it++) {
        // id is memop
        uint64_t id = (*it);
        ReuseStats* r= (ReuseStats*)stats[id];
        tot += r->GetAccessCount();
        mis += r->GetMissCount();
    }

    // done once at the begining of the file
    if (annotate){
        ReuseDistance::PrintFormat(f);
        ReuseStats::PrintFormat(f);
    }
    // Print the overall information
    // Describe Returns REUSEDISTANCE 
    f << Describe() << "STATS"
      << TAB << dec << capacity
      << TAB << binindividual
      << TAB << keys.size()
      << TAB << tot 
      << TAB << mis
      << ENDL;

    for (vector<uint64_t>::const_iterator it = keys.begin(); 
      it != keys.end(); it++) {
        // memop
        uint64_t id = (*it);
        ReuseStats* r= (ReuseStats*)stats[id];
        f << TAB << Describe() << "ID"
          << TAB << hex << id
          << TAB << dec << r->GetAccessCount()
          << TAB << r->GetMissCount()
          << ENDL;

          r->Print(f);
    }
    return;
    
}

void ReuseDistance::Print(bool annotate){
    Print(cout, annotate);
}

void ReuseDistance::PrintFormat(ostream& f){
    f << "# "
      << Describe() << "STATS"
      << TAB << "<window_size>"
      << TAB << "<bin_indiv>"
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

void ReuseDistance::Process(ReuseEntry& r){
    // the address
    uint64_t addr = r.address;
    // the memop
    uint64_t id = r.id;
    // after this call mres is either 0 for not present or 1 for present
    uint64_t mres = mwindow.count(addr);
    // get the Stats associated with this memop, and generate it if we haven't
    // seen this memop yet
    ReuseStats* statsForMemop = GetStats(id, true);
    int dist = 0;
    ReuseEntry* result;
    if (mres) { // if we have the address present
        // at this point mres is now the sequence number of the last time we
        // saw addr
        mres = mwindow[addr]; 

        list<ReuseEntry*>::iterator lastInstanceItr;
        // find the node in our list where we last saw this address
        for (auto it = window->begin(); it!=window->end();it++){
            if ((*it)->__seq == mres) {
                lastInstanceItr = it;
                break;
            }
        }
        //it==window.begin() is a dist of 1
        dist = distance(window->begin(), lastInstanceItr) + 1;
        result = *lastInstanceItr;

        if (capacity != ReuseDistance::Infinity) {
            debug_assert(dist <= capacity);
        }
        // update the current memop with the distance to the last time
        // this address was seen
        statsForMemop->Update(dist);
        

        // erase from the window
        window->erase(lastInstanceItr);

        debug_assert(result);

        // update our dictionary with the new sequence number
        mwindow[addr] = sequence;

        // populate our data structure
        result->__seq = sequence;
        result->address = addr;

        // and add to the front of the list but back in the sense that as you
        // move forward in the list, sequences get smaller and smaller
        window->push_front(result);


    } else {
        // update current memop with a miss
        statsForMemop->Miss();

        // gonna need to make a new ReuseEntry
        result = new ReuseEntry();

        // add new address and sequence to our dictionary
        mwindow[addr] = sequence;

        // populate our data structure
        result->__seq = sequence;
        result->address = addr;

        // add to the front of our list
        window->push_front(result);

        // if we go over capacity remove the oldest item
        // TODO possible optimization by not deleting if we move stuff around
        if (capacity != ReuseDistance::Infinity && window->size() > capacity) {

            // get the smallest sequence we have
            ReuseEntry* oldestSeq = window->back();
            // remove it from list
            window->pop_back();
            // update dictionary
            mwindow.erase(oldestSeq->address);
            // free up memory
            delete oldestSeq;

            // verify these statements remain true
            debug_assert(mwindow[result->__address]);
            debug_assert(window->size() == mwindow.size());
        }
    }

    // verify these statements remain true
    debug_assert(window->size() == mwindow.size());
    // update sequence for the next time the function is called
    sequence++;

    return;
}

void ReuseDistance::Process(ReuseEntry* rs, uint64_t count){
    for (uint32_t i = 0; i < count; i++){
        Process(rs[i]);
    }
}

void ReuseDistance::Process(vector<ReuseEntry> rs){
    for (vector<ReuseEntry>::const_iterator it = rs.begin(); it != rs.end(); it++){
        ReuseEntry r = *it;
        Process(r);
    }
}

void ReuseDistance::Process(vector<ReuseEntry*> rs){
    for (vector<ReuseEntry*>::const_iterator it = rs.begin(); it != rs.end(); it++){
        ReuseEntry* r = *it;
        Process((*r));
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

// SkipAddresses is really only used when we are sampling, when we turn sampling
// off, we flush the buffer. So even in the event of an infinite window, the
// next time we see an address, we are going to report ReuseDistance::Infinity
// (also known as invalid, or Miss or 0)
void ReuseDistance::SkipAddresses(uint64_t amount){
    if (!initialWarning) {
        initialWarning = true;
        fprintf(stderr, 
          "WARNING: Using Sampling can cause inaccurate data reporting\n");
    }
    bool useDefault = false;
    if (binindividual == 1) {
        useDefault = true;
    }
    if((!useDefault && amount < binindividual) || (useDefault && amount < 50)){
        fprintf(stderr, 
          "WARNING: skipped amount %u with window size %u and bin size %u\n", 
          amount, window->size(), binindividual);
    }
    sequence += amount;

    // flush the window completely
    for (auto it = window->begin();it != window->end();it++){
        delete *it;
    }
    window->clear();
    mwindow.clear();
    assert(mwindow.size() == 0);
    assert(window->size() == 0);
}

// ReuseStats class

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

void ReuseStats::Miss() {
    distcounts[invalid] += 1;
    accesses++;
}

uint64_t ReuseStats::GetMissCount(){
    return distcounts[invalid];
}

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

uint64_t ReuseStats::GetAccessCount(){
    return accesses;
}

const uint64_t SpatialLocality::Invalid = INVALID_SPATIAL;
const uint64_t SpatialLocality::DefaultWindowSize = 64;

void SpatialLocality::Init(uint64_t size, uint64_t bin){
    sequence = 1;
    capacity = size;
    binindividual = bin;

    assert(capacity > 0 && capacity != ReuseDistance::Infinity 
      && "window size must be a finite, positive value");
    assert((capacity >= binindividual) 
      && "window size must be at least as large as individual binning");
}

ReuseStats* SpatialLocality::GetStats(uint64_t id, bool gen){
    ReuseStats* s = stats[id];
    if (s == NULL && gen){
        s = new ReuseStats(id, binindividual, capacity, SpatialLocality::Invalid);
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
    sequence++;
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

    sequence += amount;
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


