/**
 * @file
 * @author Michael Laurenzano <michaell@sdsc.edu>
 * @version 0.01
 *
 * @section LICENSE
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
 *
 * @section DESCRIPTION
 *
 * The ReuseDistanceHandler class allows for calculation and statistic tracking
 * for finding memory reuse distances given a stream of memory addresses and
 * ids.
 */

#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <algorithm>
#include <iostream>
#include <ostream>
#include <list>
#include <map>
#include <vector>
#include<math.h>
// unordered_map is faster for many things, use it where sorted map isn't needed
#ifdef HAVE_UNORDERED_MAP
#include <unordered_map>
#define reuse_map_type std::unordered_map
#else
#define reuse_map_type std::map
#endif

#define TAB "\t"
#define ENDL "\n"

#define __seq id

#define INFINITY_REUSE (0)
#define INVALID_SPATIAL (0xFFFFFFFFFFFFFFFFL)

/**
 * @struct ReuseEntry
 *
 * ReuseEntry is used to pass memory addresses into a ReuseDistance.
 *
 * @field id  The unique id of the entity which generated the memory address.
 * Statistics are tracked seperately for each unique id.
 * @field address  A memory address.
 */
struct ReuseEntry {
    uint64_t id;
    uint64_t address;

    bool operator==(const ReuseEntry& rhs) const
    {
        return id == rhs.id
            && address == rhs.address;
    }
};

// this should be fast as possible. This code is from 
// http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
static const uint64_t b[]
  = {0x2L, 0xCL, 0xF0L, 0xFF00L, 0xFFFF0000L, 0xFFFFFFFF00000000L};
static const uint32_t S[] = {1, 2, 4, 8, 16, 32};
extern inline uint64_t ShaveBitsPwr2(uint64_t val) {
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

class ReuseStats;

/**
 * @class ReuseDistance
 *
 * Tracks reuse distances for a memory address stream. Keep track of the 
 * addresses within a specific window of history, whose size can be finite or 
 * infinite. We use a map to keep track of what address are and are
 * not in our List that holds the unique addresses in the reverse order they
 * were visited in. We use this list to count the number of unique addresses
 * from the current address we are processing to the last time it was seen
 * we then update the list so that the unique addresses property and reverse
 * order of last seen addresses property is maintained by deleting the old and
 * adding to the front of list with the new.
 */
class ReuseDistance {
protected:
    // [sequence -> address] A linked list filled with ReuseEntry*, sorted 
    // by access order in descending order
    std::list<ReuseEntry*>* window;

    // a dictionary of addresses to the last sequence they were seen in. If an 
    // address is in window, it should be in mwindow as well as vice versa
    reuse_map_type<uint64_t, uint64_t> mwindow; 

    // store all stats keyed by memop
    reuse_map_type<uint64_t, ReuseStats*> stats;
    
    // used in spatial locality to determine the largest bin we will track
    // anything over capacity will be reported as ReuseDistance::Infinity
    uint64_t capacity; // the max size of our window
    uint64_t sequence; // the number of address we have visited + 1
    // the maximum distance that we keep track of for individual distances
    uint64_t binindividual; 
    bool initialWarning = false;

    void Init(uint64_t w, uint64_t b);
    /*
     * @param id The memop id that the ReuseStats is associated with
     * @param gen Wether or not we are generating a new ReuseStats for this
     * particular memop
     */
    virtual ReuseStats* GetStats(uint64_t id, bool gen);
    virtual const std::string Describe() { return "REUSE"; }

public:
    // TESTING ONLY METHODS
    uint64_t TestGetCapacity() { return capacity; }
    uint64_t TestGetBinIndividual() { return binindividual; }
    // END OF TESTING METHODS
    static const uint64_t DefaultBinIndividual;
    static const uint64_t Infinity;

    /**
     * Contructs a ReuseDistance object.
     *
     * @param w  The maximum window size, or alternatively the maximum 
     * possible reuse distance that this tool will find. No window/distance 
     * limit is imposed if ReuseDistance::Infinity is used, though you could 
     * easily run out of memory.
     * @param b  All distances not greater than b will be tracked individually.
     * All distances are tracked individually if b == ReuseDistance::Infinity. 
     * Beyond individual tracking, distances are tracked in bins whose 
     * boundaries are the powers of two greater than b (and not exeeding w, 
     * of course).
     *
     */
    ReuseDistance(uint64_t w, uint64_t b);

    /**
     * Contructs a ReuseDistance object. Equivalent to calling the other 
     * constructor with b == ReuseDistance::DefaultBinIndividual
     */
    ReuseDistance(uint64_t w);

    /**
     * Contructs a ReuseDistance object equivalent to the given ReuseDistance
     * object
     */
    ReuseDistance(ReuseDistance* r);

    /**
     * Destroys a ReuseDistance object.
     */
    virtual ~ReuseDistance();

    /**
     * Print statistics for this ReuseDistance to an output stream.
     * See also ReuseDistance::PrintFormat
     *
     * @param f  The output stream to print results to.
     * @param annotate  Also print annotations describing the meaning of output
     * fields, preceded by a '#'.
     *
     * @return none
     */
    virtual void Print(std::ostream& f, bool annotate=false);

    /**
     * Print statistics for this ReuseDistance to std::cout.
     *
     * @param annotate  Also print annotations describing the meaning of output
     * fields, preceded by a '#'.
     *
     * @return none
     */
    virtual void Print(bool annotate=false);

    /**
     * Print information about the output format of ReuseDistance or one of its
     * subclasses
     *
     * @param f  The stream to receive the output.
     *
     * @return none
     */
    void PrintFormat(std::ostream& f);

    /**
     * Process a single memory address.
     * Process : This Process method takes in a ReuseEntry with a memop id, 
     * and an  address. It updates an internal dictionary that map memop id -> 
     * ReuseStats When you process (memop, address) we update the associate 
     * ReuseStats, with the number of unique addresses between now and the last 
     * time it was seen. If an address hasn't been seen yet or is further back 
     * than the size of the window, we update the ReuseStats with 
     * ReuseDistance::Infinity (also referenced as invalid, and actual value 
     * is 0). If an address is seen twice in a row, that is a reuse 
     * distance of 1
     *
     * @param addr  The structure describing the memory address 
     * and memory op to process.
     *
     * @return none
     */
    virtual void Process(ReuseEntry& addr);

    /**
     * Process multiple memory addresses. Equivalent to calling Process on each
     * element of the input array.
     *
     * @param addrs  An array of structures describing memory addresses to 
     * process.
     * @param count  The number of elements in addrs.
     *
     * @return none
     */
    void Process(ReuseEntry* addrs, uint64_t count);

    /**
     * Process multiple memory addresses. Equivalent to calling Process on each
     * element of the input vector.
     *
     * @param addrs  A std::vector of memory addresses to process.
     *
     * @return none
     */
    void Process(std::vector<ReuseEntry> rs);

    /**
     * Process multiple memory addresses. Equivalent to calling Process on each 
     * element of the input vector.
     *
     * @param addrs  A std::vector of memory addresses to process.
     *
     * @return none
     */
    void Process(std::vector<ReuseEntry*> addrs);

    /**
     * Get the ReuseStats object associated with some unique id.
     *
     * @param id  The unique id.
     *
     * @return The ReuseStats object associated with parameter id, or NULL if 
     * no ReuseStats is associate with id.
     */
    ReuseStats* GetStats(uint64_t id);

    /**
     * Get a std::vector containing all of the unique indices processed
     * by this ReuseDistance object.
     *
     * @param ids  A std::vector which will contain the ids. It is an error to
     * pass this vector non-empty (that is addrs.size() == 0 is enforced at 
     * runtime).
     *
     * @return none
     */
    void GetIndices(std::vector<uint64_t>& ids);

    /**
     * Pretend that some number of addresses in the stream were skipped. Useful
     * for intervel-based sampling. This has the effect of flushing the entire 
     * window.
     * 
     * @param amount  The number of addresses to skip.
     *
     * @return none
     */
    virtual void SkipAddresses(uint64_t amount);
};

/**
 * @class ReuseStats
 *
 * ReuseStats holds count of observed reuse distances.
 */
class ReuseStats {
protected:
    reuse_map_type<uint64_t, uint64_t> distcounts;
    uint64_t accesses;

    uint64_t id;
    uint64_t binindividual;
    uint64_t maxtracking;
    uint64_t invalid;

    // ShaveBitsPwr2 was moved so that it could be accessed by 
    // testing frameworks
    // commented out values are what they will be initialized too
    
    
    uint64_t GetBin(uint64_t value);

public:

    /**
     * Contructs a ReuseStats object.
     *
     * @param idx  The unique id for this ReuseStats
     * @param bin  Stop collecting individual bins above this value
     * @param num  Any value above this is considered a miss
     * @param inv  The value which represents a miss
     */
    ReuseStats(uint64_t idx, uint64_t bin, uint64_t num, uint64_t inv)
      : accesses(0), id(idx), binindividual(bin), maxtracking(num), 
        invalid(inv) {}

    /**
     * Destroys a ReuseStats object.
     */
    ~ReuseStats() {}

    /**
     * Increment the counter for some distance.
     *
     * @param dist  A reuse distance observed in the memory address stream.
     *
     * @return none
     */
    virtual void Update(uint64_t dist);

    /**
     * Increment the number of misses. That is, addresses which were not found 
     * inside the active address window. This is equivalent Update(0), but is 
     * faster.
     *
     * @return none
     */
    virtual void Miss();

    /**
     * Get the number of misses. This is equal to the number of times
     * Update(ReuseDistance::Infinity) is called.
     *
     * @return The number of misses to this ReuseDistance object
     */
    virtual uint64_t GetMissCount();

    /**
     * Print a summary of the current reuse distances and counts for some id.
     *
     * @param f  The stream to receive the output.
     * @param annotate  Also print annotations describing the meaning of output
     * fields, preceded by a '#'.
     *
     * @return none
     */
    //virtual void Print(std::ostream& f, reuse_map_type<uint64_t,uint64_t>& 
    //  BinTotal, bool annotate=false);
    virtual void Print(std::ostream& f, bool annotate=false);

    /**
     * Print information about the output format of ReuseStats
     *
     * @param f  The stream to receive the output.
     *
     * @return none
     */
    static void PrintFormat(std::ostream& f);

    /**
     * Get a std::vector containing the distances observed, sorted in ascending
     * order.
     *
     * @param dists  The vector which will hold the sorted distance values. It 
     * is an error for dists to be passed in non-empty (that is, 
     * dists.size() == 0 is enforced).
     *
     * @return none
     */
    void GetSortedDistances(std::vector<uint64_t>& dists);

    /**
     * Count the total number of distances observed.
     *
     * @return The total number of distances observed.
     */
    uint64_t GetAccessCount();
};

/**
 * @class SpatialLocality
 *
 * Finds and tracks spatial locality within a memory address stream. Spatial 
 * locality is defined as the minimum distance between the current address and 
 * any of the previous N addresses, as in 
 * http://www.sdsc.edu/~allans/sc05_locality.pdf. This class allows that 
 * window size N to be customized. For basic usage, see the documentation at 
 * http://bit.ly/ScqZVj for the constructors, the Process methods and the Print
 * methods. Also see the simple test file test/test.cpp included in this 
 * source package.
 */
class SpatialLocality : public ReuseDistance {
protected:

    // [address -> sequence]
    std::map<uint64_t, uint64_t> awindow;

    // list of the addresses in the window, ordered by sequence id
    std::list<uint64_t> swindow;

    void Init(uint64_t size, uint64_t bin);

    virtual ReuseStats* GetStats(uint64_t id, bool gen);
    virtual const std::string Describe() { return "SPATIAL"; }


public:

    static const uint64_t Invalid;
    static const uint64_t DefaultWindowSize;

    /**
     * Contructs a SpatialLocality object.
     *
     * @param w  The maximum window size, which is the maximum number of 
     * addresses that will be searched for spatial locality. 
     * w != ReuseDistance::Infinity is enforced at runtime. All distances 
     * greater than w will be counted as infinite. w >= b is enforced 
     * at runtime.
     * @param b  All distances not greater than b will be tracked individually. 
     * All distances are tracked individually if b == ReuseDistance::Infinity. 
     * Beyond individual tracking, distances are tracked in bins whose 
     * boundaries are the powers of two greater than b and not greater than n.
     */
    SpatialLocality(uint64_t w, uint64_t b) : 
      ReuseDistance((uint64_t)0) { SpatialLocality::Init(w, b); }
    
    /**
     * Constructs a SpatialLocality object. Equivalent to calling the other 
     * 2-argument constructor with w == b 
     */
    SpatialLocality(uint64_t w) : ReuseDistance((uint64_t)0) { 
      SpatialLocality::Init(w, w); }
 
    /**
     * Constructs a SpatialLocality object. Equivalent to calling the other 
     * 2-argument constructor with 
     * w == b == SpatialLocality::DefaultWindowSize 
     */
    SpatialLocality() : ReuseDistance((uint64_t)0) { 
      SpatialLocality::Init(DefaultWindowSize, DefaultWindowSize); }
 
    /**
     * Constructs a SpatialLocality object equivalent to the given 
     * SpatialLocality object
     */
    SpatialLocality(SpatialLocality* s) : ReuseDistance((uint64_t)0) {
      SpatialLocality::Init(s->capacity, s->binindividual); }

    /**
     * Destroys a SpatialLocality object.
     */
    virtual ~SpatialLocality() {}

    /**
     * Get a std::vector containing all of the addresses currently in this 
     * SpatialLocality object's active window.
     *
     * @param addrs  A std::vector which will contain the addresses. It is an 
     * error to pass this vector non-empty (that is addrs.size() == 0 is 
     * enforced at runtime).
     *
     * @return none
     */
    virtual void GetActiveAddresses(std::vector<uint64_t>& addrs);

    /**
     * Process a single memory address.
     *
     * @param addr  The structure describing the memory address to process.
     *
     * @return none
     */
    virtual void Process(ReuseEntry& addr);

    /**
     * Pretend that some number of addresses in the stream were skipped. Useful
     * for intervel-based sampling. This has the effect of flushing the entire 
     * window.
     * 
     * @param amount  The number of addresses to skip.
     *
     * @return none
     */
    virtual void SkipAddresses(uint64_t amount);
    virtual void Print(std::ostream& f, bool annotate=false);    
};
