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

#ifndef _AddressRange_hpp_
#define _AddressRange_hpp_

#include <string>
#include <AddressStreamStats.hpp>

using namespace std;

#define DEFAULT_SAMPLE_ON  1000000
#define DEFAULT_SAMPLE_OFF 10000000
#define DEFAULT_SAMPLE_MAX 0

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

static char ToLowerCase(char c);
static bool ParseInt32(string token, uint32_t* value, uint32_t min);
static void ReadSettings();
static AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, 
  uint32_t typ, image_key_t iid, thread_key_t tid, image_key_t firstimage);
static uint64_t ReferenceStreamStats(AddressStreamStats* stats);
static void DeleteStreamStats(AddressStreamStats* stats);
static bool ReadEnvUint32(string name, uint32_t* var);
static void PrintAddressStreamStats(ofstream& f, AddressStreamStats* stats, thread_key_t tid, bool perThread);
static void RangeFileName(AddressStreamStats* stats, string& oFile);

extern "C" {
    void* tool_mpi_init();
    void* tool_thread_init(pthread_t tid);
    void* process_buffer(image_key_t* key);
    void* tool_image_fini(image_key_t* key);
};

class StreamStats {
public:
    virtual uint64_t GetAccessCount(uint32_t memid) = 0;
    virtual bool Verify() = 0;
};

struct AddressRange {
    uint64_t Minimum;
    uint64_t Maximum;
};

class RangeStats : public StreamStats {
private:
    static const uint64_t MAX_64BIT_VALUE = 0xffffffffffffffff;
public:
    uint32_t Capacity;
    AddressRange** Ranges;
    uint64_t* Counts;

    RangeStats(uint32_t capacity);
    ~RangeStats();

    bool HasMemId(uint32_t memid);
    uint64_t GetMinimum(uint32_t memid);
    uint64_t GetMaximum(uint32_t memid);
    uint64_t GetAccessCount(uint32_t memid) { return Counts[memid]; }

    void Update(uint32_t memid, uint64_t addr);
    void Update(uint32_t memid, uint64_t addr, uint32_t count);

    bool Verify();
};

class SamplingMethod {
public:
    uint32_t AccessLimit;
    uint32_t SampleOn;
    uint32_t SampleOff;
    uint64_t AccessCount;

    SamplingMethod(uint32_t limit, uint32_t on, uint32_t off);
    ~SamplingMethod();

    void Print();

    void IncrementAccessCount(uint64_t count);

    bool SwitchesMode(uint64_t count);
    bool CurrentlySampling();
    bool CurrentlySampling(uint64_t count);
    bool ExceedsAccessLimit(uint64_t count);
};

// DFP and other interesting memory things extend this class.
class MemoryStreamHandler {
protected:
    pthread_mutex_t mlock;
public:
    MemoryStreamHandler();
    ~MemoryStreamHandler();

    virtual void Print(ofstream& f) = 0;
    virtual uint32_t Process(void* stats, BufferEntry* access) = 0;
    virtual bool Verify() = 0;
    bool Lock();
    bool UnLock();
    bool TryLock();

};

class AddressRangeHandler : public MemoryStreamHandler {
public:
    AddressRangeHandler();
    AddressRangeHandler(AddressRangeHandler& h);
    ~AddressRangeHandler();

    void Print(ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    bool Verify() { return true; }
};


#endif /* _AddressRange_hpp_ */

