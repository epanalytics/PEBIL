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

#ifndef _AddressStreamBase_hpp_
#define _AddressStreamBase_hpp_

#include <string>
#include <AddressStreamStats.hpp>

#define DEFAULT_SAMPLE_ON  1000000
#define DEFAULT_SAMPLE_OFF 10000000
#define DEFAULT_SAMPLE_MAX 0

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

class StreamStats {
public:
    virtual uint64_t GetAccessCount(uint32_t memid) = 0;
    virtual bool Verify() = 0;
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

    virtual void Print(std::ofstream& f) = 0;
    virtual uint32_t Process(void* stats, BufferEntry* access) = 0;
    virtual bool Verify() = 0;
    bool Lock();
    bool UnLock();
    bool TryLock();

};

// Common functions
bool IsEmptyComment(std::string str);
bool ParseInt32(std::string token, uint32_t* value, uint32_t min);
bool ParsePositiveInt32(std::string token, uint32_t* value);
uint32_t RandomInt(uint32_t max);
bool ReadEnvUint32(std::string name, uint32_t* var);
char ToLowerCase(char c);

#endif /* _AddressStreamBase_hpp_ */

