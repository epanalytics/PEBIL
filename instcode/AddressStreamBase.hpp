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

#include <vector>
#include <string>
#include <AddressStreamStats.hpp>

template <class T> class DataManager;
class MemoryStreamHandler;
class SamplingMethod;

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

class AddressStreamTool {
  public:
    virtual std::vector<MemoryStreamHandler*> CreateHandlers(uint32_t) = 0;
    virtual void FinalizeTool(DataManager<AddressStreamStats*>*, 
      SamplingMethod*) = 0;
};

class StreamStats {
  public:
    virtual uint64_t GetAccessCount(uint32_t memid) = 0;
    virtual bool Verify() = 0;
};

// Note: User required to check if limit is hit
class SamplingMethod {
  private:
    uint32_t AccessLimit;
    uint32_t SampleOn;
    uint32_t SampleOff;
    uint64_t AccessCount;

    bool CurrentlySampling(uint64_t count);

  public:
    SamplingMethod(uint32_t limit, uint32_t on, uint32_t off);
    virtual ~SamplingMethod();

    bool CurrentlySampling();
    bool ExceedsAccessLimit(uint64_t count);
    uint64_t GetAccessCount() { return AccessCount; }
    uint64_t GetAccessLimit() { return AccessLimit; }
    double GetSamplingFrequency();
    uint32_t GetSampleOn() { return SampleOn; }
    uint32_t GetSampleOff() { return SampleOff; }
    void IncrementAccessCount(uint64_t count);
    bool SwitchesMode(uint64_t count);
    void Print();
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

// Common string functions
class StringParser {
  public:
    StringParser() {};
    virtual ~StringParser() {};

    virtual bool IsEmptyComment(std::string str);
    virtual bool ParseInt32(std::string token, int32_t* value, int32_t min);
    virtual bool ParsePositiveInt32(std::string token, uint32_t* value);
    virtual bool ReadEnvUint32(std::string name, uint32_t* var);
    virtual char ToLowerCase(char c);
};

class Randomizer {
  public:
    Randomizer() {};
    virtual ~Randomizer() {}    

    virtual uint32_t RandomInt(uint32_t max);
};

#endif /* _AddressStreamBase_hpp_ */

