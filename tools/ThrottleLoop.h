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

#ifndef _ThrottleLoop_h_
#define _ThrottleLoop_h_

#include <InstrumentationTool.h>

class ThrottleLoop : public InstrumentationTool {
private:
    InstrumentationFunction* loopEntry;
    InstrumentationFunction* loopExit;
    InstrumentationFunction* programEntry;
    InstrumentationFunction* programExit;

    Vector<InstrumentationFunction*> functionWrappers;

    Vector<char*>* loopList;    
    Vector<char*>* functionList;

    char* getFileName(uint32_t idx);
    uint32_t getLineNumber(uint32_t idx);
    uint32_t loopMatch(LineInfo* li);
    uint32_t getThrottleLevel(uint32_t idx);
    char* getWrappedFunction(uint32_t idx);
    char* getWrapperFunction(uint32_t idx);    

public:
    ThrottleLoop(ElfFile* elf);
    ~ThrottleLoop();

    void declare();
    void instrument();

    const char* briefName() { return "ThrottleLoop"; }
    const char* defaultExtension() { return "thrinst"; }
    bool checkArgs();
};


#endif /* _ThrottleLoop_h_ */
