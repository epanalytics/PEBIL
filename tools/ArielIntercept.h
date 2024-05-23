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

#ifndef _ArielIntercept_h_
#define _ArielIntercept_h_

#include <InstrumentationTool.h>
#include <SimpleHash.h>
#include <Vector.h>
#include <AddressStreamStats.hpp>


class ArielIntercept : public AddressStreamIntercept {
protected:
    void collectInsnCountEntry(BasicBlock*, X86Instruction*, uint32_t,
      AddressStreamStats&, uint32_t, uint32_t&, uint64_t);
    uint64_t getNumberOfBufferElements(BasicBlock* bb);

public:
    ArielIntercept(ElfFile* elf) : AddressStreamIntercept(elf) {}
    ~ArielIntercept() {}

    const char* briefName() { return "ArielIntercept"; }
    const char* defaultExtension() { return "arielinst"; }
    uint32_t allowsArgs() { return PEBIL_OPT_LPI | PEBIL_OPT_DTL | PEBIL_OPT_PHS | PEBIL_OPT_DFP; }
    uint32_t requiresArgs() { return PEBIL_OPT_INP; }
};


#endif /* _ArielIntercept_h_ */
