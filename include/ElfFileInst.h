#ifndef _ElfFileInst_h_
#define _ElfFileInst_h_

class ElfFile;
class Instruction;
class BinaryOutputFile;
class InstrumentationPoint;
class Instrumentation;
class InstrumentationFunction;
class Instruction;
class Function;
class TextSection;

#define IDX_INST_BOOTSTRAP_BEGIN 0
#define IDX_INST_BOOTSTRAP_END 1
#define INST_CODES_RESERVED 2
#define IDX_POINT_BOOTSTRAP 0
#define INST_POINTS_RESERVED 1

typedef enum {
    ElfInstPhase_no_phase = 0,
    ElfInstPhase_reserve_space,
    ElfInstPhase_modify_control,
    ElfInstPhase_generate_instrumentation,
    ElfInstPhase_dump_file,
    ElfInstPhase_Total_Phases
} ElfInstPhases;


class ElfFileInst {
private:
    uint32_t currentPhase;
    ElfFile* elfFile;

    uint32_t numberOfInstrumentations;
    Instrumentation** instrumentations;

    uint32_t numberOfInstrumentationLibraries;
    char** instrumentationLibraries;

    uint32_t numberOfInstrumentationPoints;
    InstrumentationPoint** instrumentationPoints;

    uint16_t extraTextIdx;
    uint16_t extraDataIdx;

    uint32_t addStringToDynamicStringTable(const char* str);
    uint32_t addSymbolToDynamicSymbolTable(uint32_t name, uint64_t value, uint64_t size, uint8_t bind, uint8_t type, uint32_t other, uint16_t scnidx);
    uint32_t expandHashTable();

    uint64_t addInstrumentationPoint(Base* instpoint, Instrumentation* inst);
public:
    ElfFileInst(ElfFile* elf);
    ~ElfFileInst();
    ElfFile* getElfFile() { return elfFile; }

    void print();
    void dump(char* extension);
    void dump(BinaryOutputFile* binaryOutputFile, uint32_t offset);

    void verify();

    void instrument();

    // instrumentation functions
    uint32_t addSharedLibrary(const char* libname);
    uint64_t addFunction(InstrumentationFunction* func);
    uint64_t addPLTRelocationEntry(uint32_t symbolIndex, uint64_t gotOffset);
    void addInstrumentationFunction(const char* funcname);
    uint64_t relocateDynamicSection();
    uint64_t getProgramBaseAddress();
    void extendTextSection(uint64_t size);
    void extendDataSection(uint64_t size);
    void generateInstrumentation();

    uint32_t declareFunction(char* funcName);
    uint32_t declareLibrary(char* libName);

    InstrumentationFunction* getInstrumentationFunction(const char* funcName);

    uint64_t addInstrumentationPoint(TextSection* instpoint, Instrumentation* inst);
    uint64_t addInstrumentationPoint(Function* instpoint, Instrumentation* inst);
    uint64_t addInstrumentationPoint(Instruction* instpoint, Instrumentation* inst);
};


#endif /* _ElfFileInst_h_ */
