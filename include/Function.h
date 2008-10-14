#ifndef _Function_h_
#define _Function_h_

#include <TextSection.h>
#include <Vector.h>

class Symbol;
class BasicBlock;
class BinaryInputFile;
class BinaryOutputFile;
class TextObject;

class Function : public TextObject {
protected:
    Symbol* functionSymbol;
    Vector<BasicBlock*> basicBlocks;

    uint32_t findBasicBlocks(uint32_t numberOfInstructions, Instruction** instructions);

public:
    Function(TextSection* text, uint32_t idx, Symbol* sym, uint32_t sz);
    ~Function();

    Symbol* getFunctionSymbol() { return functionSymbol; }

    BasicBlock* getBasicBlock(uint32_t idx) { return basicBlocks[idx]; }
    uint32_t getNumberOfBasicBlocks() { return basicBlocks.size(); }
    Instruction* getInstructionAtAddress(uint64_t addr);

    char* getName();

    uint64_t findInstrumentationPoint();
    void printInstructions();

    uint32_t digest();
    void dump (BinaryOutputFile* binaryOutputFile, uint32_t offset);
    bool verify();
    void print();

    const char* briefName() { return "Function"; }
};

#endif /* _Function_h_ */