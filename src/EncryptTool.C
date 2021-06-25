#include <EncryptTool.h>

EncryptTool::EncryptTool(){
}
EncryptTool::~EncryptTool(){
	fprintf(stderr,"destroying encryption tool");
}
std::string EncryptTool::getPasswordFromUser(int encryptOrDecrypt){
    std::string attempt1;
    std::string attempt2;
    switch(encryptOrDecrypt){
	    case Encrypt :
		std::cout << "Please provide a password to encrypt the translation file with:\n" << std::endl;
		std::cin >> attempt1;
		std::cout << "Please type your pasword in one more time to confirm\n" <<std::endl;
		std::cin >> attempt2;
    		if (attempt1 != attempt2){
	    		fprintf(stderr,"Passwords do not match!\n");
	    		return getPasswordFromUser(Encrypt);
    		} else {
	    		password=attempt1;
			std::cout << "ELIZABETH TODO DELETE PASSWORD " << password <<"\n" <<std::endl;
    		}
		return password;
		break;
            case Decrypt :
		std::cout << "Type in your password to decrypt this file\n" << std::endl;
		std::cin >> attempt1;
		if (password.compare(attempt1) ==0){
			return password;
		} else {
			std::cerr << "WRONG PASSWORD!!\n" <<std::endl;
			return getPasswordFromUser(Decrypt);
		}
		break;
            default :
		std::cerr << "SHOULD NOT GET HERE ELIZABETH\n" <<std::endl;	
   }
}
/*
void InstrumentationTool::printSanitizeTranslationFile(std::map<char*,std::string> lineNoInfo){
    char translationName[__MAX_STRING_SIZE];
    sprintf(translationName,"%s%s",getApplicationName(),".translation");
    FILE* fd = fopen(translationName,"w");
    fprintf(fd,"Alias\tFunction Name\tFile Name\tLine No.\n");
    for (uint32_t i = 0; i < getNumberOfExposedFunctions(); i++){
        Function* f = getExposedFunction(i);
        char* fakeName = f->getName();
        Symbol* funcSym = f->getFunctionSymbol();
        char* realName=funcSym->getSymbolName();
        fprintf(fd,"%s\t%s\t%s\n",fakeName,realName,lineNoInfo[fakeName].c_str());
    }
    fclose(fd);
    if (sanitizePassword[0] != '\0'){
    char encryptComm[__MAX_STRING_SIZE];
    sprintf(encryptComm,"$PEBIL_ROOT/scripts/encryptGPG.sh %s %s",sanitizePassword,translationName);
    system(encryptComm);
    }
}
*/
