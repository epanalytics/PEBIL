#include <EncryptTool.h>
using namespace std;

EncryptTool::EncryptTool(){
}
EncryptTool::~EncryptTool(){
	fprintf(stderr,"destroying encryption tool");
}
void EncryptTool::setPassword(string pass){
    password=pass;
}
void EncryptTool::getPasswordFromUser(int encryptOrDecrypt){
    string attempt1;
    string attempt2;
    switch(encryptOrDecrypt){
	    case Encrypt :
		cout << "Please provide a password to encrypt the translation file with:\n" << endl;
		cin >> attempt1;
		cout << "Please type your pasword in one more time to confirm\n" <<endl;
		cin >> attempt2;
    		if (attempt1 != attempt2){
	    		fprintf(stderr,"Passwords do not match!\n");
	    		return getPasswordFromUser(Encrypt);
    		} else {
	    		setPassword(attempt1);
			cout << "ELIZABETH TODO DELETE PASSWORD " << password <<"\n" <<endl;
    		}
		break;
            case Decrypt :
		cout << "Type in your password to decrypt this file\n" << endl;
		cin >> attempt1;
/*		if (password.compare(attempt1) ==0){
			return password;
		} else {
			cerr << "WRONG PASSWORD!!\n" <<endl;
			return getPasswordFromUser(Decrypt);
		}
*/
        setPassword(attempt1);
		break;
            default :
		cerr << "SHOULD NOT GET HERE ELIZABETH\n" <<endl;	
   }
}
bool EncryptTool::encryptFile(string filename){
   fprintf(stderr,"HERE ELIZABETH\n");
}
bool EncryptTool::decryptFile(string filename){
   ifstream fd(filename);
   string line;
   if (fd.is_open()){
       while(getline(fd,line)){
           cout << line << endl;
       }
   fd.close();
   }
}

/*
void InstrumentationTool::printSanitizeTranslationFile(map<char*,string> lineNoInfo){
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
