
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

#ifndef _EncryptTool_h_
#define _EncryptTool_h_

#include <gpgme.h>
class EncryptTool {
public:
    EncryptTool();
    std::string getPasswordFromUser();
    bool encryptFile(std::string filename);
    bool decryptFile(std::string filename);
private:
    std::string password;
};
#endif /* _EncryptTool_h_ */
void EncryptTool::EncryptTool(void){
    password="";
}
void EncryptTool::~EncryptTool(void){
	fprintf(stderr,"destroying encryption tool");
}
std::string getPasswordFromUser(int encryptOrDecrypt){
    std::string attempt1;
    std::string attempt2;
    switch(encryptOrDecrypt){
	    case Encrypt :
    		cout << "Please provide a password to encrypt the translation file with:\n";
		cin >> attempt1;
    		cout << "Please type your pasword in one more time to confirm\n";
    		cin >> attempt2;
    		if (attempt1 != attempt2){
	    		fprintf(stderr,"Passwords do not match!\n");
	    		return getPasswordFromUser();
    		} else {
	    		password.copy(attempt1);
	    		cout << "ELIZABETH TODO DELETE PASSWORD " << password <<"\n";
    		}
		return password
		break;
            case Decrypt :
		cout << "Type in your password to decrypt this file\n";
		cin >> attempt1;
		if (password.compare(attempt1) ==0){
			return password;
		} else {
			cerr << "WRONG PASSWORD!!\n";
			return getPasswordFromUser();
		}
		break;
            default :
	       cerr << "SHOULD NOT GET HERE ELIZABETH\n";	
}

}
bool InstrumentationTool::setSanitize(void){
    sprintf(sanitizePassword,"%s","");
    sanitize=true;
    return setElfInstSanitize(true);
}
bool InstrumentationTool::setSanitize(const char* password){
    sprintf(sanitizePassword,"%s",password);//ELIZABETH TODO: use password to encrpyt translation file
    sanitize=true;
    return setElfInstSanitize(true);
}
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
