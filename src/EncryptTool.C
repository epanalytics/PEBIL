#include <EncryptTool.h>
using namespace std;

EncryptTool::EncryptTool(){
}
EncryptTool::~EncryptTool(){
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
    		}
		break;
            case Decrypt :
		cout << "Type in your password to decrypt this file\n" << endl;
		cin >> attempt1;
        setPassword(attempt1);
		break;
            default :
		cerr << "SHOULD NOT GET HERE\n" <<endl;	
        exit(1);
   }
}
bool EncryptTool::encryptFile(string filename){
   fprintf(stderr,"HERE TODO\n");
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

