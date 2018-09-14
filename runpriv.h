#ifndef RUNPRIV_H_
#define RUNPRIV_H_

#include <sys/types.h>

uid_t checkUserID();
void promptPassword(uid_t userID);
void checkSniff();
void checkSniffPermissions(uid_t ownerID, mode_t permissions);
void checkSniffTime(time_t modificationTime);
void setSniffPermissions();
void printError(int errorCode);
#endif //RUNPRIV_H_
