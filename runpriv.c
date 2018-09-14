#include "runpriv.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

//temporary CHOWN_TO my student ID for testing, change 0 for root
#define CHOWN_TO 7007924

//my student ID 
#define STUDENT_UID 7007924

//Maximum password length for Kerberos Authentication
#define MAX_PASSWORD_LENGTH 256

//error codes
#define EXTRA_ARGUMENTS -10
#define WRONG_UID -11
#define PASSWORD_TOO_LONG -12
#define AUTHENTICATION_FAILED -13
#define SNIFF_DOES_NOT_EXIST -14
#define STUDENT_NOT_OWNER -15
#define OWNER_NOT_EXECUTE -16
#define OTHERS_HAVE_RIGHTS -17
#define FILE_TOO_OLD -18
#define LSTAT_FAILED -19
#define CANNOT_CHANGE_UID -20
#define UID_INCORRECT -21
#define LACKS_SET_UID_PRIVILEGES -22
#define SETUID_FAILED -23
#define GROUP_INVALID -24
#define LACKS_SET_GID_PRIVILEGES -25
#define SETGID_FAILED -26
#define LCHOWN_FAILED -27
#define CHMOD_FAILED -28

//program to set root permissions for a student-created file
int main(int argc, char* argv[])
{
	//do not specify arguments, exit if arguments found
	if (argc > 1)
	{
		printError(EXTRA_ARGUMENTS);
		exit(EXIT_FAILURE);
	}
	//check userID and get userID if valid
	uid_t userID = checkUserID();
	//prompt user for password and validate against Kerberos CAS
	promptPassword(userID);
	//check if file sniff exists in current working directory
	checkSniff();
}

//check user ID against mine 
//print error and exit if invalid or return the userID if valid.
uid_t checkUserID()
{
	//get user ID of person running this process
	uid_t callerID = getuid();
	//not student's userID
	if (callerID != STUDENT_UID)
	{
		//prints an error and exits
		printError(WRONG_UID);
		exit(EXIT_FAILURE);
	}
	//returns the user ID if valid for authentication
	return callerID;
}

//prompts user for password
//validates authentication against UC Davis Kerberos Central Authentication System
void promptPassword(uid_t userID)
{

/*
	//allocate memory for input string	
	char password[MAX_PASSWORD_LENGTH+1];
	//prompt user for password
	printf("Please enter your Kerberos password: ");
	//use the safe fgets to get user input up to 257 characters
	fgets(password, MAX_PASSWORD_LENGTH+2, stdin);
	//strlen is safe here because fgets always returns a null terminated string
	//check for more than 256 character input
	if (strlen(password) > 256)
	{
		printError(PASSWORD_TOO_LONG);
		exit(EXIT_FAILURE);
	}
*/
	//get username from specified user ID
	struct passwd *pwd = getpwuid(userID);
	char* userName = pwd->pw_name;
	//create a command buffer for command with arguments
	char cmdbuf[256];
	//put command in command buffer
	//note echo is used to pipe password into kinit
	//snprintf(cmdbuf, sizeof(cmdbuf), "echo '%s' | kinit %s > /dev/null 2>&1", password, userName);
	snprintf(cmdbuf, sizeof(cmdbuf), "kinit %s 2> /dev/null", userName);
	//execute kinit as subprocess and get return status
	int isValidPassword = system(cmdbuf);
	//nonzero return status means kinit failed or password is wrong
	if (isValidPassword != 0)
	{	
		//print error and exit
		printError(AUTHENTICATION_FAILED);
		exit(EXIT_FAILURE);
	}
}

//check to see if file sniff is there
void checkSniff()
{
	struct stat sniffNode;
	//get file information on file sniff
	//note use of lstat to prevent symbolic link attacks
	int fileStatus = lstat("sniff", &sniffNode);
	//special error if file does not exist
	if (ENOENT == errno)
	{
		//print error and exit
		printError(SNIFF_DOES_NOT_EXIST);
		exit(EXIT_FAILURE);
	}
	if (fileStatus != 0)
	{
		printError(LSTAT_FAILED);
		exit(EXIT_FAILURE);
	}
	uid_t ownerID = sniffNode.st_uid;
	mode_t filePermissions = sniffNode.st_mode;
	//now check if sniff has valid permissions
	checkSniffPermissions(ownerID, filePermissions);
	time_t modificationTime = sniffNode.st_mtime;
	//printf("%s\n", ctime(&modificationTime));	
	checkSniffTime(modificationTime);
	setSniffPermissions();
}

//check file permissions on sniff (owner is student, owner can execute, no one else has permissions)	
void checkSniffPermissions(uid_t ownerID, mode_t filePermissions)
{
	//if student is not owner of sniff
	if (ownerID != STUDENT_UID)
	{
		//print error and exit
		printError(STUDENT_NOT_OWNER);
		exit(EXIT_FAILURE);
	}
	int allPermissions = (filePermissions & 07777);
	//get owner permissions with mask 00700
	int ownerPermissions = (allPermissions & 00700) >> 6;
	//execute perrmisions are 1, 3, 5, 7
	if (ownerPermissions % 2 != 1)
	{
		printError(OWNER_NOT_EXECUTE);
		exit(EXIT_FAILURE);
	}
	//get group permissions with mask 00070
	int groupPermissions = (allPermissions & 00070);
	//check if anyone but owner has permissions
	if (groupPermissions != 0)
	{
		//print error and exit
		printError(OTHERS_HAVE_RIGHTS);
		exit(EXIT_FAILURE);
	}
	//get other permissions with mask 00007
	int otherPermissions = (allPermissions & 00007);
	//check if anyone but owner has permissions
	if (otherPermissions != 0)
	{
		printError(OTHERS_HAVE_RIGHTS);
		exit(EXIT_FAILURE);
	}	
}

//check modification time to ensure file was modified only recently
void checkSniffTime(time_t modificationTime)
{
	//get current time
	time_t currentTime;
	time(&currentTime);
	//check if file was modified over 1 minute ago
	if ((currentTime - modificationTime) > 60)
	{
		//print error and exit
		printError(FILE_TOO_OLD);
		exit(EXIT_FAILURE);
	}
}

//set sniff owner to root, gid to 95, and permissions to -r-sr-x---
void setSniffPermissions()
{	
	//chown to root
	//this works on CSIF so using my own ID instead so it fails
	int lchownStatus = lchown("sniff", CHOWN_TO, 95);
	if (lchownStatus != 0)
	{
		printError(LCHOWN_FAILED);
	}
	//chmod sniff to 4550 giving readable and executable to owner and group members
	int chmodStatus = chmod("sniff", 04550);
	if (chmodStatus != 0)
	{
		printError(CHMOD_FAILED);
		exit(EXIT_FAILURE);
	}
	/*
	//set user id to root
	int setUIDStatus = setuid(0);
	switch (errno)
	{
		case EAGAIN:
			printError(CANNOT_CHANGE_UID);
			exit(EXIT_FAILURE);
		case EINVAL:
			printError(UID_INCORRECT);
			exit(EXIT_FAILURE);
		case EPERM:
			printError(LACKS_SET_UID_PRIVILEGES);
			exit(EXIT_FAILURE);
	}
	if (setUIDStatus != 0)
	{
		printError(SETUID_FAILED);
		exit(EXIT_FAILURE);
	}
	int setGIDStatus = setgid(95);
	switch (errno)
	{
		case EINVAL:
			printError(GROUP_INVALID);
			exit(EXIT_FAILURE);
		case EPERM:
			printError(LACKS_SET_GID_PRIVILEGES);
			exit(EXIT_FAILURE);
	}
	if (setGIDStatus != 0)
	{
		printError(SETGID_FAILED);
		exit(EXIT_FAILURE);
	}*/
}

//prints error messages based on error codes	
void printError(int errorCode)
{
	switch (errorCode)
	{
		//extra arguments, not really an error but just to be safe
		case EXTRA_ARGUMENTS:
			printf("Do not add extra arguments.\nUsage: runpriv\n");
			break;
		//caller's user ID is not of the student
		case WRONG_UID:
			printf("UID of caller is not of the student\n");
			break;
		/*
		//input password for authentication is > 256 characters
		case PASSWORD_TOO_LONG:
			printf("Entered password is too long (max length is 256 characters)\n");
			break;
		*/
		//kinit failed or password is not correct
		case AUTHENTICATION_FAILED:
			printf("Either password is incorrect or authentication system failed, try again\n");
			break;
		case SNIFF_DOES_NOT_EXIST:
			printf("File sniff does not exist in current working directory\n");
			break;
		case STUDENT_NOT_OWNER:
			printf("File sniff is not owned by the student\n");
			break;
		case OWNER_NOT_EXECUTE:
			printf("File sniff cannot be executed by the owner\n");
			break;
		case OTHERS_HAVE_RIGHTS:
			printf("Users that aren't the owner have read, write, or execute privileges on the file sniff\n");
			break;
		case FILE_TOO_OLD:
			printf("File sniff was created or modified over 1 minute ago \n");	
			break;
		case LSTAT_FAILED:
			printf("Lstat on file sniff failed\n");
			break;
		/*
		case CANNOT_CHANGE_UID:
			printf("The process is currently not able to change UIDs.\n");
			break;
		case UID_INCORRECT:
			printf("The value of uid is incorrect\n");
			break;
		case LACKS_SET_UID_PRIVILEGES:
			printf("The process does not have appropriate privileges to set the UID to 0.\n");
			break;
		case SETUID_FAILED:
			printf("setuid on file sniff failed\n");
			break;
		case GROUP_INVALID:
			printf("GID is not valid in this user namespace\n");
			break;
		case LACKS_SET_GID_PRIVILEGES:
			printf("The process does not have the appropriate privileges to set the GID to 95.\n");
			break;
		case SETGID_FAILED:
			printf("setgid on file sniff failed\n");
			break;
		*/
		case LCHOWN_FAILED:
			printf("Lchown on file sniff failed\n");
			break;
		case CHMOD_FAILED:
			printf("Chmod on file sniff failed\n");
			break;
	}
}


