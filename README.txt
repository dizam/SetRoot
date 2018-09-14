Name: Daljodh Pannu
SID: 912303549

To compile the program, a Makefile is provided. Simply type make! There is also a make clean command to remove the executable and object files.
This program:
1. Checks that a student specified by STUDENT_UID is running the program.
2. Uses kinit to authenticate the user against UC Davis CAS.
3. Checks if a file sniff exists.
4. Check if the student owns sniff, that only they can execute it, and that no one else has any rights over sniff.
5. Checks that sniff was created or modified less than 1 minute ago.
6. Changes the owner of sniff to root, its group to GID 95, and its permissions to -r-sr-x---

Note: For the CHOWN, I use the macro CHOWN_TO with my own student ID to test chmod. Change CHOWN_TO at the top of the file to 0 if you want the program to set the owner to root.
Also, lstat and lchown are used to avoid symbolic link attacks.
There is also alot of commented code if you want to use your own custom prompt for the password or use setuid and setgid instead of chown (which is thoroughly error-checked).

