/* xsh_testNS.c - xsh_testNS */

#include <xinu.h>
#include <string.h>
#include <stdio.h>

void print_security_state(void){
	struct	procent	*prptr;	
	prptr=&proctab[getpid()];
	if(prptr->NS){
		printf("\nNon Secure Process: %s",prptr->prname);
	}
	else{
		printf("\nSecure Process: %s",prptr->prname);
	}
}


/*---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 * xsh_testNS - A simple test code to test the creation and detection of secure and non-secure process
 *----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 */
shellcmd xsh_testNS(int nargs, char *args[]) {

	/* Output info for '--help' argument */

	if (nargs == 2 && strncmp(args[1], "--help", 7) == 0) {
		printf("Usage: %s <sring> \n\n", args[0]);
		printf("Description:\n");
		printf("\tDisplays the name and security state of the process:\n");
		return 0;
	}

	/* Check argument count */

	if (nargs > 2) {
		fprintf(stderr, "%s: too many arguments\n", args[0]);
		fprintf(stderr, "Try '%s --help' for more information\n",
			args[0]);
		return 1;
	}
	resume( create(print_security_state, 1024, 20, "SecureProc", 0) );
	resume( create_NS(print_security_state, 1024, 20, "NonSecureProc", 0) );
	return 0;
}