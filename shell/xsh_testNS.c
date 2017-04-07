/* xsh_testNS.c - xsh_testNS */

#include <xinu.h>
#include <string.h>
#include <stdio.h>

void print_security_state(void){
	struct	procent	*prptr;	
	pid32 pid=getpid();
	prptr=&proctab[pid];
	if(getNS(pid)){
		printf("\n%s [pid: %d] is: Non Secure Process\n",prptr->prname,pid);
	}
	else{
		printf("%s [pid: %d] is: Secure Process\n",prptr->prname,pid);
	}
}

void security_critical_job(void){
	printf("\nA call to security_critical_job function is about to process");
	printf("\nDemo that security state can be detected inside critical job");
	if(!getNS(getpid())){
		printf("\nSecure Access ! Everything is fine!\n");
		
	}
	else{
		printf("\nIn-secure access detected ! Security - breach !!\n");
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
	//resume( create(print_security_state, 1024, 20, "Proc1", 0) );
	//resume( create_NS(print_security_state, 1024, 20, "Proc2", 0) );
	printf("\nMain Process is calling in-secure process call_print");
	resume( create_NS(security_critical_job, 1024, 20, "Proc-Parent", 0) );
	
	if(proctab[currpid].NS){
		//printf("\nMain Process is Non Secure");
	}
	else{
		//printf("\nMain Process is Secure");
	}
	return 0;
}
