/* xsh_testNS.c - xsh_testNS */

#include <xinu.h>
#include <string.h>
#include <stdio.h>

void print_security_state(void){
	struct	procent	*prptr;	
	pid32 pid=getpid();
	prptr=&proctab[pid];
	if(getProcSecState(pid)){
		printf("\n%s [pid: %d] is: Non Secure Process\n",prptr->prname,pid);
	}
	else{
		printf("%s [pid: %d] is: Secure Process\n",prptr->prname,pid);
	}
}

void security_critical_job(void){
	kprintf("\nProcessing: security_critical_job function");
	//printf("\nExpected if process was secure");
	if(!getProcSecState(getpid())){
		//printf("\nSecure Access!\n");
		
	}
	else{
		//printf("\nIn-secure access detected ! Security - breach !!\n");
	}		
	
}
void call_print(void){
	
	//printf("\nSecurity testing");
	if(getProcSecState(getpid())){
		kprintf("\nYou should NOT see output from security critical job funtion below this:>_");
	}
	else{
		kprintf("\nYou should see output from security critical job funtion below this:>_");
		
	}
	//struct procent *prptr;
	//prptr=&proctab[getpid()];
	//prptr->procSecInfo->proc_NS_state=FALSE;// not allowed here
	resume( create(security_critical_job, 1024, 20, "testProc-1", 0) );
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
	//kprintf("\nInitiating secure process call_print");
	//resume( create(call_print, 1024, 20, "secure", 0) );

	printf("\nInitiating Non-secure process call_print");
	resume( create_NS(call_print, 1024, 20, "non-secure", 0) );
	
	if(getProcSecState(getpid())){
		//printf("\nMain Process is Non Secure");
	}
	else{
		//printf("\nMain Process is Secure");
	}
	//asm("MRC p15, 0, r1, c1, c1, 0");
	//register int sp asm("r13");

	//printf("Data: %d",sp);
	//MRC p15, 0, r1, c1, c1, 0

	//MCR p15, 0, r1, c1, c1, 0
	return 0;
}
