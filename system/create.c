/* create.c - create, newpid */
#include <xinu.h>

//defining struct ProcSecInfo - part of process security implementation
struct procSecurityInfo {
	bool8 proc_NS_state;
	//proc_NS_state =True , process is non secure
	//proc_NS_state =False , process is secure
};
//  ----------------

local	int newpid();

#define	roundew(x)	( (x+3)& ~0x3)

/*------------------------------------------------------------------------
 *  create  -  create a process to start running a procedure
 *------------------------------------------------------------------------
 */
pid32	create(
	  void		*procaddr,	/* procedure address		*/
	  uint32	ssize,		/* stack size in words		*/
	  pri16		priority,	/* process priority > 0		*/
	  char		*name,		/* name (for debugging)		*/
	  uint32	nargs,		/* number of args that follow	*/
	  ...
	)
{
	uint32		savsp, *pushsp;
	intmask 	mask;    	/* interrupt mask		*/
	pid32		pid;		/* stores new process id	*/
	struct	procent	*prptr;		/* pointer to proc. table entry */
	int32		i;
	uint32		*a;		/* points to list of args	*/
	uint32		*saddr;		/* stack address		*/

	mask = disable();
	
	
	//check if the create call has been initiated by an insecure process
	//only secure process can call create
	//insecure process can only create insecure child process by making a call to create_NS
	//Return error if the current process which is calling create is insecure BUT....
	//EXCEPTION: INIT process (shell or "nullproc" will always be insecue. For nullproc do not return error
	//rather modify its security state 
	//this exception is only for nullproc for all other return SYSERR
	if(getProcSecState(getpid())){ 
		if(getpid()==0){
			//modify the security state of nullproc process and continue 
			struct procent *pr=&proctab[0];
			pr->procSecInfo->proc_NS_state=FALSE;
		}
		else{
			//quit if process is neither secure nor init process 
			restore(mask);
			return SYSERR;
		}
	}	
	///-----------------------------------------
	
	if (ssize < MINSTK)
		ssize = MINSTK;
	ssize = (uint32) roundew(ssize);
	if (((saddr = (uint32 *)getstk(ssize)) ==
	    (uint32 *)SYSERR ) ||
	    (pid=newpid()) == SYSERR || priority < 1 ) {
		restore(mask);
		return SYSERR;
	}

	prcount++;
	prptr = &proctab[pid];

	/* initialize process table entry for new process */
	prptr->prstate = PR_SUSP;	/* initial state is suspended	*/
	prptr->prprio = priority;
	prptr->prstkbase = (char *)saddr;
	prptr->prstklen = ssize;
	prptr->prname[PNMLEN-1] = NULLCH;
	for (i=0 ; i<PNMLEN-1 && (prptr->prname[i]=name[i])!=NULLCH; i++)
		;
	prptr->prsem = -1;
	prptr->prparent = (pid32)getpid();
	prptr->prhasmsg = FALSE;
	/* By default make process secure  */
	//prptr->NS = FALSE; //depricated
	prptr->procSecInfo=getmem(sizeof(struct procSecurityInfo));
	prptr->procSecInfo->proc_NS_state=FALSE;

	/* set up initial device descriptors for the shell		*/
#ifdef ARM_BBB
	prptr->prdesc[0] = CONSOLE;	/* stdin  is CONSOLE device	*/
	prptr->prdesc[1] = CONSOLE;	/* stdout is CONSOLE device	*/
	prptr->prdesc[2] = CONSOLE;	/* stderr is CONSOLE device	*/
#endif
#ifdef ARM_QEMU
	prptr->prdesc[0] = SERIAL0;	/* stdin  is SERIAL0 device	*/
	prptr->prdesc[1] = SERIAL0;	/* stdout is SERIAL0 device	*/
	prptr->prdesc[2] = SERIAL0;	/* stderr is SERIAL0 device	*/
#endif

	/* Initialize stack as if the process was called		*/

	*saddr = STACKMAGIC;
	savsp = (uint32)saddr;

	/* push arguments */
	a = (uint32 *)(&nargs + 1);	/* start of args		*/
	a += nargs -1;			/* last argument		*/
	for ( ; nargs > 4 ; nargs--)	/* machine dependent; copy args	*/
		*--saddr = *a--;	/* onto created process' stack	*/
	*--saddr = (long)procaddr;
	for(i = 11; i >= 4; i--)
		*--saddr = 0;
	for(i = 4; i > 0; i--) {
		if(i <= nargs)
			*--saddr = *a--;
		else
			*--saddr = 0;
	}
	*--saddr = (long)INITRET;	/* push on return address	*/
	*--saddr = (long)(ARMV7A_CPSR_SPR | ARMV7A_CPSR_F); /* CPSR, F bit set,		*/
                                                      /* Supervisor mode		*/
  
	prptr->prstkptr = (char *)saddr;
	restore(mask);
	return pid;

	/* The following entries on the stack must match what ctxsw	*/
	/*   expects a saved process state to contain: ret address,	*/
	/*   ebp, interrupt mask, flags, registerss, and an old SP	*/

	*--saddr = (long)procaddr;	/* Make the stack look like it's*/
					/*  half-way through a call to	*/
					/*  ctxsw that "returns" to the	*/
					/*  new process			*/
	*--saddr = savsp;		/* This will be register ebp	*/
					/*  for process exit		*/
	savsp = (uint32) saddr;		/* start of frame for ctxsw	*/
	*--saddr = 0x00000200;		/* New process runs with	*/
					/*  interrupts enabled		*/

	/* Basically, the following emulates a x86 "pushal" instruction	*/

	*--saddr = 0;		/* %eax */
	*--saddr = 0;		/* %ecx */
	*--saddr = 0;		/* %edx */
	*--saddr = 0;		/* %ebx */
	*--saddr = 0;		/* %esp; value filled in below */
	pushsp = saddr;		/*  remember this location */
	*--saddr = savsp;	/* %ebp (while finishing ctxsw) */
	*--saddr = 0;		/* %esi */
	*--saddr = 0;		/* %edi */
	*pushsp = (unsigned long) (prptr->prstkptr = (char *)saddr);
	restore(mask);
	return pid;
}

//creating Non-secure process 

/*------------------------------------------------------------------------
 *  create_NS  -  create a process to start running a procedure
 * 			-  It will create a non secure process to do some 
 * 			-  untruted operation
 *------------------------------------------------------------------------
 */
pid32	create_NS(
	  void		*procaddr,	/* procedure address		*/
	  uint32	ssize,		/* stack size in words		*/
	  pri16		priority,	/* process priority > 0		*/
	  char		*name,		/* name (for debugging)		*/
	  uint32	nargs,		/* number of args that follow	*/
	  ...
	)
{
	uint32		savsp, *pushsp;
	intmask 	mask;    	/* interrupt mask		*/
	pid32		pid;		/* stores new process id	*/
	struct	procent	*prptr;		/* pointer to proc. table entry */
	int32		i;
	uint32		*a;		/* points to list of args	*/
	uint32		*saddr;		/* stack address		*/

	mask = disable();
	if (ssize < MINSTK)
		ssize = MINSTK;
	ssize = (uint32) roundew(ssize);
	if (((saddr = (uint32 *)getstk(ssize)) ==
	    (uint32 *)SYSERR ) ||
	    (pid=newpid()) == SYSERR || priority < 1 ) {
		restore(mask);
		return SYSERR;
	}

	prcount++;
	prptr = &proctab[pid];

	/* initialize process table entry for new process */
	prptr->prstate = PR_SUSP;	/* initial state is suspended	*/
	prptr->prprio = priority;
	prptr->prstkbase = (char *)saddr;
	prptr->prstklen = ssize;
	prptr->prname[PNMLEN-1] = NULLCH;
	for (i=0 ; i<PNMLEN-1 && (prptr->prname[i]=name[i])!=NULLCH; i++)
		;
	prptr->prsem = -1;
	prptr->prparent = (pid32)getpid();
	prptr->prhasmsg = FALSE;
	/* By default make process non-secure  */
	//prptr->NS = TRUE; //depricated
	prptr->procSecInfo=getmem(sizeof(struct procSecurityInfo));
	prptr->procSecInfo->proc_NS_state=TRUE;

	/* set up initial device descriptors for the shell		*/
#ifdef ARM_BBB
	prptr->prdesc[0] = CONSOLE;	/* stdin  is CONSOLE device	*/
	prptr->prdesc[1] = CONSOLE;	/* stdout is CONSOLE device	*/
	prptr->prdesc[2] = CONSOLE;	/* stderr is CONSOLE device	*/
#endif
#ifdef ARM_QEMU
	prptr->prdesc[0] = SERIAL0;	/* stdin  is SERIAL0 device	*/
	prptr->prdesc[1] = SERIAL0;	/* stdout is SERIAL0 device	*/
	prptr->prdesc[2] = SERIAL0;	/* stderr is SERIAL0 device	*/
#endif

	/* Initialize stack as if the process was called		*/

	*saddr = STACKMAGIC;
	savsp = (uint32)saddr;

	/* push arguments */
	a = (uint32 *)(&nargs + 1);	/* start of args		*/
	a += nargs -1;			/* last argument		*/
	for ( ; nargs > 4 ; nargs--)	/* machine dependent; copy args	*/
		*--saddr = *a--;	/* onto created process' stack	*/
	*--saddr = (long)procaddr;
	for(i = 11; i >= 4; i--)
		*--saddr = 0;
	for(i = 4; i > 0; i--) {
		if(i <= nargs)
			*--saddr = *a--;
		else
			*--saddr = 0;
	}
	*--saddr = (long)INITRET;	/* push on return address	*/
	*--saddr = (long)(ARMV7A_CPSR_SPR | ARMV7A_CPSR_F); /* CPSR, F bit set,		*/
                                                      /* Supervisor mode		*/
  
	prptr->prstkptr = (char *)saddr;
	restore(mask);
	return pid;

	/* The following entries on the stack must match what ctxsw	*/
	/*   expects a saved process state to contain: ret address,	*/
	/*   ebp, interrupt mask, flags, registerss, and an old SP	*/

	*--saddr = (long)procaddr;	/* Make the stack look like it's*/
					/*  half-way through a call to	*/
					/*  ctxsw that "returns" to the	*/
					/*  new process			*/
	*--saddr = savsp;		/* This will be register ebp	*/
					/*  for process exit		*/
	savsp = (uint32) saddr;		/* start of frame for ctxsw	*/
	*--saddr = 0x00000200;		/* New process runs with	*/
					/*  interrupts enabled		*/

	/* Basically, the following emulates a x86 "pushal" instruction	*/

	*--saddr = 0;		/* %eax */
	*--saddr = 0;		/* %ecx */
	*--saddr = 0;		/* %edx */
	*--saddr = 0;		/* %ebx */
	*--saddr = 0;		/* %esp; value filled in below */
	pushsp = saddr;		/*  remember this location */
	*--saddr = savsp;	/* %ebp (while finishing ctxsw) */
	*--saddr = 0;		/* %esi */
	*--saddr = 0;		/* %edi */
	*pushsp = (unsigned long) (prptr->prstkptr = (char *)saddr);
	restore(mask);
	return pid;
}


/*------------------------------------------------------------------------
 *  getProcSecState -  return the security state of process, True emplies non secure
 *------------------------------------------------------------------------
 */
extern	bool8	getProcSecState(pid32 pid){
	
	intmask	mask;			/* Saved interrupt mask		*/
	bool8	security_state;			/* Priority to return		*/

	mask = disable();
	if (isbadpid(pid)) {
		restore(mask);
		return SYSERR;
	}
	struct procent *prptr;
	prptr=&proctab[pid];
	security_state=prptr->procSecInfo->proc_NS_state;
	restore(mask);
	return security_state;
}


/*------------------------------------------------------------------------
 *  newpid  -  Obtain a new (free) process ID
 *------------------------------------------------------------------------
 */
local	pid32	newpid(void)
{
	uint32	i;			/* iterate through all processes*/
	static	pid32 nextpid = 1;	/* position in table to try or	*/
					/*  one beyond end of table	*/

	/* check all NPROC slots */

	for (i = 0; i < NPROC; i++) {
		nextpid %= NPROC;	/* wrap around to beginning */
		if (proctab[nextpid].prstate == PR_FREE) {
			return nextpid++;
		} else {
			nextpid++;
		}
	}
	return (pid32) SYSERR;
}

