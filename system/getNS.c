/* getNS.c - getNS */

#include <xinu.h>

/*------------------------------------------------------------------------
 *  getNS  -  Return the secrity state of a process
 *------------------------------------------------------------------------
 */
bool8	getNS(
	  pid32		pid		/* Process ID			*/
	)
{
	intmask	mask;			/* Saved interrupt mask		*/
	bool8	security_state;			/* Priority to return		*/

	mask = disable();
	if (isbadpid(pid)) {
		restore(mask);
		return SYSERR;
	}
	security_state = proctab[pid].NS;
	restore(mask);
	return security_state;
}
