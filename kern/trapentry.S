/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>



###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.text;								\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps;	                                                \
	.data;								\
	.long name


/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.text;								\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps; 							\
	.data;								\
	.long name

// the array pointer of interrupt vectors
.data
.globl vectors
vectors:

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

 TRAPHANDLER_NOEC(vectors0, T_DIVIDE); 
 TRAPHANDLER_NOEC(vectors1, T_DEBUG); 
 TRAPHANDLER_NOEC(vectors2, T_NMI); 
 TRAPHANDLER_NOEC(vectors3, T_BRKPT); 
 TRAPHANDLER_NOEC(vectors4, T_OFLOW); 
 TRAPHANDLER_NOEC(vectors5, T_BOUND); 
 TRAPHANDLER_NOEC(vectors6, T_ILLOP); 
 TRAPHANDLER_NOEC(vectors7, T_DEVICE); 
 TRAPHANDLER(vectors8 ,T_DBLFLT); 
 TRAPHANDLER(vectors9, -1);// Reserved
 TRAPHANDLER(vectors10 , T_TSS); 
 TRAPHANDLER(vectors11 , T_SEGNP); 
 TRAPHANDLER(vectors12 , T_STACK); 
 TRAPHANDLER(vectors13 , T_GPFLT); 
 TRAPHANDLER(vectors14 , T_PGFLT); 
 TRAPHANDLER(vectors15 , -1);// Reserved
 TRAPHANDLER_NOEC(vectors16 , T_FPERR); 
 TRAPHANDLER(vectors17 , T_ALIGN); 
 TRAPHANDLER_NOEC(vectors18 , T_MCHK); 
 TRAPHANDLER_NOEC(vectors19 , T_SIMDERR); 

 TRAPHANDLER_NOEC(vector_SYS, T_SYSCALL);


/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:

 pushw $0x0
 pushw %ds
 pushw $0x0
 pushw %es
 pushal

 movl $GD_KD, %eax
 movw %ax, %ds
 movw %ax, %es
 pushl %esp
 call trap

