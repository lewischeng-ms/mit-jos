/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


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
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

#define H(N) handler##N
#define TY(N) TRAPHANDLER(H(N), N)
#define TN(N) TRAPHANDLER_NOEC(H(N), N)
#define L(N) .long H(N)
#define S(N) .long 0 /* skip */

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TN(0)
TN(1)
TN(2)
TN(3)
TN(4)
TN(5)
TN(6)
TN(7)
TY(8)
// TN(9) /* reserved */
TY(10)
TY(11)
TY(12)
TY(13)
TY(14)
// TN(15) /* reserved */
TN(16)
TY(17)
TN(18)
TN(19)

/* 16 IRQs */
TN(32)
TN(33)
TN(34)
TN(35)
TN(36)
TN(37)
TN(38)
TN(39)
TN(40)
TN(41)
TN(42)
TN(43)
TN(44)
TN(45)
TN(46)
TN(47)
	
TN(48)

/*
 * Lab 3: Your code here for _alltraps
 */
.global _alltraps
_alltraps:
	// Build struct Trapframe
	pushl %ds
	pushl %es
	pushal

	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es

	pushl %esp /* struct Trapframe * as argument */
	call trap
	/* the call will never return */

