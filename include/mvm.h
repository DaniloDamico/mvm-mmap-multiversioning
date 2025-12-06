#ifndef _MVM_
#define _MVM_

#define INSTRUMENT do {asm volatile("jmp 1f; cli;nop;nop;nop;nop;cli;nop;nop;nop;nop;cli;nop;nop;nop;nop; 1:"::);} while (0)

#endif
