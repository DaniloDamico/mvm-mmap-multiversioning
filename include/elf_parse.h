#ifndef _ELF_PARSE_
#define _ELF_PARSE_

#include <head.h>
#include <stdint.h>

#define TARGET_FUNCTIONS  128 //max number of functions to be checked for instrumentation

#define LINE_SIZE (1024) //maximum size in bytes of the line of -D elf listing

#define BLOCK 128 //max num bytes for representing the mnemonic of an instruction or its code/operands

typedef struct _target_address{
	long displacement;
	long int base_index; // registro base
	long int  scale_index; // registro indice
	unsigned long scale; // moltiplicatore
} target_address;

typedef struct _instruction_record{
	int record_index;
	char *function;//the function the instruction belongs to
	uint64_t address;
	unsigned long size;
	char indirect_jump;//'y' or 'n' - this must be 'y' for any instruction whose size is less than 5 bytes
	uint64_t middle_buffer;//this is usefull only for intructions requiring indirect jumps - 0x0 should be the default
	char type;//load 'l' or store 's'
	char rip_relative;//'y' or 'n'
	uint64_t effective_operand_address;//should be 0x0 for non RIP-relative instructions
	//whole string of the instruction
	char whole[BLOCK];
	//specific fields
	char op[BLOCK];
	char source[BLOCK];
	char dest[BLOCK];
	int data_size;
	int instrumentation_instructions;//number of instructions in the instrumentation scheme (including the original one to be instrumented or an equivalent)
	target_address target;
} instruction_record;

#define NUM_INSTRUCTIONS ((int)(SIZE/sizeof(instruction_record)))//this is the max number of instructions we can intercept

#define MAX_INST_LEN 12
#define CODE_BLOCK 512 
typedef struct _patch{
	char functional_instr[CODE_BLOCK];//additional room for instructions (if any) to be finally posted onto 'block'
	int functional_instr_size;
	char block[CODE_BLOCK];//this is the actual patch - it must terminate with a jmp to original_instruction_address+original_instruction_size
	char *code;
	uint64_t intermediate_zone_address;
	char jmp_to_intermediate[2];//the size is fixed to 2 bytes - it is a relative jump to a 8-bit relative offset
	unsigned long original_instruction_size; //this is the size of the patched area
	uint64_t original_instruction_address; //this is the address where to apply the patch
	char original_instruction_bytes[MAX_INST_LEN];
	char jmp_to_post[5];//the size is fixed to 5 bytes - it is a relative jump to a 32-bit relative offset
} patch;

#endif
