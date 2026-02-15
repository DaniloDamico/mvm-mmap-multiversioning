
#APPLICATION SPECIFIC STUFF
#the below specify the directory where the user application is located, the name of the executable to be generated, the name of the object file of the program and the names of the target functions to instrument 
#IMPORTANT: a Makefile in the APP dir is responsible for generating the .o file specified by APP_OBJ
APP = $(PWD)/application
EXECUTABLE = $(APP)/prog
APP_OBJ = $(APP)/prog.o
#TARGET_MODULES= a.c  sub-dir/b.c this is an example usage
TARGET_MODULES= prog.c
#TARGET_FUNCTIONS="<a>:","<b>:" this is an example usage
TARGET_FUNCTIONS="<function>:"
LIBS = -lpthread
# max number of versions for each allocated subregion
MVMM_MAX_VERSIONS ?= 10
# number of writes to trigger a version switch
#ROTATE_EVERY ?= 2


INCLUDE = $(PWD)/include
OBJ = $(PWD)/obj
LIB = $(PWD)/lib
TEMP = $(PWD)/temp
DISASSEMBLY = $(TEMP)/disassembly
DISASSEMBLY_FILE = -Ddisassembly_file=\"$(DISASSEMBLY)\"
TEMPDIR = -Dtemp_dir=$(TEMP)
SHADOW = shadow
INTERMEDIATEFILE = intermediate.S
INTERMEDIATEOBJFILE = intermediate.o
TEMPFILE = -Dtemp_file=\"$(TEMP)/$(INTERMEDIATEFILE)\"
TEMPOBJ = -Dtemp_obj_file=\"$(TEMP)/$(INTERMEDIATEOBJFILE)\"
TF=-Dtarget_functions=\"$(TARGET_FUNCTIONS)\"

#USER DEFINED STUFF - PLEASE CHANGE WHATEVER YOU NEED
USER_DEFINED = $(PWD)/user-defined
USER_DEFINED_FILE = intermediate.S
USER_DEFINED_OBJ_FILE = intermediate.o
UDTEMPDIR = -Duser_defined_dir=\"$(USER_DEFINED)\"
UDTEMPFILE = -Duser_defined_temp_file=\"$(USER_DEFINED)/$(USER_DEFINED_FILE)\"
UDTEMPOBJ = -Duser_defined_temp_obj_file=\"$(USER_DEFINED)/$(USER_DEFINED_OBJ_FILE)\"

SECURITY_FLAGS = -pie -fPIE -fstack-protector-all

ADDITIONAL_FLAGS = -O3 -DASM_PREAMBLE -DAPPLY_PATCHES -DMVMM_MAX_VERSIONS=$(MVMM_MAX_VERSIONS) # -DROTATE_EVERY=$(ROTATE_EVERY)
# -DVERBOSE
#NOTE: 
#the ASM_PREAMBLE macro enables building a demo patch for each memory access instruction
#which passess control to a trampoline that calls the the_patch(...) fuction
#offered by the MVM package (see patches/patches.c)
#the APPLY_PATCHES macro actually leads to apply the patches thar are build by the instrumentation process
#the VERBOSE macro simply leads to the massive production of output messages 


THE_VM = -DVM_NAME=\"MVM\"

all: checks backup-files file-rewriting compile-and-link restore-files

compile-and-link: movm
	export C_INCLUDE_PATH=$(PWD)/include; cd $(APP) ; make ; gcc $(APP_OBJ) $(LIB)/movm.o -o $(EXECUTABLE) $(SECURITY_FLAGS) $(ADDITIONAL_FLAGS) $(LIBS) -Xlinker --wrap=main -Xlinker --wrap=mmap
	objdump -Dw $(EXECUTABLE) > $(DISASSEMBLY) 

checks:
	@if [ -d $(APP) ]; then echo ""; else echo "application directory does not exist" ; exit 1; fi
	@./scripts/file-existence $(APP) $(TARGET_MODULES)
	@echo "PLEASE for any compiling error run 'make restore-files'\n"

base:
	./scripts/temp-dir.sh $(TEMP) $(TEMP)/$(INTERMEDIATEFILE)

head:
	cd ./src; gcc _head.c -c -I$(INCLUDE) $(SECURITY_FLAGS) $(ADDITIONAL_FLAGS) -o $(OBJ)/_head.o

startup:
	cd ./src; gcc _early_start.c -c -I$(INCLUDE) $(SECURITY_FLAGS) $(ADDITIONAL_FLAGS) -o $(OBJ)/_early_start.o

asm-patch:
	cd ./src; gcc _asm_patches.S -c -I$(INCLUDE) $(SECURITY_FLAGS) $(ADDITIONAL_FLAGS) -o $(OBJ)/_asm_patches.o

patch:
	cd ./patches; gcc patches.c -c -I$(INCLUDE) $(THE_VM) $(UDTEMPDIR) $(UDTEMPFILE) $(UDTEMPOBJ) $(SECURITY_FLAGS) $(ADDITIONAL_FLAGS) -o $(OBJ)/_patches.o
#please rember to insert whatever Makefile in the user-defined directory
	cd $(USER_DEFINED); make

movm: base head startup asm-patch patch 
	cd ./src; gcc _elf_parse.c -c $(TEMPDIR) $(TEMPFILE) $(DISASSEMBLY_FILE) $(TEMPOBJ) $(TF) $(THE_VM) -I$(INCLUDE) $(SECURITY_FLAGS) $(ADDITIONAL_FLAGS) -o $(OBJ)/_elf_parse.o
	cd $(OBJ) ; ld -i *.o -o $(LIB)/movm.o

backup-files: checks
	cd $(APP) ; touch $(EXECUTABLE) ; rm $(EXECUTABLE)
	cd $(APP) ; tar -cvf $(TEMP)/$(SHADOW)/backup.tar *

restore-files: 
	cp $(TEMP)/$(SHADOW)/backup.tar $(APP) ; cd $(APP) ; tar -xvf backup.tar ; rm backup.tar

file-rewriting:
	export MVM_TEMP_FILE=$(TEMP)/__temp_file ; ./scripts/file-processor.sh $(APP) $(TARGET_MODULES)

clean:
	find . -type f \( -name "*.o" -o -name "*.a" -o -name "*.so" -o -name "*.out" \) -delete
