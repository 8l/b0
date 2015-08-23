// B0
// 
// Copyright (C) 2000-2006, Darran Kartaschew.
// All rights reserved.
// 
// Licence
// -------
// 
// Copyright (C) 2000-2006, Darran Kartaschew.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
// 
// *  Redistributions of source code must retain the above copyright notice, this list of conditions
//    and the following disclaimer. 
// 
// *  Redistributions in binary form must reproduce the above copyright notice, this list of 
//    conditions and the following disclaimer in the documentation and/or other materials provided
//    with the distribution. 
// 
// *  Neither the name of "B0" nor the names of its contributors may be used to endorse or promote 
//    products derived from this software without specific prior written permission. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND 
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
// OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

// Uncomment to build i386 version of the compiler, else default to AMD64 version.
// #define i386


#if _MSC_VER >= 1400
	#define _CRT_SECURE_NO_DEPRECATE 
#endif

#define _POSIX_ 1

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef _MSC_VER
	#include <process.h>
#endif

#include <time.h>
#include "b0.h"

#ifndef FILENAME_MAX
	#define FILENAME_MAX 256
#endif

#ifdef _MSC_VER
	#define PATH_SEPARATOR 59
#else
	#define PATH_SEPARATOR 58
#endif

// 59 = ;
// 58 = :

/* Extern stdlib functions:

** If you need to port to another OS, then your libc
   just has to provide the following functions!
   Other than those listed below, b0 is completely
   self-contained.
   
	printf();
	fgetc();
	strcpy();
	strcmp();
	strcat();
	strrchr();
	fprintf();
	fopen();
	fclose();
	ftell();
	rewind();
	remove();
	clock();
	tolower();
	atof();
	sprintf();
	calloc();
*/

typedef struct {
	unsigned long hash;
	unsigned int type;
	unsigned int size;
	unsigned int offset;
} struc_entry;

typedef struct{
	struc_entry struc[STRUC_SIZE];
} struc_struc;

typedef struct{
	unsigned long hash;
	unsigned char token[TOKEN_MAX_SIZE];
	unsigned int token_type;
	unsigned int local_offset;		// If a proc, then this holds the current amount of space used for local variables
	long define_int;					// If this is a define, it holds the value of the define integer value.
	double define_fp;				// If this is a define, it holds the value of the define float value.
	struc_struc *struc_ptr;			// Pointer to structure if a structure.
	unsigned char token_import_name[TOKEN_MAX_SIZE]; // Real name of proc as defined by Windows.
	unsigned long token_import_lib; 	// hash of the library in which this EPROC belongs to.
} hash_table_struc;

typedef struct{
	unsigned int type;
	unsigned int offset;
	unsigned long if_while_test1;
	unsigned long if_while_test2;
	unsigned long comparison;
} if_while_struc;

typedef struct{
	FILE *handle;
	unsigned char filename[FILENAME_MAX];
	unsigned int line_count;
	int ch;
	int look_ahead_ch;
} file_struct;

int ch;							//current character in queue
int look_ahead_ch;				//look ahead character
file_struct file[MAX_LIB_DEPTH];
								//Lib / Include stack
int file_stack_ptr;				//Pointer into the file stack
FILE *code;						//pointer to code output file
FILE *data;						//pointer to data output file
FILE *bss;						//pointer to bss output file

unsigned int state;				//current instruction state
unsigned int line_count;			//current line in source
unsigned int token_stack[TOKEN_STACK_SIZE];		
								//Stack containing the current tokens to be processed.
unsigned int pp_token_stack[TOKEN_STACK_SIZE];
								//Preparser token stack!
unsigned int token;				//Pointer to current token within token stack;
unsigned int global;				//Are we at a global level?
								// If zero, we are global otherwise = hash of proc
								// we are in.
unsigned int struc_def;			// Hash of current struc being defined!
unsigned int do_process;			// Flag for structure processing.
unsigned int target;				// Target Register of line (contains hash).
unsigned int block_level = 0;		//Indentation level
hash_table_struc hash_table[HASH_TABLE_SIZE];			
								//hash table
unsigned long token_hash;			//Hash of current token
unsigned char token_buffer[TOKEN_MAX_SIZE];	
								//Buffer for tokens
unsigned int toki; 				// index into above buffer.
unsigned char filename[FILENAME_MAX];
								//Filename for when opening a file.
unsigned char tmp_filename[FILENAME_MAX];
								//Temp filename used when searching includes.
char *path;
char *b0_env;
unsigned int total_paths;
char paths[PATHS_MAX][FILENAME_MAX]; // allow upto 256 paths to be searched.
								
unsigned int asm_in_string;		//Flag used to see in if string within
								// asm block.

if_while_struc if_while_stack[TOKEN_STACK_SIZE];
								//Stack which holds the current block type
								//Index by block_level
unsigned int block_num;			//number of occurance of block.
unsigned int local_var_offset;
unsigned int dynamic_string_count;	//Count of the dynamic string decl.
clock_t time_start, time_end;
double duration;

int DEBUG = 0;					// Whether to output debugging output.
int ContinueOnAbort = 0;			// Flag to set if to continue on abort operation?
#ifdef _MSC_VER
int SOURCE_TYPE = SOURCE_PE;		// Default Source is PE output if building using MSVC++
#else
int SOURCE_TYPE = SOURCE_ELF;		// Default Source is ELF output if building anything else.
#endif
int UTF8_STRINGS = 0;  			// Encode strings as UTF8 instead of UTF16
int CLI_UTF8_STRINGS = 0;			// UTF8 strings was defined by the CLI
int SOURCE_CLI = 0;				// Output format defined by the CLI
int HeaderPrinted = 0;			// Header info block has been printed, eg -v CLI switch
int STACK_FRAME = 1;			// Generation of stack frame when calling functions.
int WarningsDisabled = 0;		// Set to disable printing of warnings.

int pp_GenCode[MAX_LIB_DEPTH];	// Preparser toggle for code generation.
int pp_ptr = 0;					// Pointer into above array.

/* New method of handling variables: (intro v0.0.13)
   What we do is fill in the variables below, and then build the instruction,
   rather than build the instruction as we go. */
   
unsigned long v_base = 0;       	// Base variable;   (hash)
unsigned int v_isStruc = 0;     	// The base variable is a Struc (1, or 0)
unsigned long v_offset = 0;     	// Offset to sub-object; (value)
unsigned int v_offset_type = 0; 	// Type of offset == state.
unsigned int v_size = 0;			// Size of structure.
unsigned int v_index = 0;       	// index into array of struc. (pos on token stack of start of array value;)
unsigned int v_target = 0;      	// pos of what we are inserting into the variable (pos on token stack).
unsigned int v_global = 0;      	// Variable is global? (if not then local)
unsigned long v_reg = 0;			// Variable to hold calculated address of structure.

#ifndef i386
const unsigned char B0_VERSION[] = "0.0.19";
#else
const unsigned char B0_VERSION[] = "0.0.19 - IA32";
#endif

const unsigned char B0_COPYRIGHT[] = "This is free software; see the source for copying conditions.  There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n";

const unsigned char TOKEN_KEYWORD[] = "if\0else\0while\0lib\0asm\0return\0exit\0proc\0push\0pop\0syscall\0sysret\0fdecstp\0fincstp\0extern\0define\0undefine\0ifdef\0endif\0ifndef\0m8\0m16\0m32\0m64\0f32\0f64\0f80\0struc\0call\0jmp\0ret\0in\0out\0as\0COMPILER_OPTION\0\0";
#ifndef i386
const unsigned char TOKEN_REG[] = "0\0r0\0r1\0r2\0r3\0r4\0r5\0r6\0r7\0r8\0r9\0r10\0r11\0r12\0r13\0r14\0r15\0\0";
const unsigned char TOKEN_REG_SHORT[] = "r0b\0r1b\0r2b\0r3b\0r4b\0r5b\0r6b\0r7b\0r8b\0r9b\0r10b\0r11b\0r12b\0r13b\0r14b\0r15b\0r0w\0r1w\0r2w\0r3w\0r4w\0r5w\0r6w\0r7w\0r8w\0r9w\0r10w\0r11w\0r12w\0r13w\0r14w\0r15w\0r0d\0r1d\0r2d\0r3d\0r4d\0r5d\0r6d\0r7d\0r8d\0r9d\0r10d\0r11d\0r12d\0r13d\0r14d\0r15d\0\0";
#else
const unsigned char TOKEN_REG[] = "0\0r0\0r1\0r2\0r3\0r4\0r5\0r6\0r7\0\0";
const unsigned char TOKEN_REG_SHORT[] = "r0b\0r1b\0r2b\0r3b\0r0w\0r1w\0r2w\0r3w\0r4w\0r5w\0r6w\0r7w\0\0";
#endif
const unsigned char TOKEN_REG_FPU[] = "fp0\0fp1\0fp2\0fp3\0fp4\0fp5\0fp6\0fp7\0\0";
const unsigned char TOKEN_FLAG[] = "CARRY\0NOCARRY\0OVERFLOW\0NOOVERFLOW\0PARITY\0NOPARITY\0ZERO\0NOTZERO\0SIGN\0NOTSIGN\0\0";
const unsigned char TOKEN_RESERVED[] = "UTF8\0UTF16\0ELF\0ELFO\0PE\0ENABLESTACKFRAME\0DISABLESTACKFRAME\0\0";

unsigned int getChar(void){
	ch = look_ahead_ch;
	if (ch == CR) {
		file[file_stack_ptr].line_count++;
		if(DEBUG)
			printf("NEW LINE - %d\n", file[file_stack_ptr].line_count);
		}
	look_ahead_ch = fgetc(file[file_stack_ptr].handle);
	if(DEBUG){
		if ((ch != CR)&&(look_ahead_ch != CR)){
			printf("ch=%c 0x%x, lch=%c 0x%x\n", ch, ch, look_ahead_ch, look_ahead_ch);
		} else {
			if (ch == CR) {
				printf("ch=CR 0x%x, ", ch);
			} else {
				printf("ch=%c 0x%x, ", ch, ch);
			}
			if (look_ahead_ch == CR) {
				printf("lch=CR 0x%x\n", look_ahead_ch);
			} else {
				printf("lch=%c 0x%x\n", look_ahead_ch, look_ahead_ch);
			}
		
		}
	}
	return(0);
}

unsigned int isAlpha(int s){
	if (((s >= 'a') && (s <= 'z'))||((s >= 'A') && (s <= 'Z')) || (s == '_')){
		return(1);
	} else {
		return(0);
	}
}

unsigned int isXDigit(int s){
	if (((s >= 'a') && (s <= 'f'))||((s >= 'A') && (s <= 'F')) || ((s >= '0') && (s <= '9')) ){
		return(1);
	} else {
		return(0);
	}
}

unsigned int isDigit(int s){
	if ((s >= '0') && (s <= '9')){
		return(1);
	} else {
		return(0);
	}
}

unsigned int isSpace(int s){
	if ((((s == SP || s == CR) || s == 0) || s == TAB) || s == LF){
		return(1);
	} else {
		return(0);
	}
}

/*--- ElfHash ---------------------------------------------------
 *  The published hash algorithm used in the UNIX ELF format
 *  for object files. Accepts a pointer to a string to be hashed
 *  and returns an unsigned long.
 *-------------------------------------------------------------*/
unsigned long ElfHash ( const unsigned char *name ){
	unsigned long h = 0, g;
	while ( *name ){
		h = ( h << 4 ) + *name++;
		g = h & 0xF0000000;
		if ( g )
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

void abort_b0(const char *s){
	if (HeaderPrinted == 0)
		PrintHeader();
	printf("Error: %s\n",s);
	if(DEBUG)
		printf("Char: %c Token: %d ",ch,token);
	printf("Filename: %s Line: %d.\n",file[file_stack_ptr].filename, (file[file_stack_ptr].line_count));
	if (ContinueOnAbort == 0) {
		time_end = clock();
		duration = (double)(time_end - time_start) / CLOCKS_PER_SEC;
		printf( "Processing Time: %2.3f seconds\n", duration );
		fclose(code);
		fclose(data);
		fclose(bss);
		if (DEBUG == 0){
			// If not debugging, get rid of the temp files
			remove("c_output.tmp");
			remove("d_output.tmp");
			remove("b_output.tmp");
		}
		exit(1);
	}
}

void insert_token( const unsigned char *name, unsigned int token_type ){
	token_hash = (ElfHash(name)) % HASH_TABLE_SIZE + 1;
	if (token_hash >= (HASH_TABLE_SIZE-1)) token_hash = 1;
	hash_table[token_hash].hash = token_hash;
	strcpy((char *) hash_table[token_hash].token, ( char *) name);
	hash_table[token_hash].token_type = token_type;	
	if(DEBUG)
		printf("#define HASH_%s 0x%lx\n", hash_table[token_hash].token, hash_table[token_hash].hash);
		// A Little hack to help rebuild the b0.h file if modding the hash table size, eg HASH_TABLE_SIZE in b0.h.
}

void insert_token_stack( unsigned int _token) {
	token_stack[token] = _token;
	token++;
	if (token >= TOKEN_STACK_SIZE) 
		abort_b0("INTERNAL: Token Stack Overflow! - Increase TOKEN_STACK_SIZE");
}

unsigned int atStackStart(void){
	if ( token != 0)
		abort_b0("Invalid construct");
	token++;
	return(1);
}

unsigned int atStackEnd(unsigned int i){
	if (token != i) 
		abort_b0("Unexpected expression/token");
	return(1);
}

unsigned int TokenIsLabelType(unsigned int i){
	if (token_stack[token] < HASH_OFFSET)
		abort_b0("Expected Token/Label");
	if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & i) != i) {
		switch(i) {
			#ifndef i386
			case TYPE_REG: abort_b0("64bit Register Expected"); break;
			#else
			case TYPE_REG: abort_b0("32bit Register Expected"); break;
			#endif
			case TYPE_REG_FPU: abort_b0("FPU Register Expected"); break;
			#ifndef i386
			case TYPE_REG_SHORT: abort_b0("non-64bit Register Expected"); break;
			#else
			case TYPE_REG_SHORT: abort_b0("non-32bit Register Expected"); break;
			#endif
			case TYPE_KEYWORD: abort_b0("Keyword Expected"); break;
			case TYPE_PROC: abort_b0("Procedure Expected"); break;
			case TYPE_EPROC: abort_b0("External Procedure Expected"); break;
			case TYPE_ELIB: abort_b0("Expected External DLL Name"); break;
			case TYPE_M8:
			case TYPE_M16:
			case TYPE_M32:
			#ifndef i386
			case TYPE_M64:
			#endif
			case TYPE_F32:
			case TYPE_F64:
			case TYPE_F80:
			case TYPE_ARRAY:
			case TYPE_LOCAL:
			case TYPE_GLOBAL: abort_b0("Variable Expected"); break;
			case TYPE_FLAG: abort_b0("CPU Flag Expected"); break;
			case 0: abort_b0("Unable to redefine Label/Token"); break;
			default: abort_b0("Unknown Construct"); break;
		}
	} 
	return(1);
}

unsigned int IsLabelAllocated(void){
	if (token_stack[token] < HASH_OFFSET)
		abort_b0("Expected Token/Label");
	if (hash_table[token_stack[token]-HASH_OFFSET].token_type != 0)
		abort_b0("Unable to redefine Label/Token");
	return(1);
}

unsigned int isHash(unsigned int i){
	if(i < HASH_OFFSET)
		abort_b0("Expected Token/Label");
	return(1);
}

unsigned int outputString(unsigned int i){
	while ((token_stack[token] != TOKEN_END_STRING) && (token != i)) {
		if (token_stack[token] < 0xffff) {
			fprintf(data, "0%xh,", token_stack[token]); // Output string as hex value rather than plain characters.
			token++;
		} else {
			fprintf(data, "0%xh,", (((token_stack[token] >> 10) & 0x3f) + (((token_stack[token] >> 16) - 1) << 6 ) + 0xd800) ); // upper 11 bits
			fprintf(data, "0%xh,", ((token_stack[token] & 0x3ff)+ 0xfc00) ); // lower 10 bits
			token++;
		}
	}
	fprintf(data, "0\n"); // Terminate the string.
	return(1);
}

unsigned int outputStringUTF8(unsigned int i){
	while ((token_stack[token] != TOKEN_END_STRING) && (token != i)) {
		if (token_stack[token] < 0x80) {
			fprintf(data, "0%xh,", token_stack[token]); // Output string as hex value rather than plain characters.
			token++;
		} else {
			if (token_stack[token] < 0x800) {
				// 2 byte encoding
				fprintf(data, "0%xh,", ((token_stack[token] >> 6) + 0xc0));
				fprintf(data, "0%xh,", ((token_stack[token] & 0x3f) + 0x80));
			} else {
				if (token_stack[token] < 0x10000){
					// 3 byte encoding
					fprintf(data, "0%xh,", ((token_stack[token] >> 12) + 0xe0));
					fprintf(data, "0%xh,", (((token_stack[token] >> 6) & 0x3f) + 0x80));
					fprintf(data, "0%xh,", ((token_stack[token] & 0x3f) + 0x80));
					
				} else {
					// 4 byte encoding
					fprintf(data, "0%xh,", ((token_stack[token] >> 18) + 0xf0));
					fprintf(data, "0%xh,", (((token_stack[token] >> 12) & 0x3f) + 0x80));
					fprintf(data, "0%xh,", (((token_stack[token] >> 6) & 0x3f) + 0x80));
					fprintf(data, "0%xh,", ((token_stack[token] & 0x3f) + 0x80));
				}
			}
			token++;
		}
	}
	fprintf(data, "0\n"); // Terminate the string.
	return(1);
}

unsigned int outputNumber(unsigned int i, int dec){
	int dec_flag;
	dec_flag = 0;
	while ((token_stack[token] < TOKEN_OFFSET) && (token != i)) {
		if (dec == NUM_DECIMAL) {
			// Only allow digits and '.' in number
			if (((token_stack[token] >= 'a') && (token_stack[token] <= 'f')) ||	(token_stack[token] == 'h'))
				abort_b0("Unexpected hexadecimal value");
			if ((dec_flag == 1)&&(token_stack[token] == '.'))
				abort_b0("Unexpected second decimal");
			if (token_stack[token] == '.')
				dec_flag = 1;
			fprintf(code, "%c", token_stack[token] );
			token++;
		} else {
			// allow all xdigits except .
			if (token_stack[token] == '.')
				abort_b0("Unexpected floating point value");
			fprintf(code, "%c", token_stack[token] );
			token++;
		}
	}
	if ((dec == NUM_DECIMAL) && (dec_flag == 0))
		fprintf(code, ".0");
	return(1);
}

unsigned int outputNumberD(unsigned int i, int dec){
	int dec_flag;
	dec_flag = 0;
	while ((token_stack[token] < TOKEN_OFFSET) && (token != i)) {
		if (dec == NUM_DECIMAL) {
			// Only allow digits and '.' in number
			if (((token_stack[token] >= 'a') && (token_stack[token] <= 'f')) ||	(token_stack[token] == 'h'))
				abort_b0("Unexpected hexadecimal value");
			if ((dec_flag == 1)&&(token_stack[token] == '.'))
				abort_b0("Unexpected second decimal");
			if (token_stack[token] == '.')
				dec_flag = 1;
			fprintf(data, "%c", token_stack[token] );
			token++;
		} else {
			// allow all xdigits except .
			if (token_stack[token] == '.')
				abort_b0("Unexpected floating point value");
			fprintf(data, "%c", token_stack[token] );
			token++;
		}
	}
	if ((dec == NUM_DECIMAL) && (dec_flag == 0))
		fprintf(data, ".0");
	return(1);
}

unsigned int SetState(void){
	switch( hash_table[token_stack[token]-HASH_OFFSET].token_type & 0xf) {
		case TYPE_M8: state = 'b'; break;
		case TYPE_M16: state = 'w'; break;
		#ifndef i386
		case TYPE_M32: state = 'd'; break;
		case TYPE_M64: state = ' '; break;
		#else
		case TYPE_M32: state = ' '; break;
		#endif
		case TYPE_F32: state = '3'; break;
		case TYPE_F64: state = '6'; break;
		case TYPE_F80: state = '8'; break;
	}
	return(1);
}

unsigned int TokenIs(unsigned int tok){
	if (token_stack[token] != tok){
		switch(tok){
			case TOKEN_AND: abort_b0("&& Expected"); break;
			case TOKEN_OR: abort_b0("| Expected"); break;
			case TOKEN_XOR: abort_b0("^ Expected"); break;
			case TOKEN_NOT: abort_b0("! Expected"); break;
			case TOKEN_EQUATE: abort_b0("= Expected"); break;
			case TOKEN_ADD: abort_b0("+ Expected"); break;
			case TOKEN_MINUS: abort_b0("- Expected"); break;
			case TOKEN_MULTIPLY: abort_b0("* Expected"); break;
			case TOKEN_DIVIDE: abort_b0("/ Expected"); break;
			case TOKEN_MODULUS: abort_b0("% Expected"); break;
			case TOKEN_S_MULTIPLY: abort_b0("~* Expected"); break;
			case TOKEN_S_DIVIDE: abort_b0("~/ Expected"); break;
			case TOKEN_S_MODULUS: abort_b0("~% Expected"); break;
			case TOKEN_RSHIFT: abort_b0(">> Expected"); break;
			case TOKEN_LSHIFT: abort_b0("<< Expected"); break;
			case TOKEN_RROTATE: abort_b0(">>> Expected"); break;
			case TOKEN_LROTATE: abort_b0("<<< Expected"); break;
			case TOKEN_EQUALS: abort_b0("== Expected"); break;
			case TOKEN_NOTEQUALS: abort_b0("!= Expected"); break;
			case TOKEN_LESSTHAN: abort_b0("< Expected"); break;
			case TOKEN_GREATERTHAN: abort_b0("> Expected"); break;
			case TOKEN_LESSTHANEQUALS: abort_b0("<= Expected"); break;
			case TOKEN_GREATERTHANEQUALS: abort_b0(">= Expected"); break;
			case TOKEN_S_LESSTHAN: abort_b0("~< Expected"); break;
			case TOKEN_S_GREATERTHAN: abort_b0("~> Expected"); break;
			case TOKEN_S_LESSTHANEQUALS: abort_b0("~<= Expected"); break;
			case TOKEN_S_GREATERTHANEQUALS: abort_b0("~>= Expected"); break;
			case TOKEN_STRING: abort_b0("Start of String Expected"); break;
			case TOKEN_END_STRING: abort_b0("End of String Expected"); break;
			case TOKEN_PARA_START: abort_b0("( Expected"); break;
			case TOKEN_PARA_END: abort_b0(") Expected"); break;
			case TOKEN_POINTER: abort_b0("& Expected"); break;
			case TOKEN_ARRAY_START: abort_b0("[ Expected"); break;
			case TOKEN_ARRAY_END: abort_b0("] Expected"); break;
			case TOKEN_FULLSTOP: abort_b0(". Expected"); break;
			default: abort_b0("Unknown Token"); break;
		}
	}
	return(1);
}

unsigned int callProc(unsigned int who, unsigned int return_reg, unsigned int i){
	int local_offset;
	int WarningIssued = 0;
	if(DEBUG)
		printf("Processing Function call with target\n");
	local_offset = 0;
	token++;          
	TokenIs(TOKEN_PARA_START);
	token++; // Move onto the next token
	
	// First set our local variable block
	// All we do in save r0 (if required), push esi, and add the amount of space used to nearest 8 bytes
	if (return_reg != HASH_r0)
		fprintf(code, "\tpush r0\n");
	
	if(STACK_FRAME){
		#ifndef i386
		fprintf(code, "\tpush r6\n\tadd r6, 0%xh\n", (((hash_table[(global-HASH_OFFSET)].local_offset/8)+1)*8) );
		#else
		fprintf(code, "\tpush r6\n\tadd r6, 0%xh\n", (((hash_table[(global-HASH_OFFSET)].local_offset/4)+1)*4) );
		#endif
	}

	while ((token_stack[token] != TOKEN_PARA_END)&&(token<i)){
		if((STACK_FRAME == 0)&&(WarningIssued == 0)&&(WarningsDisabled == 0)){
			// issue warning that passing local variables, but stack frame has not been setup
			if(HeaderPrinted == 0)
				PrintHeader();
			printf("WARNING: Stack frame creation has been disabled, current local variable\n frame will be overwritten during this procedure call\n");
			printf("Filename: %s Line: %d.\n",file[file_stack_ptr].filename, (file[file_stack_ptr].line_count));
			WarningIssued = 1;
		}
		if ((token_stack[token] == TOKEN_STRING) || (token_stack[token] == TOKEN_POINTER)) {
			if (token_stack[token] == TOKEN_POINTER){
				token++;
			}
			TokenIs(TOKEN_STRING);
			token++;
			if (UTF8_STRINGS == 0){
				fprintf(data, "UTF16_STRING B0_DynStr%d , ", dynamic_string_count);
				outputString(i);
			} else {
				fprintf(data, "UTF8_STRING B0_DynStr%d , ", dynamic_string_count);
				outputStringUTF8(i);
			}
			TokenIs(TOKEN_END_STRING);
			#ifndef i386
			fprintf(code, "\tpush r0\n\tmov r0, B0_DynStr%d\n\tmov qword [r6+0%xh], r0\n\tpop r0\n", dynamic_string_count, local_offset);
			#else
			fprintf(code, "\tpush r0\n\tmov r0, B0_DynStr%d\n\tmov dword [r6+0%xh], r0\n\tpop r0\n", dynamic_string_count, local_offset);
			#endif
						// We place the string offset into r0, and then store it rather than using "mov mem64, imm64" as this opcode
						// doesn't exist! fasm truncates the immediate to 32bits to form a valid opcode.
			dynamic_string_count++; // Inc the number of dynamic strings we have
		} else {
			if ((token_stack[token] < TOKEN_OFFSET) || (token_stack[token] == TOKEN_MINUS)) {
				// We have an immediate load
				#ifndef i386
				fprintf(code, "\tmov qword [r6+0%xh], ", local_offset);
				#else
				fprintf(code, "\tmov dword [r6+0%xh], ", local_offset);
				#endif
				if (token_stack[token] == TOKEN_MINUS) {
					token++;
					fprintf(code, "-");
				}
				outputNumber(i, NUM_INTEGER);
				fprintf(code, "\n");
				token--; // Adjust for token++ below.
			} else {
				TokenIsLabelType(TYPE_REG); // Otherwise only accept 64bit registers
				fprintf(code, "\tmov [r6+0%xh], %s\n", local_offset, hash_table[token_stack[token]-HASH_OFFSET].token);
			}
		}
		token++;
		#ifndef i386
		local_offset += 8; // Move the offset forward 8.
		#else
		local_offset += 4; // Move the offset forward 4.
		#endif
		if(token_stack[token] == TOKEN_COMMA)
			token++;
	}
	if(token >= i)
		abort_b0("Unexpected end of procedure call");
	TokenIs(TOKEN_PARA_END); // Final token should be the )
	token++;
	atStackEnd(i);
	// Lets call our procedure
	if (hash_table[who].token_type == TYPE_EPROC){
		if (SOURCE_TYPE != SOURCE_PE){
			fprintf(code, "\tcall %s\n", hash_table[who].token);
		} else {
			fprintf(code, "\tcall [%s]\n", hash_table[who].token);
		}
	} else {
		fprintf(code, "\tcall _B0_%s\n", hash_table[who].token);		
	}
	// Reset esi to point to our local variables.
	if(STACK_FRAME){
		fprintf(code, "\tpop r6\n");	// Restore our frame pointer
	}
	if (return_reg != HASH_r0){
		fprintf(code, "\tmov %s, r0\n", hash_table[return_reg].token); // Copy our result to the target reg
		fprintf(code, "\tpop r0\n"); // And restore r0, back to our default.
	}
	return(1);
}

unsigned int outputDynamicString(unsigned int i){
	token++;
	//Point to the first char.
	// dynamic_string_count = string number.
	
	if (UTF8_STRINGS == 0){
		fprintf(data, "UTF16_STRING B0_DynStr%d , ", dynamic_string_count);
		outputString(i);
	} else {
		fprintf(data, "UTF8_STRING B0_DynStr%d , ", dynamic_string_count);
		outputStringUTF8(i);
	}
	fprintf(code, "\tmov %s, B0_DynStr%d\n", hash_table[target].token, dynamic_string_count);
	dynamic_string_count++; // Inc the number of dynamic strings we have
	token++;
	return(1);
}

void PrintHelp(void){
	PrintHeader();
	printf("\nUsage: b0 [-v] [-W] [-?|-h|-l] [-f<type>] [-i<include>] [-!] [-DEBUG] [-UTF8] [-UTF16] <filename>\n");
	printf("\nWhere:\n\t-v\t\tDisplay Version Information\n");
	printf("\t-W\t\tDisable warnings during compilation\n");
	printf("\t-? or -h\tDisplay Help\n");
	printf("\t-l\t\tDisplay Software License\n");
	printf("\t-f<type>\tOuptut Format Type, 'elf','elfo' or 'pe' accepted\n");
	printf("\t-i<include>\tInclude directories for libraries\n");
	printf("\t-!\t\tContinue to compile on error (DANGEROUS)\n");
	printf("\t-DEBUG\t\tDisplay Extremely Verbose Debugging Information\n");
	printf("\t-UTF8\t\tEncode strings as UTF8\n");
	printf("\t-UTF16\t\tEncode strings as UTF16\n");
	printf("\t<filename>\tFile to compile\n");
	printf("\neg: B0 -felf -i./include -DEBUG myprog.b0\n");
	exit(0);
}

void PrintHeader(void){
	printf("b0 v%s\nCopyright (C) 2005-2006, Darran Kartaschew.\nAll rights reserved.\n", B0_VERSION);
	printf("%s\n", B0_COPYRIGHT);
	HeaderPrinted = 1;
}

void PrintLicense(void){
	printf("BSD Licence\n-----------\n\nCopyright (C) 2000-2006, Darran Kartaschew.\nAll rights reserved.\n");
	printf("\nRedistribution and use in source and binary forms, with or without\n");
	printf("modification, are permitted provided that the following conditions are met:\n");
	printf("\n");
	printf("*  Redistributions of source code must retain the above copyright notice, \n");
	printf("   this list of conditions and the following disclaimer.\n"); 
	printf("\n"); 
	printf("*  Redistributions in binary form must reproduce the above copyright notice,\n");
	printf("   this list of conditions and the following disclaimer in the documentation\n");
	printf("   and/or other materials provided with the distribution.\n"); 
	printf("\n"); 
	printf("*  Neither the name of \"B0\" nor the names of its contributors may be used\n");
	printf("   to endorse or promote products derived from this software without specific\n");
	printf("   prior written permission.\n"); 
	printf("\n");
	printf("THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n");
	printf("AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE \n");
	printf("IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE \n");
	printf("ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE \n");
	printf("LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR \n");
	printf("CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF \n");
	printf("SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n");
	printf("INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN \n");
	printf("CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) \n");
	printf("ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n");
	printf("POSSIBILITY OF SUCH DAMAGE.\n\n");
};

int dhtoi(const unsigned char *number){
	int isHex = 0; // Flag to see if string is a hex value
	int value = 0;
	const unsigned char *start_number;
	start_number = number;	// Save the string pointer.
	while (*number){
		if (((*number >= 'a') && (*number <= 'f')) || (*number == 'h')) {
			isHex = 1;
		}
		*number++;
	}
	number = start_number; // Restore our pointer.
	if (isHex) {
		while (*number){
			if (*number != 'h') {
				value = value << 4;
				if (*number < 'a') {
					value += (*number - '0');
				} else {
					value += (*number - 'a' + 10);
				}
			}
			*number++;
		}
	} else {
		while (*number){
			value *= 10;
			value += (*number - '0');
			*number++;
		}
	}
	if(DEBUG)
		printf("dhtoi = %d\n", value);
	return value;
}

unsigned int setDefine(unsigned int def_hash, unsigned int i){
	// i = end of stack;
	// token = current stack pointer;
	// def_hash = the hash value of the label we are setting;
	int isNeg = 0;
	int isFP = 0;  		// 0 = int, 1 = fp (decimal), 2 = hex (aka int)
	long value;			// Our value
	double fp_value;		// Our value in fp
	double fp_value2;	//
	
	if ((token_stack[token] == TOKEN_MINUS)||(token_stack[token] == '-')){
		isNeg = 1;
		token++;
		if(token == i)
			abort_b0("Expected value?");
	}

	//Move the value in a separate NULL terminated string;
	toki = 0;
	while ((token_stack[token] < TOKEN_OFFSET) && (token != i)) {
		token_buffer[toki] = (unsigned char)token_stack[token];
		token_buffer[toki+1] = '\0';
		toki++;
		token++;
		if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");	
	}
	
	if(DEBUG)
		printf("token_buffer = %s\n", token_buffer);
	// token_buffer now holds our value in string form.
	toki = 0;
	while (token_buffer[toki] != '\0'){
		if (token_buffer[toki] == '.'){
			// Looks like a decimal
			if (isFP == 2)
				abort_b0("Invalid construct");
			isFP = 1;
		}
		if ( ((token_buffer[toki] >= 'a') && (token_buffer[toki] <= 'f')) || (token_buffer[toki]  == 'h') ){
			if (isFP == 1)
				abort_b0("Invalid construct");
			isFP = 2;
		}
		toki++;
	}
	
	if (isFP == 1) {
		// Convert our string to a floating point value
		fp_value = atof(( char *) token_buffer);
		if (isNeg == 1)
			fp_value = 0 - fp_value; // Simple negate operation
		if(DEBUG)
			printf("atof = %f\n", fp_value);
		hash_table[def_hash].token_type = TYPE_DEFINE + TYPE_F64;
		hash_table[def_hash].define_fp = fp_value;
		
		if(DEBUG){
			fp_value2 = hash_table[def_hash].define_fp;
			printf("fp_val2 = %f\n", fp_value2);
		}
	} else {
		// Convert our string to an integer
		value = dhtoi(token_buffer);
		if (isNeg == 1)
			value = 0 - value; // Simple negate operation
		#ifndef i386
		hash_table[def_hash].token_type = TYPE_DEFINE + TYPE_M64;
		#else
		hash_table[def_hash].token_type = TYPE_DEFINE + TYPE_M32;
		#endif
		hash_table[def_hash].define_int = value;
	}
	
	if(DEBUG)
		printf("define %s; type 0%xh; value 0%lxh or %f\n", hash_table[def_hash].token, hash_table[def_hash].token_type, hash_table[def_hash].define_int, hash_table[def_hash].define_fp);
	
	return(1);
}

unsigned int checkDefine(unsigned int def_hash, unsigned int comparison, unsigned int i){
	// def_hash = the has we are testing
	// comparision = the test
	// i = end of token_stack.
	// token = current start of string of the number to test against.
	int isNeg = 0;
	int isFP = 0;  		// 0 = int, 1 = fp (decimal), 2 = hex (aka int)
	long value;			// Our value
	double fp_value;		// Our value in fp
	double fp_value2;	//
	
	if ((token_stack[token] == TOKEN_MINUS)||(token_stack[token] == '-')){
		isNeg = 1;
		token++;
		if(token == i)
			abort_b0("Expected value?");
	}

	//Move the value in a separate NULL terminated string;
	toki = 0;
	while ((token_stack[token] < TOKEN_OFFSET) && (token != i)) {
		token_buffer[toki] = (unsigned char)token_stack[token];
		token_buffer[toki+1] = '\0';
		toki++;
		token++;
		if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
	}
	// token_buffer now holds our value in string form.
	toki = 0;
	while (token_buffer[toki] != '\0'){
		if (token_buffer[toki] == '.'){
			// Looks like a decimal
			if (isFP == 2)
				abort_b0("Invalid construct");
			isFP = 1;
		}
		if ( ((token_buffer[toki] >= 'a') && (token_buffer[toki] <= 'f')) || (token_buffer[toki]  == 'h') ){
			if (isFP == 1)
				abort_b0("Invalid construct");
			isFP = 2;
		}
		toki++;
	}
	
	if (isFP == 1) {
		// Convert our string to a floating point value
		fp_value = atof(( char *) token_buffer);
		if (isNeg == 1)
			fp_value = 0 - fp_value; // Simple negate operation
		if(DEBUG)
			printf("atof = %f\n", fp_value);
	} else {
		// Convert our string to an integer
		value = dhtoi(token_buffer);
		if (isNeg == 1)
			value = 0 - value; // Simple negate operation
		if(DEBUG)
			printf("int_val = %ld\n", value);
		fp_value = value; // Convert long to double?
	}
	
	// Our test values have been converted
	// Check to see if our hash is a DEFINE or exists?
	if ((hash_table[def_hash].token_type & TYPE_DEFINE) != TYPE_DEFINE)
		return(0); // Isn't a define or doesn't exist, then exit
	if ((hash_table[def_hash].token_type & TYPE_F64) == TYPE_F64){
		fp_value2 = hash_table[def_hash].define_fp;
	} else {
		fp_value2 = hash_table[def_hash].define_int;
		if(DEBUG)
			printf("loading fp_value2 with int\n");
	};
	if(DEBUG)
		printf("define_val = %f\ncheck_val = %f\n", fp_value2, fp_value);
	// fp_value = our test against value
	// fp_value2 = value of define.
	
	switch(comparison){
		case TOKEN_EQUALS: if(fp_value2 == fp_value) return(1); break;
		case TOKEN_NOTEQUALS: if(fp_value2 != fp_value) return(1); break;
		case TOKEN_LESSTHAN: if(fp_value2 < fp_value) return(1); break;
		case TOKEN_GREATERTHAN: if(fp_value2 > fp_value) return(1); break;
		case TOKEN_LESSTHANEQUALS: if(fp_value2 <= fp_value) return(1); break;
		case TOKEN_GREATERTHANEQUALS: if(fp_value2 >= fp_value) return(1); break;
		case TOKEN_S_LESSTHAN: if(fp_value2 < fp_value) return(1); break;
		case TOKEN_S_GREATERTHAN: if(fp_value2 > fp_value) return(1); break;
		case TOKEN_S_LESSTHANEQUALS: if(fp_value2 >= fp_value) return(1); break;
		case TOKEN_S_GREATERTHANEQUALS: if(fp_value2 <= fp_value) return(1); break;
		default: abort_b0("Invalid Construct"); break;
	}
	return(0);
}


unsigned int preparse_token_stack(void){
	unsigned int i, j, k, pp_token, skiptoken, comparison = 0, hasDefines = 0;
	double fp_value = 0.0;
	long value = 0;
	
	int isFP = 0;  			// 0 = int, 1 = fp (decimal), 2 = hex (aka int)
	int isFP2 = 0;
	long value2 = 0;			// Our value
	double fp_value2 = 0.0;	//

	struc_struc *struc_ptr;	// Pointer to variable structure

			
	j = 0;
	i = token; // i holds the number of tokens to process.
	if(DEBUG){
		printf("PREPARSING STACK : ");
		for (token = 0; token < i; token++){
			printf("0x%x ", token_stack[token]);
		}
		printf("\n");
	}
	
	// Let's do a quick scan of the stack, and if no defines are found,
	// skip processing.
	
	for (token = 0; token < i; token++){
		if (token_stack[token] > HASH_OFFSET){
			if (((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_DEFINE) == TYPE_DEFINE)
				|| ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_STRUC) == TYPE_STRUC))
				hasDefines = 1;
		}
	}
	if (hasDefines == 1){
		// The stack may have something we need to handle...
		if(DEBUG)
			printf("Stack contains defines - starting to process\n");
		pp_token = 0;
		token = 0;
		isFP = 0;
		
		if ((token_stack[token] == TOKEN_PREPARSER)&&((token_stack[token+1] != HASH_define+HASH_OFFSET)||(token_stack[token+1] == HASH_undefine+HASH_OFFSET))){
			skiptoken = 1;
		} else {
			if (token_stack[token] > HASH_OFFSET){
				if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_STRUC) == TYPE_STRUC) {
					skiptoken = 1; // Don't process the definition if the very first token is a defined structure...
				} else {
					skiptoken = 0;
				}
			} else {
				skiptoken = 0;
			}
		}
		while (token < i){
			if(DEBUG)
				printf("skiptoken = %d ; token = 0x%x\n", skiptoken, token_stack[token]);
			
			if (token_stack[token] == TOKEN_STRING){
				hasDefines = 0;
				if(DEBUG)
					printf("Turning off preprocessor due to string\n");
			}
			if (token_stack[token] == TOKEN_END_STRING){
				hasDefines = 1;
				if(DEBUG)
					printf("Turning on preprocessor due to end of string\n");
			}
			
			if (hasDefines) {
				if (token_stack[token] > HASH_OFFSET){
					if (((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_DEFINE) == TYPE_DEFINE) ||
						((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_STRUC) == TYPE_STRUC)) {
						//Look like we have hit a define.
						if (skiptoken == 0){
							// Looks like we don't skip this one.
							if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_DEFINE) == TYPE_DEFINE){
								if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_F64) == TYPE_F64){
									fp_value = hash_table[token_stack[token]-HASH_OFFSET].define_fp;
									isFP = 1;
									if(DEBUG)
										printf("Change isFP = 1\n");
								} else {
									value = hash_table[token_stack[token]-HASH_OFFSET].define_int;
									isFP = 0;
								};
							} else {
								// We must have a struc definition...
								isFP = 0;
								//Lets first get the structure pointer...
								struc_ptr = hash_table[token_stack[token]-HASH_OFFSET].struc_ptr;
								if(DEBUG)
									printf("Define: struc_ptr = %p\n", struc_ptr);
								value = 0;  // We set this to zero, just incase there is no fullstop to indicate a sub-element.
								if (token_stack[token+1] == TOKEN_FULLSTOP) {
									//We have a sub-object of a larger structure;
									if (DEBUG)
										printf("Sub-element of variable, eg a structure is being used\n");
									token++;
									token++;
									k = 0;
									while ((struc_ptr->struc[k].hash != token_stack[token]-HASH_OFFSET) &&
											(struc_ptr->struc[k].hash != 0))
												k++;
									if (struc_ptr->struc[k].hash == 0)
										abort_b0("Structure does not contain sub-object defined");
									
									value = struc_ptr->struc[k].offset;							
								}
							}
							token++;
							// We have our value, so let's see if the next token is a math operator?
							while ((((token_stack[token] >= TOKEN_ADD) && (token_stack[token] <= TOKEN_DIVIDE))||((token_stack[token] == TOKEN_LSHIFT) || (token_stack[token] == TOKEN_RSHIFT) )) && (token != i)) {
								comparison = token_stack[token];
								if(DEBUG)
									printf("operation = 0x%x\n", comparison);
								token++;
								if (token_stack[token] < TOKEN_OFFSET) {
									// Looks like a number!
									//Move the value in a separate NULL terminated string;
									toki = 0;
									while ((token_stack[token] < TOKEN_OFFSET) && (token != i)) {
										token_buffer[toki] = (unsigned char)token_stack[token];
										token_buffer[toki+1] = '\0';
										toki++;
										token++;
										if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
									}
									// token_buffer now holds our value in string form.
									toki = 0;
									while (token_buffer[toki] != '\0'){
										if (token_buffer[toki] == '.'){
											// Looks like a decimal
											if (isFP2 == 2)
												abort_b0("Invalid construct");
											isFP2 = 1;
										}
										if ( ((token_buffer[toki] >= 'a') && (token_buffer[toki] <= 'f')) || (token_buffer[toki]  == 'h') ){
											if (isFP == 1)
												abort_b0("Invalid construct");
											isFP2 = 2;
										}
										toki++;
									}
									
									if (isFP2 == 1) {
										// Convert our string to a floating point value
										fp_value2 = atof(( char *) token_buffer);
										if(DEBUG)
											printf("pp_atof = %f\n", fp_value2);
									} else {
										// Convert our string to an integer
										value2 = dhtoi(token_buffer);
										if(DEBUG)
											printf("pp_int_val = %ld\n", value2);
										isFP2 = 0;
									}
								} else {
									if (token_stack[token] > HASH_OFFSET){
										if (((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_DEFINE) == TYPE_DEFINE) ||
											((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_STRUC) == TYPE_STRUC))  {
											if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_DEFINE) == TYPE_DEFINE){
												if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_F64) == TYPE_F64){
													fp_value2 = hash_table[token_stack[token]-HASH_OFFSET].define_fp;
													isFP2 = 1;
												} else {
													value2 = hash_table[token_stack[token]-HASH_OFFSET].define_int;
													isFP2 = 0;
												};
												token++;
											} else {
												// Looks like we have a structure definition
												isFP2 = 0;
												//Lets first get the structure pointer...
												struc_ptr = hash_table[token_stack[token]-HASH_OFFSET].struc_ptr;
												if(DEBUG)
													printf("Define: struc_ptr = %p\n", struc_ptr);
												token++;
												if (token_stack[token] == TOKEN_FULLSTOP) {
													//We have a sub-object of a larger structure;
													if (DEBUG)
														printf("Sub-element of variable, eg a structure is being used\n");
													token++;
													k = 0;
													while ((struc_ptr->struc[k].hash != token_stack[token]-HASH_OFFSET) &&
															(struc_ptr->struc[k].hash != 0))
																k++;
													if (struc_ptr->struc[k].hash == 0)
														abort_b0("Structure does not contain sub-object defined");
													
													value2 = struc_ptr->struc[k].offset;		
													token++;					
												} else {
													value2 = 0; //  WTF? but we need to handle 0 offsets as well...
												}
												//token++;
											}
										} else {
											value2 = 0;
											isFP = 0;
											j = 1;
										}
									} else {
										//Looks like another token?
										abort_b0("Invalid Construct");
									}
								}
								if (isFP == 0){
									//current value is a int.
									if (isFP2 == 0){
										// Our read value is a int
										switch(comparison){
											case TOKEN_ADD: value += value2; break;
											case TOKEN_MINUS: value -= value2; break;
											case TOKEN_MULTIPLY: value = value * value2; break;
											case TOKEN_DIVIDE: value = value / value2; break;
											case TOKEN_LSHIFT: value = value << value2; break;
											case TOKEN_RSHIFT: value = value >> value2; break;
										}
									} else {
										// Out read value is a float
										switch(comparison){
											case TOKEN_ADD: fp_value = value + fp_value2; break;
											case TOKEN_MINUS: fp_value = value - fp_value2; break;
											case TOKEN_MULTIPLY: fp_value = value * fp_value2; break;
											case TOKEN_DIVIDE: fp_value = value / fp_value2; break;
											default: abort_b0("Shift operations are not valid when dealing with floating point definitions"); break;
										}
										isFP = 1;
										if(DEBUG)
											printf("Changle isFP = 1\n");
									}
								} else {
									//current value is a float.
									if (isFP2 == 0){
										// Our read value is a int
										switch(comparison){
											case TOKEN_ADD: fp_value = fp_value + value2; break;
											case TOKEN_MINUS: fp_value = fp_value - value2; break;
											case TOKEN_MULTIPLY: fp_value = fp_value * value2; break;
											case TOKEN_DIVIDE: fp_value = fp_value / value2; break;
											default: abort_b0("Shift operations are not valid when dealing with floating point definitions"); break;
										}
									} else {
										// Out read value is a float
										switch(comparison){
											case TOKEN_ADD: fp_value = fp_value + fp_value2; break;
											case TOKEN_MINUS: fp_value = fp_value - fp_value2; break;
											case TOKEN_MULTIPLY: fp_value = fp_value * fp_value2; break;
											case TOKEN_DIVIDE: fp_value = fp_value / fp_value2; break;
											default: abort_b0("Shift operations are not valid when dealing with floating point definitions"); break;
										}
									}
								}
							}
							if (isFP == 0){
								sprintf((char *) token_buffer, "%ld", value);
								if(DEBUG)
									printf("int_sprintf = %s\n", token_buffer);
							} else {
								sprintf((char *) token_buffer, "%1.16f", fp_value);
								if(DEBUG)
									printf("fp_sprintf = %s\n", token_buffer);
							}
							toki = 0;
							while (token_buffer[toki] != 0){
								pp_token_stack[pp_token] = token_buffer[toki];
								pp_token++;
								toki++;
								if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
								if (pp_token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: PP Token stack overflow during preprocessing! - Increase TOKEN_STACK_SIZE");
							}
							if (j == 1){
								pp_token_stack[pp_token] = comparison;
								pp_token++;
								j = 0;
								if (pp_token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: PP Token stack overflow during preprocessing! - Increase TOKEN_STACK_SIZE");
							}
						} else {
							pp_token_stack[pp_token] = token_stack[token];
							token++;
							pp_token++;
							skiptoken = 0;
							if (pp_token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: PP Token stack overflow during preprocessing! - Increase TOKEN_STACK_SIZE");
						}
					} else {
						pp_token_stack[pp_token] = token_stack[token];
						token++;
						pp_token++;
						if (pp_token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: PP Token stack overflow during preprocessing! - Increase TOKEN_STACK_SIZE");
					}
				} else {
					// We have a number or operator, so just skip ahead
					pp_token_stack[pp_token] = token_stack[token];
					token++;
					pp_token++;
					if (pp_token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: PP Token stack overflow during preprocessing! - Increase TOKEN_STACK_SIZE");
				}
			} else {
				// We have a number or operator, so just skip ahead
				pp_token_stack[pp_token] = token_stack[token];
				token++;
				pp_token++;
				if (pp_token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: PP Token stack overflow during preprocessing! - Increase TOKEN_STACK_SIZE");
			}
		}
		// Now copy the pp_token_stack to token_stack.
		i = pp_token;
		hasDefines = 1;
		for (pp_token = 0; pp_token < i; pp_token++){
			token_stack[pp_token] = pp_token_stack[pp_token];
			
			if (token_stack[pp_token] == TOKEN_STRING){
				hasDefines = 0;
				if(DEBUG)
					printf("Turning off preprocessor due to string\n");
			}
			if (token_stack[pp_token] == TOKEN_END_STRING){
				hasDefines = 1;
				if(DEBUG)
					printf("Turning on preprocessor due to end of string\n");
			}

			if (hasDefines){
				if (token_stack[pp_token] == '-')
					token_stack[pp_token] = TOKEN_MINUS;
			}
		}
		token = i; // Set our new token count.
	} else {
		if(DEBUG)
			printf("Stack does not contatin defines - skip preparse stage\n");
	}
	if(token >= TOKEN_STACK_SIZE) abort_b0("INTERNAL: Token stack overflow post preprocessing! - Increase TOKEN_STACK_SIZE");
	return(1);
}

void scan_env(char *str){
	int i;
	if (total_paths > PATHS_MAX)
		return;		//buffer already full
	while(*str){
		i = 0;
		while((*str != PATH_SEPARATOR)&&(*str)){
			paths[total_paths][i] = *str++;
			i++;
			if (i >= FILENAME_MAX)
				abort_b0("File path supplied too large");
		}
		if(paths[total_paths][i-1] != '/')
			paths[total_paths][i++] = '/'; // add terminating slash if not there
		paths[total_paths][i] = '\0';		 // Null terminate the string.
		total_paths++;
		if (total_paths >= PATHS_MAX)
			return;  // Return, as the path buffer is now full.
		if (!*str)
			return;
		*str++;
	}
}

unsigned int if_while_block(unsigned int i){
	atStackStart();
	if (ch != '{')	// While statements are to be followed immediately by a block.
		abort_b0("{ Expected");
	if_while_stack[block_level].type = (token_stack[0]-HASH_OFFSET);
	if ((token_stack[0]-HASH_OFFSET) == HASH_while)
		block_num++;
	if_while_stack[block_level].offset = block_num;
	
	TokenIs(TOKEN_PARA_START);
	token++; // Lets see what we are testing?
	if (token_stack[token] == TOKEN_PARA_END) 
		abort_b0("Unexpected ')'");
	
	// Process the first item...
	if ((token_stack[token] < HASH_OFFSET) && (token_stack[token] != TOKEN_MODULUS))
		abort_b0("Expected Token/Label");
	if (token_stack[token] == TOKEN_MODULUS)
		token++;		// Skip past this flag marker
	if (((hash_table[(token_stack[token]-HASH_OFFSET)].token_type != TYPE_REG) && (hash_table[(token_stack[token]-HASH_OFFSET)].token_type != TYPE_REG_FPU)) && (hash_table[(token_stack[token]-HASH_OFFSET)].token_type != TYPE_FLAG))
		#ifndef i386
		abort_b0("Expected 64bit Register, FPU Register or CPU Flag");
		#else
		abort_b0("Expected 32bit Register, FPU Register or CPU Flag");
		#endif
	
	if (hash_table[(token_stack[token]-HASH_OFFSET)].token_type == TYPE_FLAG){
		if (token_stack[(token-1)] != TOKEN_MODULUS)
		#ifndef i386
			abort_b0("Expected 64bit Register, FPU Register or CPU Flag");
		#else
			abort_b0("Expected 32bit Register, FPU Register or CPU Flag");
		#endif
	}
	
	if_while_stack[block_level].if_while_test1 = hash_table[(token_stack[token]-HASH_OFFSET)].hash; 
	token++;	// goto the next token?
	
	if (token_stack[token] == TOKEN_PARA_END) {
		// Looks like we are testing against zero?
		if_while_stack[block_level].comparison = TOKEN_NOTEQUALS;
		if_while_stack[block_level].if_while_test2 = HASH_zero;
		token++;
		atStackEnd(i);
		return(0);
	} 
	
	if (hash_table[if_while_stack[block_level].if_while_test1].token_type == TYPE_FLAG)
		abort_b0("Expected ) - Comparisons cannot be performed on flags?");
	
	if ((token_stack[token] < TOKEN_EQUALS) || (token_stack[token] > TOKEN_GREATERTHAN))
		abort_b0("Expected comparison test");
	
	token++;
	
	if (token_stack[token] < HASH_OFFSET) 
		abort_b0("Expected Token/Label");
	if ((hash_table[(token_stack[token]-HASH_OFFSET)].token_type != TYPE_REG) && (hash_table[(token_stack[token]-HASH_OFFSET)].token_type != TYPE_REG_FPU))
		#ifndef i386
		abort_b0("Expected 64bit or FPU Register");
		#else
		abort_b0("Expected 32bit or FPU Register");
		#endif
		
	if_while_stack[block_level].if_while_test2 = hash_table[(token_stack[token]-HASH_OFFSET)].hash;

	token++;
	TokenIs(TOKEN_PARA_END);
	if_while_stack[block_level].comparison = token_stack[(token-2)]; // Save the type of test for later
	token++;
	atStackEnd(i);
	return(0);
}

void ScanForDupStrucLabel(unsigned long dest_table, unsigned long source_hash){
	unsigned int j; // Count of hashes to check
	struc_struc *ptr_struc; // Pointer to struc
	
	ptr_struc = hash_table[dest_table].struc_ptr;
	for (j = 0; j < hash_table[dest_table].local_offset; j++){
		if (ptr_struc->struc[j].hash == source_hash)
			abort_b0("Duplicate label found when constructing structure");
	}
}

unsigned int BuildLabelInfo(unsigned int i){
	struc_struc *struc_ptr;			// Pointer to variable structure
	unsigned j;

	v_base = token_stack[token]-HASH_OFFSET;
	SetState();
	v_offset_type = state;
	if ((hash_table[v_base].token_type & TYPE_GLOBAL) == TYPE_GLOBAL) {
		v_global = 1;
	} else {
		v_global = 0;
	}
	if ((hash_table[v_base].token_type & TYPE_VSTRUC) == TYPE_VSTRUC) {
		v_isStruc = 1;
		v_size = hash_table[v_base].local_offset;
	} else {
		v_isStruc = 0;
		switch(state){
			case 'b': v_size = 1; break;
			case 'w': v_size = 2; break;
			#ifndef i386
			case 'd': v_size = 4; break;
			case ' ': v_size = 8; break;
			#else
			case ' ': v_size = 4; break;
			#endif
			case '3': v_size = 4; break;
			case '6': v_size = 8; break;
			case '8': v_size = 10; break;
		}
	}
	if(DEBUG)
		printf("v_isStruc = %d; v_global = %d\n", v_isStruc, v_global);
	token++;
	if (token == i)
		return(0);
		
	if (token_stack[token] == TOKEN_ARRAY_START){
		if(DEBUG)
			printf("Array index value defined\n");
		token++;
		v_index = token;
		if (token_stack[token] == TOKEN_ARRAY_END)
			abort_b0("Unexpected ]");
		while ((token_stack[token] != TOKEN_ARRAY_END)&&(token != i)){
			token++;
		}
		if (token == i)
			abort_b0("Unexpected end of instruction");
		TokenIs(TOKEN_ARRAY_END);
		token++;
	}
	if (token == i)
		return(0);
	
	if (token_stack[token] == TOKEN_FULLSTOP) {
		//We have a sub-object of a larger structure;
		if (DEBUG)
			printf("Sub-element of variable, eg a structure is being used\n");
		// Now let's find the sub-object within the structure information.
		if (v_isStruc == 0)
			abort_b0("Structure element defined on Non-structure variable");
		token++;
		// token now points to the hash of the struc sub-object.
		isHash(token_stack[token]);
		struc_ptr = hash_table[v_base].struc_ptr;
		if(DEBUG)
			printf(" struc_ptr = %p\n", struc_ptr);
		j = 0;
		while ((struc_ptr->struc[j].hash != token_stack[token]-HASH_OFFSET) &&
				(struc_ptr->struc[j].hash != 0))
					j++;
		if (struc_ptr->struc[j].hash == 0)
			abort_b0("Structure does not contain sub-object defined");
		v_offset_type = struc_ptr->struc[j].type & 0xf;
		switch(v_offset_type){
			case TYPE_M8: state = 'b'; break;
			case TYPE_M16: state = 'w'; break;
			#ifndef i386
			case TYPE_M32: state = 'd'; break;
			case TYPE_M64: state = ' '; break;
			#else
			case TYPE_M32: state = ' '; break;
			#endif
			case TYPE_F32: state = '3'; break;
			case TYPE_F64: state = '6'; break;
			case TYPE_F80: state = '8'; break;		
		}
		// We had better ensure that state was set correctly
		v_offset_type = state;
		v_offset = struc_ptr->struc[j].offset;
		
		// When operating with variable structures, .local_offset is the size of the structure. 
		// Read it's offset to get the size of the structure.
		
		v_size = hash_table[v_base].local_offset;
		token++;				
	}
	if(token == i)
		return(0);
	TokenIs(TOKEN_EQUATE);
	return(0);
} 

void DisplayLabelInfo(void){
	printf("Variable Info:\n  v_base = 0x%lx\n", v_base);
	printf("  v_isStruc     = 0x%x\n", v_isStruc);
	printf("  v_offset      = 0x%lx\n", v_offset);
	printf("  v_offset_type = %c\n", v_offset_type);
	printf("  v_size        = 0x%x\n", v_size);
	printf("  v_target      = 0x%x\n", v_target);
	printf("  v_global      = 0x%x\n", v_global);
	printf("  v_index       = 0x%x\n", v_index);	
}

void Set_v_reg(void){
	if (v_index == 0) {
		v_reg = HASH_r6;
	} else {
		if (token_stack[v_index] > TOKEN_OFFSET){
			if(token_stack[v_index]-HASH_OFFSET != HASH_r6){
				v_reg = HASH_r6;					
			} else {
				#ifndef i386
				v_reg = HASH_r15; // This should never happen?
				#else
				v_reg = HASH_r5; // This should never happen?
				#endif
			}
		} else {
			v_reg = HASH_r6;
		}				
	}

	if (token_stack[v_target] > TOKEN_OFFSET) {
		#ifndef i386
		if (v_reg == HASH_r15){
		#else
		if (v_reg == HASH_r5){
		#endif
		// Our index is HASH_r6!
			#ifndef i386
			if (token_stack[v_target]-HASH_OFFSET == HASH_r15)
				v_reg = HASH_r14;
			#else
			if (token_stack[v_target]-HASH_OFFSET == HASH_r5)
 				v_reg = HASH_r4;
			#endif
		} else {
			if (token_stack[v_target]-HASH_OFFSET == HASH_r6){
				// Just check that the index isn't r15 first!
				if (v_index == 0){
					#ifndef i386
					v_reg = HASH_r15;
					#else
					v_reg = HASH_r5;
					#endif
				} else {
					if (token_stack[v_index] > TOKEN_OFFSET) {
						#ifndef i386
						if (token_stack[v_index]-HASH_OFFSET == HASH_r15){
							v_reg = HASH_r14;
						#else
						if (token_stack[v_index]-HASH_OFFSET == HASH_r5){
							v_reg = HASH_r4;						
						#endif
						} else {
							#ifndef i386
							v_reg = HASH_r15;
							#else
							v_reg = HASH_r5;
							#endif
						}
					}
				}
			}
		}
	}
}

unsigned int v_size_is_p2(unsigned int _size){
	switch(_size){
		case 1 : return(0); break;
		case 2 : return(1); break;
		case 4 : return(2); break;
		case 8 : return(3); break;
		case 16 : return(4); break;
		case 32 : return(5); break;
		case 64 : return(6); break;
		case 128 : return(7); break;
		case 256 : return(8); break;
		case 512 : return(9); break;
		case 1024 : return(10); break;
		case 2048 : return(11); break;
		case 4096 : return(12); break;
		case 8192 : return(13); break;
		case 16384 : return(14); break;
		case 32768 : return(15); break;
		case 65536 : return(16); break;
		case 131072 : return(17); break;
		case 262144 : return(18); break;
		case 524288 : return(19); break;
		case 1048576 : return(20); break;
		case 2097152 : return(21); break;
		case 4194304 : return(22); break;
		case 8388608 : return(23); break;
		case 16777216 : return(24); break;
		case 33554432 : return(25); break;
		case 67108864 : return(26); break;
		case 134217728 : return(27); break;
		case 268435456 : return(28); break;
		case 536870912 : return(29); break;
		case 1073741824 : return(30); break;
		case 2147483648 : return(31); break;
		default : return(0);
	}
};

void Calculate_label_address(unsigned int i){
	unsigned int p2_valid = 0;
	if (v_global == 0){
		fprintf(code, "\tlea %s, [r6+_B0_%s_%s]\n", hash_table[v_reg].token, hash_table[(global-HASH_OFFSET)].token, hash_table[v_base].token);
	} else {
		fprintf(code, "\tmov %s, _B0_%s\n", hash_table[v_reg].token, hash_table[v_base].token);
	}
	// Our reg now points to the base of the structure.
	
	if (v_index > 0) {
		//We have an index to worry about.
		if (token_stack[v_index] > TOKEN_OFFSET) {
			token = v_index;
			TokenIsLabelType(TYPE_REG);
			// Crap, it's a reg.
			if ((p2_valid = v_size_is_p2(v_size))){ //v_size_is_p2 returns a shift value. If 0, shift value cannot be found.
					// Rather than using mul, we use a shl to calculate the index into the structure!
				fprintf(code, "\tpush %s\n", hash_table[token_stack[v_index]-HASH_OFFSET].token);
				fprintf(code, "\tshl %s, %d\n", hash_table[token_stack[v_index]-HASH_OFFSET].token, p2_valid);
				fprintf(code, "\tadd %s, %s\n", hash_table[v_reg].token, hash_table[token_stack[v_index]-HASH_OFFSET].token);
				fprintf(code, "\tpop %s\n", hash_table[token_stack[v_index]-HASH_OFFSET].token);
			} else {
				fprintf(code, "\tpush r0\n\tpush r3\n");
				// Load r0, with the size, unless r0 is the index...
				if(token_stack[v_index]-HASH_OFFSET == HASH_r0){
					// The index is r0... well move it to r1
					fprintf(code, "\tpush r1\n\tmov r1, r0\n");
					fprintf(code, "\tmov r0, 0%xh\n", v_size);
					fprintf(code, "\tmul r1\n");
					fprintf(code, "\tadd %s, r0\n", hash_table[v_reg].token);
					fprintf(code, "\tpop r1\n");
				} else {
					fprintf(code, "\tmov r0, 0%xh\n", v_size);
					fprintf(code, "\tmul %s\n", hash_table[token_stack[v_index]-HASH_OFFSET].token);
					fprintf(code, "\tadd %s, r0\n", hash_table[v_reg].token);
				}
				fprintf(code, "\tpop r3\n\tpop r0\n");		
			}				
		} else {
			// Easy, it's an immediate.
			if (v_size != 0){
				fprintf(code, "\tadd %s, ",hash_table[v_reg].token); 
				token = v_index;
				outputNumber(i, NUM_INTEGER);
				fprintf(code, "*0%xh\n", v_size);
			}
		}
	}
	// The index (if any) has been dealt with.
	// Now add the variable offset.
	if (v_offset > 0){
		fprintf(code, "\tadd %s, 0%lxh\n", hash_table[v_reg].token, v_offset);
	}
}

void Calculate_NSLabel_address(unsigned int i){
	if (state != '8'){
		if (v_global == 0){
			fprintf(code, "[r6+_B0_%s_%s", hash_table[(global-HASH_OFFSET)].token, hash_table[v_base].token);
		} else {
			fprintf(code, "[_B0_%s", hash_table[v_base].token);
		}
	}
	
	if (v_index != 0){
		// We have an index to work out as well
		// But we need to handle 80bit FPU offsets intelligently.
		if(state != '8'){
			// Normal register, this is nice and easy.
			switch(state){
				case 'b' : fprintf(code, "+"); break;
				case 'w' : fprintf(code, "+2*"); break;
				#ifndef i386
				case 'd' : fprintf(code, "+4*"); break;
				case ' ' : fprintf(code, "+8*"); break;
				#else
				case ' ' : fprintf(code, "+4*"); break;
				#endif
				case '3' : fprintf(code, "+4*"); break;
				case '6' : fprintf(code, "+8*"); break;
			}
			if (token_stack[v_index] > TOKEN_OFFSET){
				// We have a reg, 
				fprintf(code, "%s", hash_table[token_stack[v_index]-HASH_OFFSET].token);						
			} else {
				// We have an immediate
				token = v_index;
				outputNumber(i, NUM_INTEGER);
			}
			fprintf(code, "]");
		} else {
			// We have to deal with a pointer to an 80bit FPU reg with an index value!
			if(token_stack[v_index] < TOKEN_OFFSET){
				//Looks like an immediate, so is easy
				if (v_global == 0){
					fprintf(code, "lea %s, [r6+_B0_%s_%s", hash_table[target].token, hash_table[(global-HASH_OFFSET)].token, hash_table[v_base].token);
				} else {
					fprintf(code, "lea %s, [_B0_%s", hash_table[target].token, hash_table[v_base].token);
				}
				fprintf(code, "+10*");
				token = v_index;
				outputNumber(i, NUM_INTEGER);
				fprintf(code, "]");
			} else {
				// we have a reg!
				if ((token_stack[v_index]-HASH_OFFSET)!=target){
					fprintf(code, "\tmov %s, %s\n", hash_table[target].token, hash_table[token_stack[v_index]-HASH_OFFSET].token);
					v_index = 0; // set a new v_index to target.
				}
				fprintf(code, "\tlea %s, [%s+%s*4]\n", hash_table[token_stack[v_index]-HASH_OFFSET].token, hash_table[token_stack[v_index]-HASH_OFFSET].token, hash_table[token_stack[v_index]-HASH_OFFSET].token);	// Multiply the index by 5
				if ((SOURCE_TYPE == SOURCE_ELFO)&&(v_global == 1)){
					fprintf(code, "\tlea %s, [%s*2]\n", hash_table[target].token, hash_table[token_stack[v_index]-HASH_OFFSET].token);		 // Multiple the index again by 2
					if (target != HASH_r6){
						fprintf(code, "\tpush r6\n\tmov r6, _B0_%s\n\tadd %s, r6\n\tpop r6",hash_table[v_base].token,hash_table[target].token);
					} else {
						fprintf(code, "\tpush r0\n\tmov r0, _B0_%s\n\tadd %s, r0\n\tpop r0",hash_table[v_base].token,hash_table[target].token);
					}
				} else {	
					if(v_global == 0){
						fprintf(code, "\tlea %s, [r6+%s*2+_B0_%s_%s]", hash_table[target].token,hash_table[token_stack[v_index]-HASH_OFFSET].token, hash_table[(global-HASH_OFFSET)].token, hash_table[v_base].token);		 // Multiple the index again by 2 and add offset	
					} else {
						fprintf(code, "\tlea %s, [%s*2+_B0_%s]", hash_table[target].token, hash_table[token_stack[v_index]-HASH_OFFSET].token, hash_table[v_base].token);		 // Multiple the index again by 2 and add offset						
					}			
				}
			}										
		}
	} else {
		if(state == '8'){
			if (v_global == 0){
				fprintf(code, "\tlea %s, [r6+_B0_%s_%s]", hash_table[target].token, hash_table[(global-HASH_OFFSET)].token, hash_table[v_base].token);
			} else {
				fprintf(code, "\tmov %s, _B0_%s", hash_table[target].token, hash_table[v_base].token);
			}		
		} else {
			fprintf(code, "]");
		}
	}
}

unsigned int Global_Pointer(unsigned int i){
	if (token_stack[token] == TOKEN_ARRAY_END)
		abort_b0("Unexpected end of memory reference");
	if ((token_stack[token] < TOKEN_OFFSET)||(token_stack[token] == TOKEN_MINUS)) {
		//we have direct numerical reference
		if (token_stack[token] == TOKEN_MINUS){
			fprintf(code, "-");
			token++;
		}
		outputNumber(i, NUM_INTEGER);
	} else {
		//we should be dealing with a register
		TokenIsLabelType(TYPE_REG);
		fprintf(code, "%s", hash_table[token_stack[token]-HASH_OFFSET].token);
		token++;
		if (token_stack[token] == TOKEN_ADD){
			// Looks like a complex memory pointer operation.
			fprintf(code, "+");
			token++;
			if (token_stack[token] > TOKEN_OFFSET) {
				// Should be a reg?
				TokenIsLabelType(TYPE_REG);
				fprintf(code, "%s", hash_table[token_stack[token]-HASH_OFFSET].token); // Output the reg
				token++;
				// Here we should have either a + or a *
				if ((token_stack[token] != TOKEN_ADD) &&
					(token_stack[token] != TOKEN_MINUS) &&
					(token_stack[token] != TOKEN_MULTIPLY) &&
					(token_stack[token] != TOKEN_ARRAY_END))
					abort_b0("+, * or ] Expected");
				if ((token_stack[token] == TOKEN_ADD)||(token_stack[token] == TOKEN_MINUS)) {
					// We should have an immediate
					if(token_stack[token] == TOKEN_ADD) {
						fprintf(code, "+");
					} else {
						fprintf(code, "-");
					}
					token++;
					if (token_stack[token] > TOKEN_OFFSET)
						abort_b0("Immediate Expected");
					outputNumber(i, NUM_INTEGER);
				} else {
					if (token_stack[token] == TOKEN_MULTIPLY) {
						// Handle our multiply, else fall through (it should be an ARRAY_END).
						fprintf(code, "*");
						token++;
						// This part gets tricky, as we should only have 1,2,4 or 8 here!
						if (token_stack[token] > TOKEN_OFFSET)
							abort_b0("Immediate Expected");
						if ((token_stack[token] != '1') &&
							(token_stack[token] != '2') &&
							(token_stack[token] != '4') &&
							(token_stack[token] != '8'))
							abort_b0("Illformed pointer expression, please revise");
						fprintf(code, "%c", token_stack[token]);
						token++; // Output the number
						if (token_stack[token] < TOKEN_OFFSET){
							if (token_stack[token] != 'h') {
								abort_b0("Unexpected Immediate");
							}
							token++; // Advance past the 'h'
						}
						if ((token_stack[token] == TOKEN_ADD)||(token_stack[token] == TOKEN_MINUS)){
							if(token_stack[token] == TOKEN_ADD) {
								fprintf(code, "+");
							} else {
								fprintf(code, "-");
							}
							token++;
							if (token_stack[token] < TOKEN_OFFSET) {
								outputNumber(i, NUM_INTEGER);
							} else {
								abort_b0("Expected Immediate");
							}
						}
					}
				}
			} else {
				// Else output the displacement.
				outputNumber(i, NUM_INTEGER);
			}
		}  else {
			if (token_stack[token] == TOKEN_MULTIPLY) {
				// Handle our multiply, else fall through (it should be an ARRAY_END).
				fprintf(code, "*");
				token++;
				// This part gets tricky, as we should only have 1,2,4 or 8 here!
				if (token_stack[token] > TOKEN_OFFSET)
					abort_b0("Immediate Expected");
				if ((token_stack[token] != '1') &&
					(token_stack[token] != '2') &&
					(token_stack[token] != '4') &&
					(token_stack[token] != '8'))
					abort_b0("Illformed pointer expression, please revise");
				fprintf(code, "%c", token_stack[token]);
				token++; // Output the number
				if (token_stack[token] < TOKEN_OFFSET){
					if (token_stack[token] != 'h') {
						abort_b0("Unexpected Immediate");
					}
					token++; // Advance past the 'h'
				}
				if ((token_stack[token] == TOKEN_ADD)||(token_stack[token] == TOKEN_MINUS)){
					if(token_stack[token] == TOKEN_ADD) {
						fprintf(code, "+");
					} else {
						fprintf(code, "-");
					}
					token++;
					if (token_stack[token] < TOKEN_OFFSET) {
						outputNumber(i, NUM_INTEGER);
					} else {
						abort_b0("Expected Immediate");
					}
				}
			} else {
				if(token_stack[token] == TOKEN_MINUS){
					// We should have an immediate...
					fprintf(code, "-");
					token++;
					if (token_stack[token] < TOKEN_OFFSET) {
						outputNumber(i, NUM_INTEGER);
					} else {
						abort_b0("Expected Immediate");
					}
				}
			}
		}
	}
	return(0);
}

unsigned int process_int_operation(unsigned int i){	
	v_base = 0;
	v_isStruc = 0;
	v_offset = 0;
	v_offset_type = 0;
	v_size = 0;
	v_index = 0;
	v_target = 0;
	v_global = 0;
	v_reg = 0;

	if ( token_stack[token] == TOKEN_ARRAY_START) {
		//Process global memory reference;
		fprintf(code, "\tmov [");
		token++;	//Increase token pointer;
		Global_Pointer(i);
		TokenIs(TOKEN_ARRAY_END);
		fprintf(code, "], ");
		token++;
		TokenIs(TOKEN_EQUATE);
		token++;
		if ((token_stack[token] < TOKEN_OFFSET)||(token_stack[token]==TOKEN_MINUS)) {
			fprintf(code, "dword ");
			if(token_stack[token] == TOKEN_MINUS){
				fprintf(code, "-");
				token++;
			}
			outputNumber(i, NUM_INTEGER);
			fprintf(code, "\n");
		} else {
			//TokenIsLabelType(TYPE_REG);
			isHash(token_stack[token]);
			if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & (TYPE_REG+TYPE_REG_SHORT) ) > 0) {
				fprintf(code, "%s\n", hash_table[token_stack[token]-HASH_OFFSET].token);
			} else {
				abort_b0("Integer Register Expected");
			}
			token++;
		}
		atStackEnd(i);
	} else {
		//we must have a register, function, or label
		if (token_stack[token] == TOKEN_ARRAY_END)
			abort_b0("Unexpected token ']'");
		if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & 0xf) > 0) {
			// We have a label;
			if(DEBUG)
				printf("Processing line with variable destination\n");
			// Let's first find if we are handling a structure before continuing.
			BuildLabelInfo(i);
			TokenIs(TOKEN_EQUATE);
			token++;
			v_target = token;
			if (token_stack[token] < TOKEN_OFFSET) {
				if (DEBUG)
					printf("Immediate being stored into memory location");
				
			} else {
				isHash(token_stack[token]);
				TokenIsLabelType(TYPE_REG);
			}
			// Now we have all our information, so let build the instruction...
			if(DEBUG){
				DisplayLabelInfo();	
			}
			if ((state == '3') || (state == '6') || (state == '8'))
				abort_b0("Unable to store an integer in a floating point variable");
			
			if (v_isStruc == 1) {
				//Let's handle the structure def intelligently, (what I'm doing below isn't intelligent).
				// What we do, is calculate the offset for any struc operation, and then do a
				// mov [r6|r14|r15], reg|immediate operation.

				Set_v_reg();	//v_reg is the register we are going to use.

				fprintf(code, "\tpush %s\n", hash_table[v_reg].token);
				
				Calculate_label_address(i);
				
				//Now we are ready to store the value...
				switch(state){
					case 'b' : fprintf(code, "\tmov byte [%s], ", hash_table[v_reg].token); break;
					case 'w' : fprintf(code, "\tmov word [%s], ", hash_table[v_reg].token); break;
					#ifndef i386
					case 'd' : fprintf(code, "\tmov dword [%s], ", hash_table[v_reg].token); break;
					default  : fprintf(code, "\tmov qword [%s], ", hash_table[v_reg].token); break;
					#else
					default  : fprintf(code, "\tmov dword [%s], ", hash_table[v_reg].token); break;
					#endif
				}
				token = v_target;
				if (token_stack[token] < TOKEN_OFFSET) {
					// We have an immediate load.
					outputNumber(i, NUM_INTEGER);
					fprintf(code, "\n");
					atStackEnd(i);
				} else {
					// We should have a register
					TokenIsLabelType(TYPE_REG);
					fprintf(code, "%s%c\n", hash_table[token_stack[token]-HASH_OFFSET].token, state);
					token++;
					atStackEnd(i);
				}
				fprintf(code, "\tpop %s\n", hash_table[v_reg].token);
				
			} else {
				// Non-structure definition, so this should be quick.
				
				switch(state){
					case 'b' : fprintf(code, "\tmov byte "); break;
					case 'w' : fprintf(code, "\tmov word "); break;
					#ifndef i386
					case 'd' : fprintf(code, "\tmov dword "); break;
					default  : fprintf(code, "\tmov qword "); break;
					#else
					default  : fprintf(code, "\tmov dword "); break;
					#endif
				}
				Calculate_NSLabel_address(i);

				fprintf(code, ", ");
								
				token = v_target;
				if (token_stack[token] < TOKEN_OFFSET) {
					// We have an immediate load.
					outputNumber(i, NUM_INTEGER);
					fprintf(code, "\n");
					atStackEnd(i);
				} else {
					// We should have a register
					TokenIsLabelType(TYPE_REG);
					fprintf(code, "%s%c\n", hash_table[token_stack[token]-HASH_OFFSET].token, state);
					token++;
					atStackEnd(i);
				}
			}
			token = i;
		} else {
			if (hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_REG) {
				if(DEBUG)
					printf("Processing line with register destination\n");
				target = token_stack[token]-HASH_OFFSET; //Store hash of target.
				token++;
				TokenIs(TOKEN_EQUATE);
				token++; // Let's skip ahead for a second.
				if ((token_stack[token] == TOKEN_POINTER)||(token_stack[token] == TOKEN_STRING)) {
					// We are dealing with a pointer to either a string or label
					if (token_stack[token] == TOKEN_POINTER) {
						token++;
					}
					// Advance if token is a pointer, otherwise just wait.
					if (token_stack[token] == TOKEN_ARRAY_START){
						fprintf(code, "\tlea %s, [", hash_table[target].token);
						token++;	//Increase token pointer;
						Global_Pointer(i);
						TokenIs(TOKEN_ARRAY_END);
						fprintf(code, "]\n");
						token++;
						atStackEnd(i);
					} else {
						if (token_stack[token] == TOKEN_STRING) {
							outputDynamicString(i);
							atStackEnd(i);
						} else {
							// We are dealing with a label, but lets first check
							isHash(token_stack[token]);
							if ((hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_PROC)||
								(hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_EPROC)||
								(hash_table[token_stack[token]-HASH_OFFSET].token_type == 0)){
								//Process pointer to PROC!
								if (hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_EPROC) {
									fprintf(code, "\tmov %s, %s\n", hash_table[target].token, hash_table[token_stack[token]-HASH_OFFSET].token);
								} else {
									fprintf(code, "\tmov %s, _B0_%s\n", hash_table[target].token, hash_table[token_stack[token]-HASH_OFFSET].token);								
								};
								token++;          
								TokenIs(TOKEN_PARA_START);
								token++; // Let's skip ahead for a second.
								TokenIs(TOKEN_PARA_END);
								token++;
								atStackEnd(i);
							} else {
								if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & 0xf) == 0) abort_b0("Expected Data Label");
								// We definitely have a label.
								BuildLabelInfo(i);
								// we use target here instead of v_target!
								v_target = 0;
								if(DEBUG){
									DisplayLabelInfo();	
								}
								atStackEnd(i);
								if (v_isStruc == 1) {
									// What we do, is calculate the offset for any struc operation, and then do a
									// mov target, r6|r14|r15 operation.
	
									Set_v_reg();	//v_reg is the register we are going to use.
	
									fprintf(code, "\tpush %s\n", hash_table[v_reg].token);
					
									Calculate_label_address(i);
									
									fprintf (code, "\tmov %s, %s\n\tpop %s\n", hash_table[target].token, hash_table[v_reg].token, hash_table[v_reg].token);
								} else {
									// We have a standard variable.
									if(state != '8') //We handle f80 differently
										fprintf(code, "\tlea %s, ", hash_table[target].token);
									Calculate_NSLabel_address(i);
									fprintf(code, "\n");
								}
							}
						}
					}
				} else {
					// We have a reg, label, immediate, or proc. (pointers have already been dealth with).
					if ((token_stack[token] < TOKEN_OFFSET) || (token_stack[token] == TOKEN_MINUS)) {
						// We have an immediate load
						fprintf(code, "\tmov %s, ", hash_table[target].token);
						if (token_stack[token] == TOKEN_MINUS) {
							token++;
							fprintf(code, "-");
						}
						outputNumber(i, NUM_INTEGER);
						fprintf(code, "\n");
						atStackEnd(i);
					} else {
						// We have a reg, label or proc
						if (token_stack[token] == TOKEN_ARRAY_START) {
							// We have a global load into a register
							fprintf(code, "\tmov %s, [", hash_table[target].token);
							token++;
							Global_Pointer(i);
							TokenIs(TOKEN_ARRAY_END);
							fprintf(code, "]\n");
							token++;
							atStackEnd(i);									
						
						} else {
							// We have a reg, label or proc
							// At this stage, the next token should be a reg, label or proc.
							// Anything else is incorrect!
							isHash(token_stack[token]);
							if (hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_KEYWORD)
								abort_b0("Unexpected Keyword");
							
							// The only thing we should be left with are the regs, labels or procs!
							if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & 0xf) > 0) {
								// We have a label
								if(DEBUG)
									printf("Processing line with register destination with label source\n");
								BuildLabelInfo(i);
								// we use target here instead of v_target!
								v_target = 0;
								if(DEBUG){
									DisplayLabelInfo();	
								}
								atStackEnd(i);

								//state will hold the size of the transfer..., On m64 state = '', as this is the default size. No override needed.
								if ((state == '3') || (state == '6') || (state == '8'))
									abort_b0("Unable to load integer register with floating point variable");
									
								if (v_isStruc == 1) {
									//Let's handle the structure def intelligently, (what I'm doing below isn't intelligent).
									// What we do, is calculate the offset for any struc operation, and then do a
									// mov [r6|r14|r15], reg|immediate operation.
								
									Set_v_reg();	//v_reg is the register we are going to use.

									fprintf(code, "\tpush %s\n", hash_table[v_reg].token);
				
									Calculate_label_address(i);
				
									//Now we are ready to store the value...
									switch(state){
										case 'b' : fprintf(code, "\tmovzx %s, byte [%s]\n", hash_table[target].token, hash_table[v_reg].token); break;
										case 'w' : fprintf(code, "\tmovzx %s, word [%s]\n", hash_table[target].token, hash_table[v_reg].token); break;
										#ifndef i386
										case 'd' : fprintf(code, "\tmov %sd, dword [%s]\n", hash_table[target].token, hash_table[v_reg].token); break;
										default  : fprintf(code, "\tmov %s, qword [%s]\n", hash_table[target].token, hash_table[v_reg].token); break;
										#else
										default  : fprintf(code, "\tmov %s, dword [%s]\n", hash_table[target].token, hash_table[v_reg].token); break;
										#endif
									}
									token = v_target;
									fprintf(code, "\tpop %s\n", hash_table[v_reg].token);
								} else {
									// Non-structure definition, so this should be quick.
									switch(state){
										case 'b' : fprintf(code, "\tmovzx %s, byte ", hash_table[target].token); break;
										case 'w' : fprintf(code, "\tmovzx %s, word ", hash_table[target].token); break;
										#ifndef i386
										case 'd' : fprintf(code, "\tmov %sd, dword ", hash_table[target].token); break;
										default  : fprintf(code, "\tmov %s, qword ", hash_table[target].token); break;
										#else
										default  : fprintf(code, "\tmov %s, dword ", hash_table[target].token); break;
										#endif
									}
									
									Calculate_NSLabel_address(i);
				
									fprintf(code, "\n");
								}
							} else {
								if (hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_REG) {
									// We have a register!
									token++;	// Step forward 1
									if (token != i) {
										if ((token_stack[token] != TOKEN_MULTIPLY) &&
											(token_stack[token] != TOKEN_DIVIDE) &&
											(token_stack[token] != TOKEN_MODULUS) &&
											(token_stack[token] != TOKEN_S_MULTIPLY) &&
											(token_stack[token] != TOKEN_S_DIVIDE) &&
											(token_stack[token] != TOKEN_S_MODULUS)) {
												if (target != (token_stack[token-1]-HASH_OFFSET))
													// Only output if target and first operand are different.
													fprintf(code, "\tmov %s, %s\n", hash_table[target].token, hash_table[token_stack[token-1]-HASH_OFFSET].token);
											};
										state = token_stack[token];
										switch(state) {
											case TOKEN_AND:  // If our operation is a basic AND
												fprintf(code, "\tand %s, ", hash_table[target].token);
												break;
												
											case TOKEN_OR:
												fprintf(code, "\tor %s, ", hash_table[target].token);
												break;
												
											case TOKEN_XOR:
												fprintf(code, "\txor %s, ", hash_table[target].token);
												break;
												
											case TOKEN_ADD:
												fprintf(code, "\tadd %s, ", hash_table[target].token);
												break;
												
											case TOKEN_MINUS:
												fprintf(code, "\tsub %s, ", hash_table[target].token);
												break;
												
											case TOKEN_MULTIPLY:
												if ((token_stack[token-1]-HASH_OFFSET) != HASH_r0)
													abort_b0("Multiply Operations REQUIRE r0 as source");
												fprintf(code, "\tmul ");
												break;
												
											case TOKEN_DIVIDE:
												if ((token_stack[token-1]-HASH_OFFSET) != HASH_r0)
													abort_b0("Division Operations REQUIRE r0 as source");
												fprintf(code, "\tdiv ");
												break;
												
											case TOKEN_MODULUS:
												if ((token_stack[token-1]-HASH_OFFSET) != HASH_r0)
													abort_b0("Modulus Operations REQUIRE r0 as source");
												fprintf(code, "\tdiv ");
												break;
												
											case TOKEN_S_MULTIPLY:
												if ((token_stack[token-1]-HASH_OFFSET) != HASH_r0)
													abort_b0("Signed Multiply Operations REQUIRE r0 as source");
												fprintf(code, "\timul ");
												break;
												
											case TOKEN_S_DIVIDE:
												if ((token_stack[token-1]-HASH_OFFSET) != HASH_r0)
													abort_b0("Signed Division Operations REQUIRE r0 as source");
												fprintf(code, "\tidiv ");
												break;
												
											case TOKEN_S_MODULUS:
												if ((token_stack[token-1]-HASH_OFFSET) != HASH_r0)
													abort_b0("Signed Modulus Operations REQUIRE r0 as source");
												fprintf(code, "\tidiv ");
												break;

											case TOKEN_RSHIFT:
												fprintf(code, "\tshr %s, ", hash_table[target].token);
												break;
												
											case TOKEN_LSHIFT:
												fprintf(code, "\tshl %s, ", hash_table[target].token);
												break;

											case TOKEN_RROTATE:
												fprintf(code, "\tror %s, ", hash_table[target].token);
												break;
												
											case TOKEN_LROTATE:
												fprintf(code, "\trol %s, ", hash_table[target].token);
												break;

											default:
												abort_b0("Invalid Construct");
												break;
										}
										// We have constructed our operand
										token++;
										// Now lets see what the second operand is...
										if ((token_stack[token] < TOKEN_OFFSET) || (token_stack[token] == TOKEN_MINUS)) {
											// Looks like an immediate
											if ((state == TOKEN_MULTIPLY) ||
												(state == TOKEN_DIVIDE) ||
												(state == TOKEN_MODULUS) ||
												(state == TOKEN_S_MULTIPLY) ||
												(state == TOKEN_S_DIVIDE) ||
												(state == TOKEN_S_MODULUS)) {
													// Mul, and div require a register!
													abort_b0("Unexpected immediate value");
												}
											// We have an immediate load
											if (token_stack[token] == TOKEN_MINUS) {
												if ((state == TOKEN_RSHIFT) ||
													(state == TOKEN_LSHIFT) ||
													(state == TOKEN_RROTATE) ||
													(state == TOKEN_LROTATE)) {
														// Shifts MUST have a positive!
														abort_b0("Shift/Rotate operations require a POSITIVE shift value");
												}
												token++;
												fprintf(code, "-");
											}
											outputNumber(i, NUM_INTEGER);
											fprintf(code, "\n");
										} else {
											// Must be a REG, so lets get rid of the rest;
											if (token_stack[token] < HASH_OFFSET)
												abort_b0("Expected Token/Label");

											// Lets see if we have a shift operation, and handle appropriately.
											if ((state == TOKEN_RSHIFT) || (state == TOKEN_LSHIFT) ||
												(state == TOKEN_RROTATE) || (state == TOKEN_LROTATE)){
												if (((token_stack[token]-HASH_OFFSET) != HASH_r2) &&
													((token_stack[token]-HASH_OFFSET) != HASH_r2b))
													abort_b0("Shift/Rotate Operations REQUIRE r2 / r2b or Immediate as second operand");
												fprintf(code, "r2b\n");
											} else {
												TokenIsLabelType(TYPE_REG);
												// Everything must be okay, so lets output our second operand.
												fprintf(code, "%s\n", hash_table[token_stack[token]-HASH_OFFSET].token);
											}
											// Load the destination register if required!
											switch(state) {
												case TOKEN_MULTIPLY:
												case TOKEN_DIVIDE:
												case TOKEN_S_MULTIPLY:
												case TOKEN_S_DIVIDE:
													if (target != HASH_r0)
														fprintf(code, "\tmov %s, r0\n", hash_table[target].token);
													break;
												case TOKEN_MODULUS:
												case TOKEN_S_MODULUS:
													if (target != HASH_r3)
														fprintf(code, "\tmov %s, r3\n", hash_table[target].token);
													break;
											}
											token++;
										}
										atStackEnd(i);
									} else {
										// We have a single register load!
										if (target != (token_stack[token-1]-HASH_OFFSET))
											// Don't output code, if r0 = r0; type is present.
											fprintf(code, "\tmov %s, %s\n", hash_table[target].token, hash_table[token_stack[token-1]-HASH_OFFSET].token);
									}
								} else {
									// We must have a proc!
									callProc((token_stack[token])-HASH_OFFSET, target, i);
								}
							}
						}
					}
				}
			} else {
				if (hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_REG_SHORT) {
					// Look like we have a short reg...
					// This is going to be easy, as short regs can only be used with pointer operations.
					fprintf(code, "\tmov %s, ", hash_table[token_stack[token]-HASH_OFFSET].token);
					token++;
					TokenIs(TOKEN_EQUATE);
					token++;
					if (token_stack[token] == TOKEN_ARRAY_START){
						TokenIs(TOKEN_ARRAY_START);
						fprintf(code, "[");
						token++;
						Global_Pointer(i);
						TokenIs(TOKEN_ARRAY_END);
						fprintf(code, "]\n");
						token++;
					} else {
						if ((token_stack[token] < TOKEN_OFFSET) || (token_stack[token] == TOKEN_MINUS)) {
							// Else should be immediate
							if (token_stack[token] == TOKEN_MINUS) {
								token++;
								fprintf(code, "-");
							}
							outputNumber(i, NUM_INTEGER);
							fprintf(code, "\n");
							atStackEnd(i);			
						} else {
							abort_b0("Expected Pointer/Immediate");		
						}	
					}
				} else {
					// Whatever we have left treat as proc.
					callProc(token_stack[token]-HASH_OFFSET, HASH_r0, i);							
				}
			}
		}
	}
	return(0);
}

unsigned int process_fpu_operation(unsigned int i) {
	v_base = 0;
	v_isStruc = 0;
	v_offset = 0;
	v_offset_type = 0;
	v_size = 0;
	v_index = 0;
	v_target = 0;
	v_global = 0;
	v_reg = 0;

	if ( token_stack[token] == TOKEN_ARRAY_START) {
		//Process global memory reference;
		fprintf(code, "\tfstp tword [");
		token++;	//Increase token pointer;
		Global_Pointer(i);
		TokenIs(TOKEN_ARRAY_END);
		fprintf(code, "]\n");
		token++;
		TokenIs(TOKEN_EQUATE);
		token++;
		if (token_stack[token] != HASH_fp0+HASH_OFFSET)
			abort_b0("fp0 Expected");
		token++;
		atStackEnd(i);
	} else {
		// We can have a label or FPU reg?
		// we must have a register, function, or label
		if (token_stack[token] == TOKEN_ARRAY_END)
			abort_b0("Unexpected token ']'");
		if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & 0xf) > 0) {
			// We have a label;
			if(DEBUG)
				printf("Processing line with variable destination\n");
				
			BuildLabelInfo(i);
			TokenIs(TOKEN_EQUATE);
			token++;
			v_target = token;
			if (token_stack[token] != HASH_fp0+HASH_OFFSET)
				abort_b0("fp0 Expected");
			token++;
			atStackEnd(i);

			// Now we have all our information, so let build the instruction...
			if(DEBUG){
				DisplayLabelInfo();	
			}
			
			if ((v_isStruc == 1)||(state=='8')) {
				// What we do, is calculate the offset for any struc operation, and then do a
				// fstp [r6|r14|r15] operation.

				Set_v_reg();	//v_reg is the register we are going to use.

				fprintf(code, "\tpush %s\n", hash_table[v_reg].token);
				
				Calculate_label_address(i);
				
				//Now we are ready to store the value...
				switch(state){
					case 'b' : abort_b0("Cannot store FPU into byte");	break;
					case 'w' : fprintf(code, "\tfistp word [%s]\n", hash_table[v_reg].token); break;
					#ifndef i386
					case 'd' : fprintf(code, "\tfistp dword [%s]\n", hash_table[v_reg].token); break;
					case ' ' : fprintf(code, "\tfistp qword [%s]\n", hash_table[v_reg].token); break;
					#else
					case ' ' : fprintf(code, "\tfistp dword [%s]\n", hash_table[v_reg].token); break;
					#endif
					case '3' : fprintf(code, "\tfstp dword [%s]\n", hash_table[v_reg].token); break;
					case '6' : fprintf(code, "\tfstp qword [%s]\n", hash_table[v_reg].token); break;
					default  : fprintf(code, "\tfstp tword [%s]\n", hash_table[v_reg].token); break;
				}
				fprintf(code, "\tpop %s\n", hash_table[v_reg].token);
				
			} else {
				// Non-structure definition, so this should be quick.
				switch(state){
					case 'b' : abort_b0("Cannot store FPU into byte");	break;
					case 'w' : fprintf(code, "\tfistp word "); break;
					#ifndef i386
					case 'd' : fprintf(code, "\tfistp dword "); break;
					case ' ' : fprintf(code, "\tfistp qword "); break;
					#else
					case ' ' : fprintf(code, "\tfistp dword "); break;
					#endif
					case '3' : fprintf(code, "\tfstp dword "); break;
					case '6' : fprintf(code, "\tfstp qword "); break;
				}
				Calculate_NSLabel_address(i);
				fprintf(code, "\n");
			}
			token = i;
		} else {
			// We should have a FPU REG
			TokenIsLabelType(TYPE_REG_FPU);
			if(DEBUG)
				printf("Processing line with FPU register destination\n");
			target = token_stack[token]-HASH_OFFSET; //Store hash of target.
			token++;
			TokenIs(TOKEN_EQUATE);
			token++;
			if (target == HASH_fp0){
				// Handle fp0 = something;
				if ((token_stack[token] < TOKEN_OFFSET) || (token_stack[token] == TOKEN_MINUS)){
					// We have a direct number load.
					fprintf(data, "B0_DynNum%d dt ", dynamic_string_count);
					if (token_stack[token] == TOKEN_MINUS){
						fprintf(data, "-");
						token++;
					}
					if (token_stack[token] > TOKEN_OFFSET)
						abort_b0("Immediate Expected");
					outputNumberD(i,NUM_DECIMAL);
					fprintf(data, "\n");
					fprintf(code, "\tfld tword [B0_DynNum%d]\n", dynamic_string_count);
					dynamic_string_count++; // Inc the number of dynamic strings we have
					atStackEnd(i);
				} else {
					// We have a label or register or global!
					if (token_stack[token] == TOKEN_ARRAY_START){
						// Looks like we have a global
						fprintf(code, "\tfld tword [");
						token++;	//Increase token pointer;
						Global_Pointer(i);
						TokenIs(TOKEN_ARRAY_END);
						fprintf(code, "]\n");
						token++;
						atStackEnd(i);
					} else {
						// We can only have a reg or label
						if (token_stack[token] < HASH_OFFSET)
							abort_b0("Expected Label or FPU Register");
						if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & 0xf) > 0) {
							// We have a label
							if(DEBUG)
								printf("Loading fp0 with variable\n");
							v_target = 0;
							BuildLabelInfo(i);
							atStackEnd(i);

							// Now we have all our information, so let build the instruction...
							if(DEBUG){
								DisplayLabelInfo();	
							}
							if ((v_isStruc == 1)||(state=='8')) {
								// What we do, is calculate the offset for any struc operation, and then do a
								// fstp [r6|r14|r15] operation.
	
								Set_v_reg();	//v_reg is the register we are going to use.

								fprintf(code, "\tpush %s\n", hash_table[v_reg].token);
				
								Calculate_label_address(i);
				
								//Now we are ready to store the value...
								switch(state){
									case 'b' : abort_b0("Cannot store FPU into byte");	break;
									case 'w' : fprintf(code, "\tfild word [%s]\n", hash_table[v_reg].token); break;
									#ifndef i386
									case 'd' : fprintf(code, "\tfild dword [%s]\n", hash_table[v_reg].token); break;
									case ' ' : fprintf(code, "\tfild qword [%s]\n", hash_table[v_reg].token); break;
									#else
									case ' ' : fprintf(code, "\tfild dword [%s]\n", hash_table[v_reg].token); break;
									#endif
									case '3' : fprintf(code, "\tfld dword [%s]\n", hash_table[v_reg].token); break;
									case '6' : fprintf(code, "\tfld qword [%s]\n", hash_table[v_reg].token); break;
									default  : fprintf(code, "\tfld tword [%s]\n", hash_table[v_reg].token); break;
								}
								fprintf(code, "\tpop %s\n", hash_table[v_reg].token);
				
							} else {
								// Non-structure definition, so this should be quick.
								switch(state){
									case 'b' : abort_b0("Cannot store FPU into byte");	break;
									case 'w' : fprintf(code, "\tfild word "); break;
									#ifndef i386
									case 'd' : fprintf(code, "\tfild dword "); break;
									case ' ' : fprintf(code, "\tfild qword "); break;
									#else
									case ' ' : fprintf(code, "\tfild dword "); break;
									#endif
									case '3' : fprintf(code, "\tfld dword "); break;
									case '6' : fprintf(code, "\tfld qword "); break;
								}
								Calculate_NSLabel_address(i);
								fprintf(code, "\n");
							}
						} else {
							// We MUST have a FPU Reg.
							TokenIsLabelType(TYPE_REG_FPU);
							// All we can have here is a TOS load, or a math operation.
							if (token_stack[token] == HASH_fp0+HASH_OFFSET){
								// We MUST have a math function
								token++;
								if (token != i){
									//Process our math operator
									state = token_stack[token];
									token++;
									if (token == i)
										abort_b0("Expected FPU Register");
									TokenIsLabelType(TYPE_REG_FPU);
									switch(state){
										case TOKEN_ADD: fprintf(code, "\tfadd fp0, %s\n", hash_table[token_stack[token]-HASH_OFFSET].token); break;
										case TOKEN_MINUS: fprintf(code, "\tfsub fp0, %s\n", hash_table[token_stack[token]-HASH_OFFSET].token); break;
										case TOKEN_MULTIPLY:
										case TOKEN_S_MULTIPLY: fprintf(code, "\tfmul fp0, %s\n", hash_table[token_stack[token]-HASH_OFFSET].token); break;
										case TOKEN_DIVIDE:
										case TOKEN_S_DIVIDE: fprintf(code, "\tfdiv fp0, %s\n", hash_table[token_stack[token]-HASH_OFFSET].token); break;
										case TOKEN_MODULUS:
										case TOKEN_S_MODULUS:
											if (token_stack[token] != HASH_fp1+HASH_OFFSET)
												abort_b0("Floating Point Modulus requires 2nd operand to be fp1");
											fprintf(code, "\tfprem1\n");											
											break;
										default: abort_b0("Invalid construct"); break;
									}
									token++;
									atStackEnd(i);
								} else {
									// Looks like a dup ST0 operation.
									fprintf(code, "\tfld fp0\n");
									atStackEnd(i);
								}
							} else {
								// We MUST have a TOS load or a reverse math operation.
								target = token_stack[token]-HASH_OFFSET;
								token++;
								if (token != i){
									//Process our math operator
									state = token_stack[token];
									token++;
									if (token == i)
										abort_b0("Expected FPU Register");
									TokenIsLabelType(TYPE_REG_FPU);
									if (token_stack[token] != HASH_fp0+HASH_OFFSET)
										abort_b0("Operand register is not the same as the target register");
									switch(state){
										case TOKEN_ADD: fprintf(code, "\tfadd fp0, %s\n", hash_table[target].token); break;
										case TOKEN_MINUS: fprintf(code, "\tfsubr fp0, %s\n", hash_table[target].token); break;
										case TOKEN_MULTIPLY:
										case TOKEN_S_MULTIPLY: fprintf(code, "\tfmul fp0, %s\n", hash_table[target].token); break;
										case TOKEN_DIVIDE:
										case TOKEN_S_DIVIDE: fprintf(code, "\tfdivr fp0, %s\n", hash_table[target].token); break;
										default: abort_b0("Invalid construct"); break;
									}
									token++;
									atStackEnd(i);	
								} else {
									fprintf(code, "\tfld %s\n", hash_table[target].token);
								}								
							}
						}
					}
				}
			} else {
				// We should have a fp = fp0; or fp = fp {math} fp0;
				if (target == token_stack[token]-HASH_OFFSET){
					token++;
					if (token != i){
						//Process our math operator
						state = token_stack[token];
						token++;
						if (token == i)
							abort_b0("Expected FPU Register");
						TokenIsLabelType(TYPE_REG_FPU);
						if (token_stack[token] != HASH_fp0+HASH_OFFSET)
							abort_b0("fp0 Expected");
						switch(state){
							case TOKEN_ADD:	fprintf(code, "\tfadd %s, fp0\n", hash_table[target].token); break;
							case TOKEN_MINUS: fprintf(code, "\tfsub %s, fp0\n", hash_table[target].token); break;
							case TOKEN_MULTIPLY:
							case TOKEN_S_MULTIPLY: fprintf(code, "\tfmul %s, fp0\n", hash_table[target].token); break;
							case TOKEN_DIVIDE:
							case TOKEN_S_DIVIDE: fprintf(code, "\tfdiv %s, fp0\n", hash_table[target].token); break;
							default: abort_b0("Invalid construct"); break;
						}
						token++;
						atStackEnd(i);
					}
				} else {
					if (token_stack[token] != HASH_fp0+HASH_OFFSET)
						abort_b0("fp0 Expected");
					token++;
					if (token != i){
						//Process our math operator
						state = token_stack[token];
						token++;
						if (token == i)
							abort_b0("Expected FPU Register");
						TokenIsLabelType(TYPE_REG_FPU);
						if (token_stack[token] != (target+HASH_OFFSET))
							abort_b0("Operand register is not the same as the target register");
						switch(state){
							case TOKEN_ADD: fprintf(code, "\tfadd %s, fp0\n", hash_table[target].token); break;
							case TOKEN_MINUS: fprintf(code, "\tfsubr %s, fp0\n", hash_table[target].token); break;
							case TOKEN_MULTIPLY:
							case TOKEN_S_MULTIPLY: fprintf(code, "\tfmul %s, fp0\n", hash_table[target].token); break;
							case TOKEN_DIVIDE:
							case TOKEN_S_DIVIDE: fprintf(code, "\tfdivr %s, fp0\n", hash_table[target].token); break;
							default: abort_b0("Invalid construct"); break;
						}
						token++;
						atStackEnd(i);	
					} else {
						fprintf(code, "\tfxch %s\n", hash_table[target].token);
					}
				};
			}
		}
	}
	return(0);
}

unsigned int process_struc_def(unsigned int i){
	unsigned int target_hash;
	int variable_size, struc_size;
	struc_struc *ptr_struc;
	
	if(DEBUG)
		printf("Defining a Variable based on a Structure\n");
	atStackStart();
	
	//Lets see if we have an array of struc's
	if(token_stack[token] == TOKEN_ARRAY_START){
		// Looks like we do, so lets grab our size.
		toki = 0;
		token++;
		while (token_stack[token] != TOKEN_ARRAY_END) {
			token_buffer[toki] = (unsigned char)token_stack[token];
			token_buffer[toki+1] = '\0';
			toki++;
			token++;
			if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
		}
		TokenIs(TOKEN_ARRAY_END);
		token++; // Skip end of array size indicator.
		variable_size = dhtoi(token_buffer);  // Get our array size!
	} else {
		variable_size = 1;
	}
	if(DEBUG)
		printf("Struc Variable Size = %d\n", variable_size);
	isHash(token_stack[token]);
	target_hash = token_stack[token]-HASH_OFFSET;
	IsLabelAllocated();
	//Set our variable type;
	if(global == 0){
		hash_table[target_hash].token_type = TYPE_GLOBAL+TYPE_VSTRUC+(hash_table[token_stack[0]-HASH_OFFSET].token_type & 0xf);
	} else {
		hash_table[target_hash].token_type = TYPE_LOCAL+TYPE_VSTRUC +(hash_table[token_stack[0]-HASH_OFFSET].token_type & 0xf);
	}
	
	//Now comes the hard bit... Now to allocate the space within the final executable.
	struc_size = hash_table[token_stack[0]-HASH_OFFSET].local_offset;  //Local offset holds the number of elements within the struc
	ptr_struc = hash_table[token_stack[0]-HASH_OFFSET].struc_ptr;
	hash_table[target_hash].struc_ptr = ptr_struc;
	struc_size = ptr_struc->struc[struc_size].offset; // Struc Size == size of structure in bytes!
	hash_table[target_hash].local_offset = struc_size;
	if(DEBUG)
		printf("Structure Size = %d\nVariable Size = %d\n", struc_size, struc_size*variable_size);
	
	// Now that we have our size, let's output the required stuff...
	if(global == 0){
		fprintf(bss, "_B0_%s rb %d\n", hash_table[target_hash].token, struc_size*variable_size);	
	} else {
		fprintf(data, "_B0_%s_%s equ %d\n", hash_table[global-HASH_OFFSET].token, hash_table[target_hash].token, local_var_offset);	
		local_var_offset = local_var_offset + (struc_size*variable_size);
		hash_table[global-HASH_OFFSET].local_offset = local_var_offset;	
	}
	token++;
	if(DEBUG)
		printf("token = 0x%x, i = 0x%x\n", token, i);
	atStackEnd(i);
	if(DEBUG)
		printf("Finished defining a variable based on a structure\n");
	return(0);
}

unsigned int TS_is_int(unsigned int i){
	// All this function does is scan the token_stack, and
	// if we have a FPU reg in there somewhere, return 0
	// else return 1, indicating that no tokens relate
	// to fpu operations.
	unsigned int isInt = 1;
	// i = number of tokens.
	// token = current token., we assume token = 0;
	for (token = 0; token < i; token++){
		switch(token_stack[token]) {
			case HASH_fp0+HASH_OFFSET:
			case HASH_fp1+HASH_OFFSET:
			case HASH_fp2+HASH_OFFSET:
			case HASH_fp3+HASH_OFFSET:
			case HASH_fp4+HASH_OFFSET:
			case HASH_fp5+HASH_OFFSET:
			case HASH_fp6+HASH_OFFSET:
			case HASH_fp7+HASH_OFFSET: isInt = 0;
			break;
		}
	}
	token = 0; // Reset the token value
	return(isInt);
}

unsigned int process_struc(void){
	unsigned int i, j, k, offset, s_offset;
	int variable_size;
	struc_struc *ptr_struc;
	struc_struc *ptr_struc_embedded;	// Pointer to another structure which we want
									// to embed into this structure!
	// struc_def = hash of the structure we are operating on.
	i = token;
	token = 0;
	if(DEBUG){
		printf("PROCESSING STRUC STACK : ");
		for (token = 0; token < i; token++){
			printf("0x%x ", token_stack[token]);
		}
		printf("\n");
	}
	token = 0;
	while (token < i){
		if(DEBUG)
			printf("Structure - Processing Stack\n");
		switch (token_stack[token]) {
			case HASH_m8+HASH_OFFSET :
			case HASH_m16+HASH_OFFSET :
			case HASH_m32+HASH_OFFSET :
			#ifndef i386
			case HASH_m64+HASH_OFFSET :
			#endif
			case HASH_f32+HASH_OFFSET :
			case HASH_f64+HASH_OFFSET :
			case HASH_f80+HASH_OFFSET :
				if(DEBUG)
					printf("Structure - Processing Variable Def\n");
				atStackStart();
				if (token_stack[token] == TOKEN_ARRAY_START) {
					// This gets a little complicated?
					toki = 0;
					token++;
					while (token_stack[token] != TOKEN_ARRAY_END) {
						token_buffer[toki] = (unsigned char)token_stack[token];
						token_buffer[toki+1] = '\0';
						toki++;
						token++;
						if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
					}
					token++; // Skip end of array size indicator.
					variable_size = dhtoi(token_buffer);  // Get our array size!
				} else {
					variable_size = 1;
				}
				isHash(token_stack[token]);
				switch (token_stack[0]) {
					case HASH_m8+HASH_OFFSET : break;
					case HASH_m16+HASH_OFFSET : variable_size *= 2; break;
					case HASH_m32+HASH_OFFSET : variable_size *= 4; break;
					#ifndef i386
					case HASH_m64+HASH_OFFSET : variable_size *= 8; break;
					#endif
					case HASH_f32+HASH_OFFSET : variable_size *= 4; break;
					case HASH_f64+HASH_OFFSET : variable_size *= 8; break;
					case HASH_f80+HASH_OFFSET : variable_size *= 10; break;
				}
				token++;
				atStackEnd(i);
				ScanForDupStrucLabel(struc_def, token_stack[token-1]-HASH_OFFSET);
				offset = hash_table[struc_def].local_offset;
				ptr_struc = hash_table[struc_def].struc_ptr;
				if(DEBUG)
					printf("Variable Size = %d, Offset = 0x%x\n", variable_size, offset);
				token--;	// Better point to our hash value!
				if (hash_table[struc_def].token_type == TYPE_STRUC) {
					// We better set the it the first variable type;
					switch (token_stack[0]) {
						case HASH_m8+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_M8; break;
						case HASH_m16+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_M16; break;
						case HASH_m32+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_M32; break;
						#ifndef i386
						case HASH_m64+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_M64; break;
						#endif
						case HASH_f32+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_F32; break;
						case HASH_f64+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_F64; break;
						case HASH_f80+HASH_OFFSET : hash_table[struc_def].token_type = TYPE_STRUC+TYPE_F80; break;
					}
				}
				// Get our next offset.
				s_offset = ptr_struc->struc[offset].offset;
				switch (token_stack[0]) {
					case HASH_m8+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_M8; break;
					case HASH_m16+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_M16;  break;
					case HASH_m32+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_M32;  break;
					#ifndef i386
					case HASH_m64+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_M64;  break;
					#endif
					case HASH_f32+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_F32;  break;
					case HASH_f64+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_F64;  break;
					case HASH_f80+HASH_OFFSET : ptr_struc->struc[offset].type = TYPE_F80;  break;
				}
				ptr_struc->struc[offset].size = variable_size;
				ptr_struc->struc[offset].hash = token_stack[token]-HASH_OFFSET;
				ptr_struc->struc[offset+1].offset = s_offset+variable_size;
				ptr_struc->struc[offset+1].hash = 0;
				if(DEBUG)
					printf("Variable %s, Type = 0x%x, Size = 0x%x, Offset = 0x%x\n", hash_table[ptr_struc->struc[offset].hash].token, ptr_struc->struc[offset].type, ptr_struc->struc[offset].size, ptr_struc->struc[offset].offset);
				hash_table[struc_def].local_offset++;	// Increment the pointer into the structure table
				if (offset+1 >= STRUC_SIZE)
					abort_b0("INTERNAL: Structure Definition Table Overflow! - Increase STRUC_SIZE");
				token = i;
				break;

			case TOKEN_BLOCK_END : 
				if(DEBUG)
					printf("Struc - Processing TOKEN_END_BLOCK\n");
				atStackStart();
				if(DEBUG)
					printf("token = 0x%x, i = 0x%x\n", token, i);
				if (i > token){
					j = i - token; // make j our count!
					for (k = 0; k < j; k++){
						// Quick move the stack forward
						token_stack[k] = token_stack[token];
						token++;
						if (DEBUG)
							printf("stack[%d] = 0x%x\n",k,token_stack[k]);
					}
					token = 0;		// Set our stack pointer to 0
					i = j;			// Set our new stack size to the count!
					if(DEBUG)
						printf("process_struc > token = 0x%x, i = 0x%x\n", token, i);
					struc_def = 0;
					do_process = 0;
					return(i);
				} else {
					atStackEnd(i);
					getChar();
					struc_def = 0;
					return(1);
				}
				break;
								
			default:
				if ((hash_table[(token_stack[token]-HASH_OFFSET)].token_type & TYPE_STRUC) != TYPE_STRUC)
					abort_b0("Structures can only contain variable definitions");
				if(DEBUG)
					printf("Structure - Processing embedded structure\n");
				atStackStart();
				atStackEnd(i);
				token--;

				// The structure which we want to copy.
				ptr_struc_embedded = hash_table[token_stack[token]-HASH_OFFSET].struc_ptr;
				s_offset = hash_table[token_stack[token]-HASH_OFFSET].local_offset;

				if(DEBUG)
					printf("Source ptr = %p\n", ptr_struc_embedded);
				// The desintation
				offset = hash_table[struc_def].local_offset;
				ptr_struc = hash_table[struc_def].struc_ptr;

				// Now copy the structures over
				for (j = 0; j < s_offset; j++){
					ScanForDupStrucLabel(struc_def, ptr_struc_embedded->struc[j].hash);
					ptr_struc->struc[offset].type = ptr_struc_embedded->struc[j].type;
					ptr_struc->struc[offset].size = ptr_struc_embedded->struc[j].size;
					ptr_struc->struc[offset].hash = ptr_struc_embedded->struc[j].hash;
					ptr_struc->struc[offset+1].offset = ptr_struc->struc[offset].offset + ptr_struc->struc[offset].size;
					if(DEBUG)
						printf("Variable %s, Type = 0x%x, Size = 0x%x, Offset = 0x%x\n", hash_table[ptr_struc->struc[offset].hash].token, ptr_struc->struc[offset].type, ptr_struc->struc[offset].size, ptr_struc->struc[offset].offset);
					offset++;
				}
				hash_table[struc_def].local_offset = offset;
				token = i;
				break;
		}
	}
	token = 0;	// Clear the token stack
	return(0);
}

unsigned int process_token_stack(void){
	unsigned int i, j, k, l, exit_struc;
	
	preparse_token_stack();
	
	i = token; // i holds the number of tokens to process.
	if(DEBUG){
		printf("PROCESSING STACK : ");
		for (token = 0; token < i; token++){
			printf("0x%x ", token_stack[token]);
		}
		printf("\n");
	}
	
	if ((pp_GenCode[pp_ptr] == 1)||(token_stack[0] == TOKEN_PREPARSER)) {
		token = 0;		// Set the token pointer to the start of the stack
	} else {
		if (token_stack[0] == TOKEN_BLOCK_END){
			// The next valid token could be a PREPARSER command which we definitely need to execute.
			j = 0;
			while ((token_stack[j] == TOKEN_BLOCK_END) & (j < i)){
				// Scan the token stack for the last TOKEN_END_BLOCK
				j++;
			}
			// If we're at the end, just exit
			if (j == i) {
				token = i;
			} else {
				// Else see if the next one is a preparser command.
				if (token_stack[j] != TOKEN_PREPARSER){
					token = i;
				} else {
					token = 0;
				}
			}
		} else {
			token = i;		// Set the token pointer to the end of the stack, which causes no code generation to occur!
		}
	}
	while (token < i){
		if(DEBUG)
			printf("Processing Stack\n");
		switch (token_stack[token]) {
			case HASH_lib+HASH_OFFSET : 
				atStackStart();
				// Looks like we need to include a file.
				TokenIs(TOKEN_STRING);
				token++; // skip the start of string token
				while (token_stack[token] != TOKEN_END_STRING){
					filename[token-2] = ((unsigned char)token_stack[token] & 0x7f); // Convert to ASCII
					filename[token-1] = '\0'; //Null terminate!
					token++;
					if ((token-1) >= FILENAME_MAX) abort_b0("INTERNAL: Filename generation overflow! - Increase FILENAME_MAX");
				}
				TokenIs(TOKEN_END_STRING);
				token++;	// Skip TOKEN_END_STRING
				atStackEnd(i);
				// Save current ch and lch values;
				file[file_stack_ptr].ch = ch;
				file[file_stack_ptr].look_ahead_ch = look_ahead_ch;
				// Reset values;
				ch = 00;
				look_ahead_ch = 00;
				file_stack_ptr++;
				if (file_stack_ptr >= MAX_LIB_DEPTH)
					abort_b0("INTERNAL: File Table overflow - too many nested files! - Increase MAX_LIB_DEPTH");
				if (DEBUG)
					printf("filename = %s\n", filename);
				file[file_stack_ptr].handle = fopen(( char *) filename, "r");  // Let's see if it's in our current directory
				if (!file[file_stack_ptr].handle){
					// Now we just need to sort through the various include directories
					j = 0;
					while (j < total_paths){
						strcpy((char *) tmp_filename, paths[j]);
						strcat((char *) tmp_filename, (char *) filename);							// attach our include path
						file[file_stack_ptr].handle = fopen(( char *) tmp_filename, "r"); // Attempt to open
						if (DEBUG)
							printf("filename = %s; handle = %p\n", tmp_filename, file[file_stack_ptr].handle );
						if (file[file_stack_ptr].handle){						// We get a good handle
							strcpy((char *) file[file_stack_ptr].filename, ( char *) filename);	// So copy it to our file-open stack
							file[file_stack_ptr].line_count = 1;				// Reset line count.
							if (DEBUG)
								printf("found file: %s in %s\n", filename, paths[j]);
							break;												// and exit.
						}
						j++;
					}
					if (!file[file_stack_ptr].handle){
						abort_b0("Unable to open file");
						exit(1);
					}
				} else {
					strcpy((char *) file[file_stack_ptr].filename, ( char *)filename);
					file[file_stack_ptr].line_count = 1;
				};
				break;

			case HASH_syscall+HASH_OFFSET : 
			case HASH_sysret+HASH_OFFSET : 
			case HASH_fdecstp+HASH_OFFSET :
			case HASH_fincstp+HASH_OFFSET :
			case HASH_ret+HASH_OFFSET:
				atStackStart();
				fprintf(code, "\t%s\n", hash_table[token_stack[(token-1)]-HASH_OFFSET].token);
				atStackEnd(i);
				break;
				
			case HASH_extern+HASH_OFFSET:
				atStackStart();
				IsLabelAllocated();
				hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_EPROC;
				token++;
				TokenIs(TOKEN_PARA_START);
				token++;
				TokenIs(TOKEN_PARA_END);
				token++;
				if (token != i) {
					// We must have more in here!
					TokenIs(HASH_as+HASH_OFFSET); // The next keyword MUST be 'as';
					token++;
					TokenIs(TOKEN_STRING);
					token++;
					j = 0;
					k = token_stack[1]-HASH_OFFSET;
					while ((token_stack[token] != TOKEN_END_STRING) && (token != i)){
						hash_table[k].token_import_name[j] = ((unsigned char)token_stack[token] & 0x7f);
						j++;
						token++;
					}
					TokenIs(TOKEN_END_STRING);
					token++;
					if (token != i){
						// Looks like we are even defining the library name where the extern is located in!
						TokenIs(HASH_in+HASH_OFFSET);
						token++;
						isHash(token_stack[token]);
						l = token_stack[token]-HASH_OFFSET;
						if ((hash_table[l].token_type != 0x0)&&(hash_table[l].token_type != TYPE_ELIB))
							abort_b0("Unable to redefine Label/Token"); 
						token++;
						hash_table[l].token_type = TYPE_ELIB;
						// Now link the extern name to the export library token.
						hash_table[k].token_import_lib = l;
						if (token != i){
							// Looks like we are defining the actual DLL name as well.
							TokenIs(HASH_as+HASH_OFFSET); // The next keyword MUST be 'as';
							token++;
							TokenIs(TOKEN_STRING);
							token++;
							j = 0;
							while ((token_stack[token] != TOKEN_END_STRING) && (token != i)){
								hash_table[l].token_import_name[j] = ((unsigned char)token_stack[token] & 0x7f);
								j++;
								token++;
							}
							TokenIs(TOKEN_END_STRING);
							token++;
						}
					}				
				}; 
				atStackEnd(i);
				break;
				
			case HASH_push+HASH_OFFSET : 
			case HASH_pop+HASH_OFFSET : 
				atStackStart();
				j = token_stack[0]-HASH_OFFSET;
				while (token < i){
					TokenIsLabelType(TYPE_REG); // Only allow 64 bit regs
					fprintf(code, "\t%s %s\n", hash_table[j].token, hash_table[token_stack[token]-HASH_OFFSET].token);
					token++;
					if (token < i){
						TokenIs(TOKEN_COMMA);
						token++;
					}
				}
				atStackEnd(i);
				break;

			case HASH_in+HASH_OFFSET:
			case HASH_out+HASH_OFFSET:
				atStackStart();
				TokenIs(TOKEN_PARA_START);
				token++;
				TokenIsLabelType(TYPE_REG);
				if(token_stack[token] != HASH_r3+HASH_OFFSET)
					abort_b0("Expected register r3");
				token++;
				TokenIs(TOKEN_COMMA);
				token++;
				if((token_stack[token] != HASH_r0w+HASH_OFFSET)&&
					#ifndef i386
					(token_stack[token] != HASH_r0d+HASH_OFFSET)&&
					#endif
					(token_stack[token] != HASH_r0b+HASH_OFFSET))
						abort_b0("Expected register r0d, r0w or r0b");
				token++;
				TokenIs(TOKEN_PARA_END);
				token++;
				atStackEnd(i);
				if (token_stack[0] == HASH_in+HASH_OFFSET){
					fprintf(code, "\tin %s, r3w\n", hash_table[token_stack[4]-HASH_OFFSET].token);					
				} else {
					fprintf(code, "\tout r3w, %s\n", hash_table[token_stack[4]-HASH_OFFSET].token);
				}
				break;
				
			case HASH_call+HASH_OFFSET:
			case HASH_jmp+HASH_OFFSET:
				atStackStart();
				//token++;
				if (token_stack[token] == TOKEN_ARRAY_START){
					//We must have a global pointer
					token++;
					fprintf(code, "\t%s qword [", hash_table[token_stack[0]-HASH_OFFSET].token);
					Global_Pointer(i);
					TokenIs(TOKEN_ARRAY_END);
					fprintf(code, "]\n");
					token++;
				} else {
					// We should have a reg or a procedure();
					isHash(token_stack[token]);
					if (((hash_table[token_stack[token]-HASH_OFFSET].token_type) & TYPE_REG) == TYPE_REG){
						// We MUST have a register
						TokenIsLabelType(TYPE_REG);
						fprintf(code, "\t%s %s\n", hash_table[token_stack[0]-HASH_OFFSET].token, hash_table[token_stack[token]-HASH_OFFSET].token);
						token++;
					} else {
						//We should have a e_proc!
						TokenIsLabelType(TYPE_EPROC);
						if (SOURCE_TYPE != SOURCE_PE){
							fprintf(code, "\t%s %s\n", hash_table[token_stack[0]-HASH_OFFSET].token, hash_table[token_stack[token]-HASH_OFFSET].token);
						} else {
							fprintf(code, "\t%s [%s]\n", hash_table[token_stack[0]-HASH_OFFSET].token, hash_table[token_stack[token]-HASH_OFFSET].token);
						}						
						token++;
						TokenIs(TOKEN_PARA_START);
						token++;
						TokenIs(TOKEN_PARA_END);
						token++;
					}
				}
				atStackEnd(i);					
				break;
				
			case HASH_asm+HASH_OFFSET :
				atStackStart();
				atStackEnd(i);
				if (ch != '{') // Asm statements are to be followed immediately by a block.
					abort_b0("{ Expected");
				getChar();
				asm_in_string = 0;
				while ((ch != '}') || (asm_in_string == 1)){
					if ((ch == '/')&&(asm_in_string == 0)) { // Skip comments
						if (look_ahead_ch == '/'){
							while (ch != CR){
								getChar();
							}
						}
					}
					fprintf(code, "%c", ch);
					getChar();
					if (ch == '\'') {
						if (asm_in_string == 1) {
							asm_in_string = 0;
						} else {
							asm_in_string = 1;
						}
					}
				}
				if(DEBUG)
					printf("\n");
				block_level--;
				break;
			
			case HASH_else+HASH_OFFSET:
				abort_b0("Unexpected ELSE");
				break;
				
			case TOKEN_BLOCK_END:
				if(DEBUG)
					printf("processing TOKEN_END_BLOCK\n");
				while ((token_stack[token] == TOKEN_BLOCK_END) && (token < i)) {
					if (DEBUG)
						printf("token = %d, i = %d\n", token, i);
					if (DEBUG)
						printf("Calling END_BLOCK in while\n");
					if (token_stack[token+1] != HASH_else+HASH_OFFSET) {
						end_block();
					} else {
						end_block_else();
						token++;
						token++;
						atStackEnd(i);		// ELSE must ALWAYS be the last token on the stack
						if (ch != '{')		// Check for stack termination character!
							abort_b0("Illformed IF-THEN-ELSE statement");
					}
					token++;
				}
				if (DEBUG)
					printf("token = %d, i = %d\n", token, i);
				if (token < i) {
					// We have something other than ELSE
					// Becuase most items need to be at the start, we simply remove all
					// block ends, and reprocess as per normal.
					// We lucky becuase token = our first non } character!
					j = i - token; // make j our count!
					for (k = 0; k < j; k++){
						// Quick move the stack forward
						token_stack[k] = token_stack[token];
						token++;
					}
					token = 0;		// Set our stack pointer to 0
					i = j;			// Set our new stack size to the count!
				}
				break;
			
			case HASH_if+HASH_OFFSET:
			case HASH_while+HASH_OFFSET:
				if_while_block(i);
				
				// Now construct the test!
				if (hash_table[if_while_stack[block_level].if_while_test1].token_type == TYPE_FLAG) {
					// We have a flag comparison, so this is really easy.
					switch(if_while_stack[block_level].if_while_test1){
						case HASH_CARRY: fprintf(code, "\tjnc .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_NOCARRY: fprintf(code, "\tjc .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_OVERFLOW: fprintf(code, "\tjno .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_NOOVERFLOW: fprintf(code, "\tjo .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_PARITY: fprintf(code, "\tjnp .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_NOPARITY: fprintf(code, "\tjp .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_ZERO: 	fprintf(code, "\tjnz .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_NOTZERO: fprintf(code, "\tjz .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_SIGN: 	fprintf(code, "\tjns .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						case HASH_NOTSIGN: fprintf(code, "\tjs .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						default: abort_b0("Unknown CPU FLAG"); break;
					}
				} else {
					// Lets see if this is a FPU or INT operation.
					if (hash_table[if_while_stack[block_level].if_while_test1].token_type == TYPE_REG) {
						// Int test
						if ((hash_table[if_while_stack[block_level].if_while_test2].token_type != TYPE_REG) && (if_while_stack[block_level].if_while_test2 != HASH_zero))
							abort_b0("Second operand MUST be a integer register");
						if (if_while_stack[block_level].if_while_test2 != HASH_zero) {
							fprintf(code, "\tcmp %s, %s\n", hash_table[if_while_stack[block_level].if_while_test1].token, hash_table[if_while_stack[block_level].if_while_test2].token );
						} else {
							fprintf(code, "\ttest %s, %s\n", hash_table[if_while_stack[block_level].if_while_test1].token, hash_table[if_while_stack[block_level].if_while_test1].token );
						}
						switch (if_while_stack[block_level].comparison) {
							case TOKEN_EQUALS :	fprintf(code, "\tjne .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_NOTEQUALS : fprintf(code, "\tje .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_LESSTHAN : fprintf(code, "\tjae .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_GREATERTHAN : fprintf(code, "\tjbe .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_LESSTHANEQUALS : fprintf(code, "\tja .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_GREATERTHANEQUALS : fprintf(code, "\tjb .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_S_LESSTHAN : fprintf(code, "\tjge .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_S_GREATERTHAN : fprintf(code, "\tjle .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_S_LESSTHANEQUALS : fprintf(code, "\tjg .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							case TOKEN_S_GREATERTHANEQUALS : fprintf(code, "\tjl .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
						}
					} else {
						// FPU test
						if (if_while_stack[block_level].if_while_test2 != HASH_zero){
							if (if_while_stack[block_level].if_while_test1 != HASH_fp0)
								abort_b0("Floating point comparison requires that fp0 be the first operand");
							// Non-zero test
							if (hash_table[if_while_stack[block_level].if_while_test2].token_type != TYPE_REG_FPU)
								abort_b0("Second operand MUST be a FPU register");
							fprintf(code, "\tfcomi %s\n", hash_table[if_while_stack[block_level].if_while_test2].token );
							switch (if_while_stack[block_level].comparison) {
								case TOKEN_EQUALS :	fprintf(code, "\tjne .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_NOTEQUALS : fprintf(code, "\tje .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_LESSTHAN : fprintf(code, "\tjae .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_GREATERTHAN : fprintf(code, "\tjbe .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_LESSTHANEQUALS : fprintf(code, "\tja .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_GREATERTHANEQUALS : fprintf(code, "\tjb .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_S_LESSTHAN : fprintf(code, "\tjae .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_S_GREATERTHAN : fprintf(code, "\tjbe .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_S_LESSTHANEQUALS : fprintf(code, "\tja .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
								case TOKEN_S_GREATERTHANEQUALS : fprintf(code, "\tjb .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset); break;
							}
						} else {
							// Handle test against zero
							if (hash_table[if_while_stack[block_level].if_while_test1].token_type != TYPE_REG_FPU)
								abort_b0("Operand MUST be a register");
							fprintf(code, "\tfldz\n\tfcomip ");
							switch(if_while_stack[block_level].if_while_test1){
								case HASH_fp0: fprintf(code, "fp1\n"); break;
								case HASH_fp1: fprintf(code, "fp2\n"); break;
								case HASH_fp2: fprintf(code, "fp3\n"); break;
								case HASH_fp3: fprintf(code, "fp4\n"); break;
								case HASH_fp4: fprintf(code, "fp5\n"); break;
								case HASH_fp5: fprintf(code, "fp6\n"); break;
								case HASH_fp6: fprintf(code, "fp7\n"); break;
								case HASH_fp7: abort_b0("Error FPU stack overflow in IF-THEN construct"); break;
							}
							fprintf(code, "\tje .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset);
						}
					}
				}
				if ((token_stack[0]-HASH_OFFSET) == HASH_while) 	// Now set the return point.
					fprintf(code, "\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1));
				break;
				
			case HASH_proc+HASH_OFFSET :
				atStackStart();
				if(DEBUG)
					printf("Defining proc2\n");
				if (ch != '{')	// Proc decl statements are to be followed immediately by a block.
					abort_b0("{ Expected");
				isHash(token_stack[token]);
				if (global != 0) 
					abort_b0("Unable to nest proc definitions");
				global = token_stack[token];
				if (hash_table[(global-HASH_OFFSET)].token_type == 0) {
					hash_table[(global-HASH_OFFSET)].token_type = TYPE_PROC;
				} else {
					abort_b0("Unable to redeclare procedure?");
				}
				if(DEBUG)
					printf("Defining proc2\n");

				fprintf(code, "\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
				fprintf(code, "; %s Function Code ;\n", hash_table[(global-HASH_OFFSET)].token);
				fprintf(code, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n\n");				
				fprintf(data, "\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
				fprintf(data, "; %s Function Variables ;\n", hash_table[(global-HASH_OFFSET)].token);
				fprintf(data, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n\n");
				fprintf(bss,  "\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
				fprintf(bss,  "; %s Function BSS Variables ;\n", hash_table[(global-HASH_OFFSET)].token);
				fprintf(bss,  ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n\n");
				fprintf(code, "align 8\n");
				fprintf(code, "_B0_%s:\n", hash_table[(global-HASH_OFFSET)].token);
				local_var_offset = 0;
				// Now clean up the hash table of all local variables.
				for (j = 0; j < HASH_TABLE_SIZE; j++) {
					if ((hash_table[j].token_type & (TYPE_LOCAL)) > 0 ){
						if(DEBUG)
							printf("Erasing 0x%x -> 0x%lx = %s ,Type: 0x%x\n", j, hash_table[j].hash, hash_table[j].token, hash_table[j].token_type);
						hash_table[j].token_type = 0;
						hash_table[j].local_offset = 0;
					}
				};
				// Now process the parameters
				// token should be on the proc
				token++;
				// move to the first para?
				TokenIs(TOKEN_PARA_START);
				token++; // Lets see what we are testing?
				if (token_stack[token] == TOKEN_PARA_END) {
					// I guess we have no parameters.
					token++;
					atStackEnd(i);
					hash_table[(global-HASH_OFFSET)].local_offset = local_var_offset;
					if(DEBUG)
						printf("Proc defined - no variables\n");
					break;	// Let's get outa here!
				}
				// Alrightly all proc parameters are type m64 so this going to be a bit easier?
				while(token_stack[token] != TOKEN_PARA_END) {
					IsLabelAllocated();
					#ifndef i386
					hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M64+TYPE_LOCAL;
					#else
					hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M32+TYPE_LOCAL;
					#endif
					hash_table[(global-HASH_OFFSET)].local_offset = local_var_offset;
					fprintf(data, "_B0_%s_%s equ %d\n", hash_table[(global-HASH_OFFSET)].token, hash_table[(token_stack[token]-HASH_OFFSET)].token , local_var_offset);
				#ifndef i386
					local_var_offset += 8;
				#else
					local_var_offset += 4;
				#endif
					token++;
					if(token_stack[token] == TOKEN_COMMA)
						token++;
				}
				token++;
				atStackEnd(i);
				if(DEBUG)
					printf("Proc defined - variables defined\n");
				break;
				
			case HASH_m8+HASH_OFFSET :
			case HASH_m16+HASH_OFFSET :
			case HASH_m32+HASH_OFFSET :
			#ifndef i386
			case HASH_m64+HASH_OFFSET :
			#endif
			case HASH_f32+HASH_OFFSET :
			case HASH_f64+HASH_OFFSET :
			case HASH_f80+HASH_OFFSET :
				if(DEBUG)
					printf("Processing Variable Def\n");
				atStackStart();
				if (global == 0) {
					if (token_stack[token] == TOKEN_ARRAY_START) {
						// This gets a little complicated?
						toki = 0;
						token++;
						while (token_stack[token] != TOKEN_ARRAY_END) {
							token_buffer[toki] = (unsigned char)token_stack[token];
							token_buffer[toki+1] = '\0';
							toki++;
							token++;
							if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
						}
						token++; // Skip end of array size indicator.
						isHash(token_stack[token]);
						switch (token_stack[0]) {
							case HASH_m8+HASH_OFFSET :
								fprintf(bss, "_B0_%s rb %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token , token_buffer);
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M8+TYPE_ARRAY+TYPE_GLOBAL;
								break;
							case HASH_m16+HASH_OFFSET :
								fprintf(bss, "_B0_%s rw %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token, token_buffer );
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M16+TYPE_ARRAY+TYPE_GLOBAL;
								break;
							case HASH_m32+HASH_OFFSET :
								fprintf(bss, "_B0_%s rd %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token, token_buffer );
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M32+TYPE_ARRAY+TYPE_GLOBAL;
								break;
						#ifndef i386
							case HASH_m64+HASH_OFFSET :
								fprintf(bss, "_B0_%s rq %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token, token_buffer );
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M64+TYPE_ARRAY+TYPE_GLOBAL;
								break;
						#endif
							case HASH_f32+HASH_OFFSET :
								fprintf(bss, "_B0_%s rd %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token, token_buffer );
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F32+TYPE_ARRAY+TYPE_GLOBAL;
								break;
							case HASH_f64+HASH_OFFSET :
								fprintf(bss, "_B0_%s rq %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token, token_buffer );
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F64+TYPE_ARRAY+TYPE_GLOBAL;
								break;
							case HASH_f80+HASH_OFFSET :
								fprintf(bss, "_B0_%s rt %s\n", hash_table[(token_stack[token]-HASH_OFFSET)].token, token_buffer );
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F80+TYPE_ARRAY+TYPE_GLOBAL;
								break;
						}
						token++;
						atStackEnd(i);
					} else {
						isHash(token_stack[token]);
						switch (token_stack[token-1]) {
							case HASH_m8+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s db ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rb 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M8+TYPE_GLOBAL;
								break;
							case HASH_m16+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s dw ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rw 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M16+TYPE_GLOBAL;
								break;
							case HASH_m32+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s dd ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rd 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M32+TYPE_GLOBAL;
								break;
						#ifndef i386
							case HASH_m64+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s dq ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rq 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M64+TYPE_GLOBAL;
								break;
						#endif
							case HASH_f32+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s dd ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rd 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F32+TYPE_GLOBAL;
								break;
							case HASH_f64+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s dq ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rq 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F64+TYPE_GLOBAL;
								break;
							case HASH_f80+HASH_OFFSET :
								if ((token+1)!=i){
									fprintf(data, "_B0_%s dt ", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								} else {
									fprintf(bss, "_B0_%s rt 1\n", hash_table[(token_stack[token]-HASH_OFFSET)].token );
								}
								IsLabelAllocated();
								hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F80+TYPE_GLOBAL;
								break;
						}
						token++;
						if (token != i) {
							// We have tokens that follow?
							TokenIs(TOKEN_EQUATE);
							token++;
							while (token < i){
								if (token_stack[token] == TOKEN_STRING) {
									TokenIs(TOKEN_STRING);
									token++;
									if ((token_stack[token-4] == HASH_f32+HASH_OFFSET) ||
										(token_stack[token-4] == HASH_f64+HASH_OFFSET) ||
										(token_stack[token-4] == HASH_f80+HASH_OFFSET))
										abort_b0("Strings cannot be encoded using f32, f64 or f80.");
									// Before outputing the string, lets find the length of the string.
									j = 0;
									while (token_stack[token] != TOKEN_END_STRING){
										j++;
										token++;
									}
									token = token - j; // Reset the token back to it's correct value
									if (UTF8_STRINGS == 0){
										if (token_stack[token-4] == HASH_m8+HASH_OFFSET)
											abort_b0("To enable UTF8 encoded strings, please use the -UTF8 switch or\n #COMPILER_OPTION directive");
										fprintf(data, "0%xh,0%xh,", j, j);
										outputString(i);
									} else {
										j = 0;
										k = token;
										while (token_stack[token] != TOKEN_END_STRING){
											if (token_stack[token] < 0x80) {
												j++;
											} else {
												if (token_stack[token] < 0x800) {
													// 2 byte encoding
													j = j+2;
												} else {
													if (token_stack[token] < 0x10000){
														// 3 byte encoding
														j = j+3;
													} else {
														// 4 byte encoding
														j = j+4;
													}
												}
											}
											token++;
										}
										token = k; // Reset the token back to it's correct value
										if (j > 256){
											if(WarningsDisabled == 0){
												if(HeaderPrinted == 0)
													PrintHeader();
												printf("WARNING: String is too long for UTF8 encoding, setting length marker to 255\n");
												printf("Filename: %s Line: %d.\n",file[file_stack_ptr].filename, (file[file_stack_ptr].line_count));
											}
											j = 255;
										};
										fprintf(data, "0%xh,0%xh,", j, j);
										outputStringUTF8(i);
									}
									TokenIs(TOKEN_END_STRING);
									token++;
								} else {
									if (token_stack[token] == TOKEN_MINUS){
										fprintf(data, "-");
										token++;
									}
									if (token_stack[token] > TOKEN_OFFSET)
										abort_b0("Immediate Expected");
									switch(token_stack[0]) {
										case HASH_m8+HASH_OFFSET :
										case HASH_m16+HASH_OFFSET :
										case HASH_m32+HASH_OFFSET :
									#ifndef i386
										case HASH_m64+HASH_OFFSET :
									#endif
													outputNumberD(i, NUM_INTEGER);
													break;
										case HASH_f32+HASH_OFFSET :
										case HASH_f64+HASH_OFFSET :
										case HASH_f80+HASH_OFFSET :
													outputNumberD(i, NUM_DECIMAL);
													break;
									}
								}
								if((token_stack[token] == TOKEN_COMMA) && (token != i)){
									fprintf(data, ",");
									token++;
								}
							}
							fprintf(data, "\n");
						}
						atStackEnd(i);
					}
				} else {
					// We have a local, and global -> current proc
					if (token_stack[token] == TOKEN_ARRAY_START) {
						// This gets a little complicated?
						toki = 0;
						token++;
						if (token_stack[token] == TOKEN_ARRAY_END)
							abort_b0("Unexpected ]");
						while (token_stack[token] != TOKEN_ARRAY_END) {
							if(token_stack[token] > TOKEN_OFFSET)
								abort_b0("Immediate value expected");
							token_buffer[toki] = (unsigned char)token_stack[token];
							token_buffer[toki+1] = '\0';
							toki++;
							token++;
							if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
						}
						token++; // Skip end of array size indicator.
					} else {
						token_buffer[0] = '1';
						token_buffer[1] = 0;
					}
					//token buffer is our size in ASCII
					isHash(token_stack[token]);
					fprintf(data, "_B0_%s_%s equ %d\n", hash_table[(global-HASH_OFFSET)].token, hash_table[(token_stack[token]-HASH_OFFSET)].token , local_var_offset);
					
					switch (token_stack[0]) {
						case HASH_m8+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer));
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M8+TYPE_LOCAL;
							break;
						case HASH_m16+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer) * 2);
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M16+TYPE_LOCAL;
							break;
						case HASH_m32+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer) * 4);
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M32+TYPE_LOCAL;
							break;
					#ifndef i386
						case HASH_m64+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer) * 8);
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_M64+TYPE_LOCAL;
							break;
					#endif
						case HASH_f32+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer) * 4);
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F32+TYPE_LOCAL;
							break;
						case HASH_f64+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer) * 8);
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F64+TYPE_LOCAL;
							break;
						case HASH_f80+HASH_OFFSET :
							IsLabelAllocated();
							local_var_offset = local_var_offset + (dhtoi(token_buffer) * 10);
							hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_F80+TYPE_LOCAL;
							break;
					}
					//set the used stack frame for the current proc.
					hash_table[(global-HASH_OFFSET)].local_offset = local_var_offset;
					token++;
					atStackEnd(i);
				}
				if(DEBUG)
					printf("End Processing Variable Def\n");
				break;
			
			case HASH_struc+HASH_OFFSET:
				atStackStart();
				IsLabelAllocated();
				hash_table[(token_stack[token]-HASH_OFFSET)].token_type = TYPE_STRUC;
				hash_table[(token_stack[token]-HASH_OFFSET)].local_offset = 0; // At entry 0 into structure's structure.
				struc_def = token_stack[token]-HASH_OFFSET;
				hash_table[struc_def].struc_ptr = calloc(1, sizeof(struc_struc));
				if(DEBUG)
					printf("Source ptr = %p\n", hash_table[struc_def].struc_ptr);
				if (hash_table[struc_def].struc_ptr == NULL)
					abort_b0("Out of Memory!");
				token++;
				atStackEnd(i);
				exit_struc = 0;
				token = 0;		// Clear the stack before we star our own little private processing run.
				getChar();
				while (exit_struc == 0) {
					do_process = nextToken();
					if (DEBUG) 
						printf("do_process_struc = 0x%x, token = 0x%x\n", do_process, token);
					if (token != 0){
						switch(do_process){
							case 1 : preparse_token_stack(); 
									exit_struc = process_struc(); 
									if(do_process == 0)
										i = exit_struc;
									break;		// get the next token, and set token variable
							case 2 : // We have encountered a { so let's handle it gracefully.
								if (token_stack[0] != TOKEN_BLOCK_END)
									abort_b0("Invalid construct");
								// We have something other than ELSE
								// Becuase most items need to be at the start, we simply remove all
								// block ends, and reprocess as per normal.
								// We get lucky becuase token = our first non } character!
								j = token - 1; // make j our count!
								token = 1;
								for (k = 0; k < j; k++){
									// Quick move the stack forward
									token_stack[k] = token_stack[token];
									token++;
									if (DEBUG)
										printf("stack[%d] = 0x%x\n",k,token_stack[k]);
								}
								token = 0;		// Set our stack pointer to 0
								i = j;			// Set our new stack size to the count!
								exit_struc = 1;
								if(DEBUG)
									printf("process stack > token = 0x%x, i = 0x%x\n", token, i);
								block_level++;
								if(block_level >= TOKEN_STACK_SIZE)
									abort_b0("INTERNAL: Block Level is too large - too many nested blocks! - Increase TOKEN_STACK_SIZE");
								do_process = 0;
								break;
						}
					}
					if (DEBUG)
						printf("exit_struc = 0x%x\n", exit_struc);
				}
				if (DEBUG) 
					printf("final do_process_struc = 0x%x, token = 0x%x, i = %d\n", do_process, token, i);
				if (do_process == 1) token = i;
				block_level--;
				break;
				
			case TOKEN_NOT: 
			case TOKEN_MINUS: 
				atStackStart();
				if (token_stack[token] < HASH_OFFSET)
					abort_b0("Expected Token/Label");
				if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & (TYPE_REG + TYPE_REG_SHORT + TYPE_REG_FPU)) == 0 )
					abort_b0("Expected Register");
				if (hash_table[token_stack[token]-HASH_OFFSET].token_type == TYPE_REG_FPU) {
					if (token_stack[0] == TOKEN_NOT){
						abort_b0("FPU registers do not support bitwise operations");
					} else {
						if (token_stack[token]-HASH_OFFSET == HASH_fp0){
							fprintf(code, "\tfchs\n");
						} else {
							abort_b0("NEG can only be performing on fp0");
						}
					}
				} else {
					if (token_stack[0] == TOKEN_NOT){
						fprintf(code, "\tnot %s\n", hash_table[token_stack[token]-HASH_OFFSET].token);
					} else {
						fprintf(code, "\tneg %s\n", hash_table[token_stack[token]-HASH_OFFSET].token);
					}				
				}
				token++;
				atStackEnd(i);
				break;
				
			case HASH_exit+HASH_OFFSET :
			case HASH_return+HASH_OFFSET :
				atStackStart();
				TokenIs(TOKEN_PARA_START);
				token++;
				if (token_stack[token] != TOKEN_PARA_END){
					if ((token_stack[token] < TOKEN_OFFSET) || (token_stack[token] == TOKEN_MINUS)) {
						// We have an immediate load
						fprintf(code, "\tmov r0, ");
						if (token_stack[token] == TOKEN_MINUS) {
							token++;
							fprintf(code, "-");
						}
						outputNumber(i, NUM_INTEGER);
						fprintf(code, "\n");
					} else {
						// We should have a reg										
						TokenIsLabelType(TYPE_REG);  // Only allow 64bit reg
						if ((token_stack[token]-HASH_OFFSET) != HASH_r0)	// If the reg is r0, then don't output code!
							fprintf(code, "\tmov r0, %s\n", hash_table[token_stack[token]-HASH_OFFSET].token);
						token++;
					}
					TokenIs(TOKEN_PARA_END);
				} else {
					fprintf(code, "\tmov r0, 0\n");
				}
				if (token_stack[0] == HASH_exit+HASH_OFFSET){
					fprintf(code, "\tjmp B0_sys_exit\n");
				} else {
					fprintf(code, "\tret\n");
				}
				token++;
				atStackEnd(i);
				break;
			
			case TOKEN_PREPARSER:
				if(DEBUG)
					printf("Preparser Command - ");
				atStackStart();
				switch(token_stack[token]){
					case HASH_define+HASH_OFFSET:
						if(DEBUG)
							printf("define\n");
						if (pp_GenCode[pp_ptr] == 1) {
							token++;
							if (token == i) 
								abort_b0("Invalid Construct");	// We should have something;
							IsLabelAllocated();		// Lets see if our token is already defined?
							token++;
							if (token != i){
								TokenIs(TOKEN_EQUATE);
								token++;
								if ((token_stack[token] == TOKEN_MINUS) || (token_stack[token] < TOKEN_OFFSET)) {
									// We have an immediate which is what is expected!
									setDefine(token_stack[2]-HASH_OFFSET, i); // This sets the label to a define, with value!
									atStackEnd(i);
								} else {
									abort_b0("Invalid Construct");
								}
							} else {
								// Look like a simple #define {label};
								hash_table[token_stack[2]-HASH_OFFSET].token_type = TYPE_DEFINE; // Set the label to TYPE_DEFINE
							}
							atStackEnd(i);
						} else {
							token = i; // Skip the DEFINE statement
						}
						if(DEBUG)
							printf("#define - pp_ptr = %d, pp_GenCode = %d\n", pp_ptr, pp_GenCode[pp_ptr]);
						break;
					case HASH_undefine+HASH_OFFSET:
						if(DEBUG)
							printf("undefine\n");
						if (pp_GenCode[pp_ptr] == 1) {
							token++;
							if (token == i) 
								abort_b0("Invalid Construct");	// We should have something;
							isHash(token_stack[token]);
							if ((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_DEFINE) == TYPE_DEFINE) {
								hash_table[token_stack[token]-HASH_OFFSET].token[0] = 0;
								hash_table[token_stack[token]-HASH_OFFSET].hash = 0;
								hash_table[token_stack[token]-HASH_OFFSET].token_type = 0;
								hash_table[token_stack[token]-HASH_OFFSET].local_offset = 0;
								hash_table[token_stack[token]-HASH_OFFSET].define_int = 0;
								hash_table[token_stack[token]-HASH_OFFSET].define_fp = 0;
							}
							token++;
							atStackEnd(i);
						} else {
							token = i; // Skip the UNDEFINE statement
						}
						if(DEBUG)
							printf("#undefine - pp_ptr = %d, pp_GenCode = %d\n", pp_ptr, pp_GenCode[pp_ptr]);					
						break;
						
					case HASH_ifdef+HASH_OFFSET:
					case HASH_ifndef+HASH_OFFSET:
						if(DEBUG)
							printf("ifdef or ifndef\n");
						if (pp_GenCode[pp_ptr] == 1) {
							token++; // Skip the current preparser command
							token++; // Skip the hash of the token!
							if (i == token) {
								// we are at the end of the token stack.
								token--;
								// The value on the stack MUST be a HASH.
								isHash(token_stack[token]);
								pp_ptr++;
								if(pp_ptr >= MAX_LIB_DEPTH) abort_b0("INTERNAL: Preprocessor depth too large - Increase MAX_LIB_DEPTH");
								// Let's see if the hash is defined
								if (hash_table[token_stack[token]-HASH_OFFSET].token_type == 0) {
									// It hasn't been defined!
									if (token_stack[1] == HASH_ifdef+HASH_OFFSET) {
										pp_GenCode[pp_ptr] = 0;
									} else {
										pp_GenCode[pp_ptr] = 1;
									}
								} else {
									// It has been defined in some way, it could be a proc, variable, keyword, or other, we don't care!
									if (token_stack[1] == HASH_ifdef+HASH_OFFSET) {
										pp_GenCode[pp_ptr] = 1;
									} else {
										pp_GenCode[pp_ptr] = 0;
									}							
								}
								token++;
							} else {
								// We must have a comparison operator?
								token--;
								isHash(token_stack[token]);
								target = token_stack[token] - HASH_OFFSET;
								pp_ptr++;
								if(pp_ptr >= MAX_LIB_DEPTH) abort_b0("INTERNAL: Preprocessor depth too large - Increase MAX_LIB_DEPTH");
								token++;
								if ((token_stack[token] >= TOKEN_EQUALS)&&(token_stack[token] <= TOKEN_GREATERTHAN)){
									// We have our operator;
									token++;
									if ((token_stack[token] > TOKEN_OFFSET)&&(token_stack[token]!=TOKEN_MINUS))
										abort_b0("Immediate expected");
									if (token_stack[1] == HASH_ifndef+HASH_OFFSET)
										abort_b0("Value comparisons are only available for #ifdef");
										
									pp_GenCode[pp_ptr] = checkDefine(target, token_stack[token-1], i);
									// checkDefine returns 1 for TRUE, 0 for FAIL.
								} else {
									abort_b0("Invalid construct");
								}
							}
							atStackEnd(i);
						} else {
							pp_ptr++;
							if(pp_ptr >= MAX_LIB_DEPTH) abort_b0("INTERNAL: Preprocessor depth too large - Increase MAX_LIB_DEPTH");
							pp_GenCode[pp_ptr] = 0;
						}
						token = i;
						if(DEBUG)
							printf("#ifdef - pp_ptr = %d, pp_GenCode = %d\n", pp_ptr, pp_GenCode[pp_ptr]);
						break;
					case HASH_else+HASH_OFFSET:
						if(DEBUG)
							printf("else\n");
						token++;
						atStackEnd(i);
						if (pp_GenCode[(pp_ptr-1)] == 1) {
							if (pp_GenCode[pp_ptr] == 1) {
								pp_GenCode[pp_ptr] = 0;
							} else {
								pp_GenCode[pp_ptr] = 1;
							}
						}
						if(DEBUG)
							printf("#else - pp_ptr = %d, pp_GenCode = %d\n", pp_ptr, pp_GenCode[pp_ptr]);
						break;
					case HASH_endif+HASH_OFFSET:
						if(DEBUG)
							printf("endif\n");
						pp_ptr--;
						token++;
						atStackEnd(i);
						if(DEBUG)
							printf("#endif - pp_ptr = %d, pp_GenCode = %d\n", pp_ptr, pp_GenCode[pp_ptr]);
						break;
					case HASH_COMPILER_OPTION+HASH_OFFSET:
						if (pp_GenCode[pp_ptr] == 1){
							// Only if code generation is true do we process this...
							if(DEBUG)
								printf("#COMPILER_OPTION:");
							token++;
							while (token < i){
								// We may have multiple options.
								switch(token_stack[token]){
									case HASH_UTF8+HASH_OFFSET:
										UTF8_STRINGS = 1;
										CLI_UTF8_STRINGS = 1;
										if (DEBUG)
											printf(" UTF8");
										break;
									case HASH_UTF16+HASH_OFFSET:
										UTF8_STRINGS = 0;
										CLI_UTF8_STRINGS = 1;
										if(DEBUG)
											printf(" UTF16");
										break;
									case HASH_PE+HASH_OFFSET:
									case HASH_ELF+HASH_OFFSET:
									case HASH_ELFO+HASH_OFFSET:
										if (ftell(code))
											abort_b0("Unable to define object format once code has been generated");
										if (SOURCE_CLI){
											if(WarningsDisabled == 0){
												if(HeaderPrinted == 0)
													PrintHeader();
												switch(SOURCE_TYPE){
													case SOURCE_PE: printf("WARNING: Object Format \"PE\" already defined - Ignoring Setting\n"); break;
													case SOURCE_ELF: printf("WARNING: Object Format \"ELF Executable\" already defined - Ignoring Setting\n"); break;
													case SOURCE_ELFO: printf("WARNING: Object Format \"ELF Object\" already defined - Ignoring Setting\n"); break;
												}
											}
										} else {
											SOURCE_CLI = 1;
											switch(token_stack[token]){
												case HASH_PE+HASH_OFFSET:
													SOURCE_TYPE = SOURCE_PE;
													if (DEBUG)
														printf(" PE");
													break;
												case HASH_ELF+HASH_OFFSET:
													SOURCE_TYPE = SOURCE_ELF;
													if (DEBUG)
														printf(" ELF");
													break;
												case HASH_ELFO+HASH_OFFSET:
													SOURCE_TYPE = SOURCE_ELFO;
													if (DEBUG)
														printf(" ELFO");
													break;
											}
										}
										break;
									case HASH_ENABLESTACKFRAME+HASH_OFFSET:
										STACK_FRAME = 1;
										if(DEBUG){
											printf(" ENABLESTACKFRAME");
										}
										break;
									case HASH_DISABLESTACKFRAME+HASH_OFFSET:
										STACK_FRAME = 0;
										if(DEBUG){
											printf(" DISABLESTACKFRAME");
										}
										break;
										
									default:
										abort_b0("Unknown Compiler Option");
								}
								token++;
							}
							if(DEBUG)
								printf("\n");
							atStackEnd(i);
						}
						break;
					
					default: abort_b0("Invalid construct - Preparser"); break;
				}
				break;
				
			default :
				if(DEBUG)
					printf("Processing Default: - token index = %d; i = %d\n", token, i);
				
				if(token_stack[token] > HASH_OFFSET){
					if (((hash_table[token_stack[token]-HASH_OFFSET].token_type & TYPE_STRUC)==TYPE_STRUC) &&
						(hash_table[token_stack[token]-HASH_OFFSET].struc_ptr != NULL)){
						process_struc_def(i);
						token = i;
						break;
					}
				}
				
				if(global == 0)
					abort_b0("Unexpected instructions");
				
				if ( token_stack[token] < TOKEN_ARRAY_START)
					abort_b0("Invalid construct");
				
				// Determine if operation is an int or FP operation?
				if (TS_is_int(i)){
					process_int_operation(i);
				} else {
					process_fpu_operation(i);
				}
				token = i;
				break;
		}
	}
	token = 0;
	return(1);
}

unsigned int nextToken(void){
	int i;
	unsigned int UTF32;
	while (isSpace(ch)) {
		//skip whitespace
		getChar();
	}
	if (ch == '/') { // Skip comments
		if (look_ahead_ch == '/'){
			while ((ch != CR)&&(ch != '\r')&&(ch != 0xffffffff)){
				getChar();
			}
			return(0);
		}
	}
	if (!isDigit(ch) && !isAlpha(ch)) {
		//process operator
		switch(ch) {
			case '\'' :
				insert_token_stack(TOKEN_STRING);
				if(DEBUG)
					printf("START STRING\n");
				getChar();
				while (ch != '\'') {
					if (ch == '\\') {
						switch (look_ahead_ch) {
							case 'n' :
								insert_token_stack(CR);
								getChar();
								getChar();
								if(DEBUG)
									printf("Output 0x%x , ch == %c\n", CR, ch);
								break;
							case 'r' :
								insert_token_stack(LF);
								getChar();
								getChar();
								if(DEBUG)
									printf("Output 0x%x , ch == %c\n", LF, ch);
								break;
							case 't' :
								insert_token_stack(TAB);
								getChar();
								getChar();
								if(DEBUG)
									printf("Output 0x%x , ch == %c\n", TAB, ch);
								break;
							case '\\' :
								insert_token_stack('\\');
								getChar();
								getChar();
								if(DEBUG)
									printf("Output \\, ch == %c\n", ch);
								break;
							case '\'' :
								insert_token_stack('\'');
								getChar();
								getChar();
								if(DEBUG)
									printf("Output \', ch == %c\n", ch);
								break;
							case '0' :
								insert_token_stack(0);
								getChar();
								getChar();
								if(DEBUG)
									printf("Output NULL, ch == NULL\n");
								break;
							default :
								insert_token_stack((unsigned int) ch);
								getChar();
								break;
						}
					} else {
						if (ch == 0xffffffff)
							return(0);
						// What we need to do is handle UTF-8 input correctly.
						if (ch < 0x7f) {
							insert_token_stack((unsigned int) ch);
						} else {
							// We must have a UTF-8 character.
							if (ch < 0xdf) {
								// we have a 2 byte sequence
								UTF32 = (unsigned int) ch & 0x1f;
								UTF32 = UTF32 << 6;
								getChar(); // Get our second character
								if (ch < 0x7f)
									abort_b0("Poor UTF-8 construct");
								UTF32 = UTF32 + (ch & 0x3f);
								insert_token_stack(UTF32);
							} else {
								if (ch < 0xf0) {
									// We have a 3 byte sequence
									UTF32 = (unsigned int) ch & 0x0f;
									UTF32 = UTF32 << 6;
									getChar(); // Get our second character
									if ((unsigned int) ch < 0x7f)
										abort_b0("Poor UTF-8 construct");
									UTF32 = UTF32 + ((unsigned int)ch & 0x3f);
									UTF32 = UTF32 << 6;
									getChar(); // Get our third character
									if ((unsigned int) ch < 0x7f)
										abort_b0("Poor UTF-8 construct");
									UTF32 = UTF32 + ((unsigned int)ch & 0x3f);
									insert_token_stack(UTF32);
								} else {
									// We must have a 4 byte sequence
									UTF32 = (unsigned int) ch & 0x0f;
									UTF32 = UTF32 << 6;
									getChar(); // Get our second character
									if ((unsigned int) ch < 0x7f)
										abort_b0("Poor UTF-8 construct");
									UTF32 = UTF32 + ((unsigned int) ch & 0x3f);
									UTF32 = UTF32 << 6;
									getChar(); // Get our third character
									if ((unsigned int) ch < 0x7f)
										abort_b0("Poor UTF-8 construct");
									UTF32 = UTF32 + ((unsigned int) ch & 0x3f);
									UTF32 = UTF32 << 6;
									getChar(); // Get our fourth character
									if ((unsigned int) ch < 0x7f)
										abort_b0("Poor UTF-8 construct");
									UTF32 = UTF32 + ((unsigned int) ch & 0x3f);
									insert_token_stack(UTF32);
								}
							}
						}
						getChar();
					}
				}
				insert_token_stack(TOKEN_END_STRING);
				if(DEBUG)
					printf("END STRING\n");
				break;
			
			case '{' :
				return(2);
				break;
				
			case '}' :
				insert_token_stack(TOKEN_BLOCK_END);
				break;
				
			case ';' :
				getChar();
				return(1);
				break;
				
			case '=' :
				if (look_ahead_ch == '=') {
					getChar();
					insert_token_stack(TOKEN_EQUALS);
				} else {
					insert_token_stack(TOKEN_EQUATE);
				}
				break;	
				
			case '&' :
				if (look_ahead_ch == '&') {
					getChar();
					insert_token_stack(TOKEN_AND);
				} else {
					insert_token_stack(TOKEN_POINTER);
				}
				break;
				
			case '|' :
				insert_token_stack(TOKEN_OR);
				break;

			case '^' :
				insert_token_stack(TOKEN_XOR);
				break;
				
			case '!' :
				if (look_ahead_ch == '=') {
					getChar();
					insert_token_stack(TOKEN_NOTEQUALS);
				} else {
					insert_token_stack(TOKEN_NOT);
				}
				break;
				
			case '*' :
				insert_token_stack(TOKEN_MULTIPLY);
				break;
				
			case '+' :
				insert_token_stack(TOKEN_ADD);
				break;
				
			case '-' :
				insert_token_stack(TOKEN_MINUS);
				break;
				
			case '/' :
				insert_token_stack(TOKEN_DIVIDE);
				break;
				
			case '%' :
				insert_token_stack(TOKEN_MODULUS);
				break;
				
			case '(' :
				insert_token_stack(TOKEN_PARA_START);
				break;
				
			case ')' :
				insert_token_stack(TOKEN_PARA_END);
				break;
			case '[' :
				insert_token_stack(TOKEN_ARRAY_START);
				break;
				
			case ']' :
				insert_token_stack(TOKEN_ARRAY_END);
				break;
				
			case '<' :
				if (look_ahead_ch == '<') {
					getChar();
					if (look_ahead_ch == '<') {
						getChar();
						insert_token_stack(TOKEN_LROTATE);
					} else {
						insert_token_stack(TOKEN_LSHIFT);
					}
				} else {
					if (look_ahead_ch == '=') {
						getChar();
						insert_token_stack(TOKEN_LESSTHANEQUALS);
					} else {
						insert_token_stack(TOKEN_LESSTHAN);
					}
				}
				break;
				
			case '>' :
				if (look_ahead_ch == '>') {
					getChar();
					if (look_ahead_ch == '>') {
						getChar();
						insert_token_stack(TOKEN_RROTATE);
					} else {
						insert_token_stack(TOKEN_RSHIFT);
					}
				} else {
					if (look_ahead_ch == '=') {
						getChar();
						insert_token_stack(TOKEN_GREATERTHANEQUALS);
					} else {
						insert_token_stack(TOKEN_GREATERTHAN);
					}
				}
				break;

			case ',' :
			    insert_token_stack(TOKEN_COMMA);
				break;

			case '.' :
			    insert_token_stack(TOKEN_FULLSTOP);
				break;

			case '#' :
			    insert_token_stack(TOKEN_PREPARSER);
				break;


				case '~' :	//Signed operation
				switch(look_ahead_ch){
					case '>' : getChar();
								if (look_ahead_ch == '=') {
									getChar();
									insert_token_stack(TOKEN_S_GREATERTHANEQUALS);
								} else {
									insert_token_stack(TOKEN_S_GREATERTHAN);
								}
								break;
								
					case '<' : getChar();
								if (look_ahead_ch == '=') {
									getChar();
									insert_token_stack(TOKEN_S_LESSTHANEQUALS);
								} else {
									insert_token_stack(TOKEN_S_LESSTHAN);
								}
								break;
								
					case '*' : getChar(); 
								insert_token_stack(TOKEN_S_MULTIPLY); 
								break;
								
					case '/' : getChar(); 
								insert_token_stack(TOKEN_S_DIVIDE); 
								break;
								
					case '%' : getChar(); 
								insert_token_stack(TOKEN_S_MODULUS); 
								break;
								
					default :
						abort_b0("Unknown Signed operation");
						break;
				}
				break;

				
			default :
				if (ch == 0xffffffff){
					return(1);
				}
				if ((ch == 0xef) && (look_ahead_ch == 0xbb)) {
					// we may have a BOM
					getChar(); // Get the next char
					if (look_ahead_ch != 0xbf)
						abort_b0("Unknown Symbol - BOM");
					getChar(); // Move the BOM indicator 0xbf into ch.
				} else {
					printf("ch = 0x%x, lch = 0x%x\n", ch, look_ahead_ch);
					abort_b0("Unknown Symbol - UNK");
				}
				break;
		}
		getChar();
	} else {
		if (isDigit(ch)){
			//process digit
			insert_token_stack((unsigned int)ch);
			getChar();
			while ((isXDigit(ch)) || (ch == '.')) {
				insert_token_stack((unsigned int)tolower(ch));
				getChar();
			}
			if ((ch == 'h')||(ch == 'H')){ // Include terminating 'h' if found?
				insert_token_stack('h');
				getChar();
			}
			if (isAlpha(ch)){
				abort_b0("Unexpected Alpha");
			}
		} else {
			//process token
			
			//Clear our token buffer
			for (i = 0; i < TOKEN_MAX_SIZE; i++) {
				token_buffer[i] = 0;
			}
			
			// copy our input into the buffer
			toki = 0;
			while (isAlpha(ch) || isDigit(ch)) {
				token_buffer[toki] = (unsigned char) (ch & 0xff);
				toki++;
				if (toki >= TOKEN_MAX_SIZE) abort_b0("INTERNAL: Token Preprocessor Buffer Overflow! - Increase TOKEN_MAX_SIZE");
				getChar();
			}
			
			// get the hash
			token_hash = (ElfHash(&token_buffer[0])) % HASH_TABLE_SIZE + 1; //Can't have tokens = 0
			
			if (token_hash >= (HASH_TABLE_SIZE-1)) token_hash = 1;
			
			// Check for collision?
			if (hash_table[token_hash].hash == 0){ 
				// No entry, so we just enter the hash into the table
				hash_table[token_hash].hash = token_hash;
				strcpy((char *) hash_table[token_hash].token, ( char *) token_buffer);
				if(DEBUG)
					printf("TOKEN : %s = 0x%lx\n", hash_table[token_hash].token, hash_table[token_hash].hash);
			} else {
				// Let's see if we have the same string
				if (strcmp((char *) token_buffer, ( char *) hash_table[token_hash].token)) {
					// If the string are different, then we have a real problem!
					if(DEBUG)
						printf("Hash Collision Detected 0x%lx = %s = %s\n", token_hash, hash_table[token_hash].token, token_buffer);
					i = 0;
					while ((hash_table[token_hash].hash != 0) && strcmp((char *) token_buffer, ( char *) hash_table[token_hash].token)) {
						token_hash++; // Linear refactor the hash!
						i++;
						if (i >= HASH_TABLE_SIZE-1) {
							if(DEBUG){
								printf("HASH TABLE----------\n");
								for (i = 0; i < HASH_TABLE_SIZE; i++) {
									if (hash_table[i].hash != 0)
										printf("0x%x -> 0x%lx = %s\n", i, hash_table[i].hash, hash_table[i].token);
								};
							}
							abort_b0("INTERNAL: Hash Table Overflow! - Increase HASH_TABLE_SIZE");
						}
						if (token_hash >= HASH_TABLE_SIZE-1) {
							token_hash = 1; // Wrap around so we don't go off the table
						}
					}
					hash_table[token_hash].hash = token_hash;
					strcpy((char *) hash_table[token_hash].token, ( char *) token_buffer);
					if(DEBUG)
						printf("TOKEN : %s = 0x%lx\n", hash_table[token_hash].token, hash_table[token_hash].hash);
				}
			}
			
			insert_token_stack(token_hash+HASH_OFFSET);
		}
	}
	return(0);
}

int end_block_else(void) {
	unsigned int old_block_num;
	block_level--;
	if (DEBUG)
		printf("EBE_ current block level is %d\n", block_level);
	if (block_level < 1)
		abort_b0("Unexpected }");
	if (block_level == 1) {
		abort_b0("Unexpected ELSE");
	} else {
		if (if_while_stack[block_level].type == HASH_if) {
			// Lets terminate the if statement
			old_block_num = if_while_stack[block_level].offset;
			if_while_stack[block_level].offset = block_num;
			fprintf(code, "\tjmp .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset);
			fprintf(code, "\t.B0_END_BLOCK_0000%d:\n", old_block_num);
		} else {
			if (if_while_stack[block_level].type == HASH_while)
				abort_b0("Unexpected ELSE");
		}
	}
	return(0);
}

int end_block(void){
	block_level--;
	if(DEBUG)
		printf("EB_ Current Block Level is %d\n", block_level);
	if (block_level < 1)
		abort_b0("Unexpected }");
	if (block_level == 1) {
		if (global != 0){  // If global == 0 then we must be in a struc?
			fprintf(code, "\tmov r0, 0\n\tret\n\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
			fprintf(code, "; End %s Function Code;\n", hash_table[(global-HASH_OFFSET)].token);
			fprintf(code, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n\n");				
			fprintf(data, "\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
			fprintf(data, "; End %s Function Variables ;\n", hash_table[(global-HASH_OFFSET)].token);
			fprintf(data, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n\n");				
			fprintf(bss,  "\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n");
			fprintf(bss,  "; End %s Function BSS Variables ;\n", hash_table[(global-HASH_OFFSET)].token);
			fprintf(bss,  ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n\n");				
			hash_table[(global-HASH_OFFSET)].local_offset = local_var_offset;
			global = 0;
		}
	} else {
		// We most likely have ended a if or a while. Let's ensure that we terminate the block 
		// correctly.
		if (if_while_stack[block_level].type == HASH_if) {
			// Lets terminate the if statement
			fprintf(code, "\t.B0_END_BLOCK_0000%d:\n", if_while_stack[block_level].offset);
		} else {
			if (if_while_stack[block_level].type == HASH_while) {
				// Lets terminate the while block correctly
				if (hash_table[if_while_stack[block_level].if_while_test1].token_type == TYPE_FLAG) {
					// We have a flag comparison, so this is really easy.
					switch(if_while_stack[block_level].if_while_test1){
						case HASH_CARRY: fprintf(code, "\tjc .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_NOCARRY: fprintf(code, "\tjnc .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_OVERFLOW: fprintf(code, "\tjo .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_NOOVERFLOW: fprintf(code, "\tjno .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_PARITY: fprintf(code, "\tjp .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_NOPARITY: fprintf(code, "\tjnp .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_ZERO: 	fprintf(code, "\tjz .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_NOTZERO: fprintf(code, "\tjnz .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_SIGN: 	fprintf(code, "\tjs .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						case HASH_NOTSIGN: fprintf(code, "\tjns .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						default: abort_b0("Unknown CPU FLAG"); break;
					}
				} else {
					if (hash_table[if_while_stack[block_level].if_while_test1].token_type == TYPE_REG) {
						// Int test
						if ((hash_table[if_while_stack[block_level].if_while_test2].token_type != TYPE_REG) && (if_while_stack[block_level].if_while_test2 != HASH_zero))
							abort_b0("Second operand MUST be a integer register");
						if (if_while_stack[block_level].if_while_test2 != HASH_zero) {
							fprintf(code, "\tcmp %s, %s\n", hash_table[if_while_stack[block_level].if_while_test1].token, hash_table[if_while_stack[block_level].if_while_test2].token );
						} else {
							fprintf(code, "\ttest %s, %s\n", hash_table[if_while_stack[block_level].if_while_test1].token, hash_table[if_while_stack[block_level].if_while_test1].token );
						}
						switch (if_while_stack[block_level].comparison) {
							case TOKEN_EQUALS :	fprintf(code, "\tje .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
							case TOKEN_NOTEQUALS : fprintf(code, "\tjne .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
							case TOKEN_LESSTHAN : fprintf(code, "\tjb .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
							case TOKEN_GREATERTHAN : fprintf(code, "\tja .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
							case TOKEN_LESSTHANEQUALS : fprintf(code, "\tjbe .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
							case TOKEN_GREATERTHANEQUALS : fprintf(code, "\tjae .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
							case TOKEN_S_LESSTHAN : fprintf(code, "\tjl .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
							case TOKEN_S_GREATERTHAN : fprintf(code, "\tjg .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
							case TOKEN_S_LESSTHANEQUALS : fprintf(code, "\tjle .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
							case TOKEN_S_GREATERTHANEQUALS : fprintf(code, "\tjge .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
						}
					} else {
						// FPU test
						if (if_while_stack[block_level].if_while_test2 != HASH_zero){
							// Non-zero test
							if (if_while_stack[block_level].if_while_test1 != HASH_fp0)
								abort_b0("Floating point comparison requires that fp0 be the first operand");
							if (hash_table[if_while_stack[block_level].if_while_test2].token_type != TYPE_REG_FPU)
								abort_b0("Second operand MUST be a FPU register");
							fprintf(code, "\tfcomi %s\n", hash_table[if_while_stack[block_level].if_while_test2].token );
							switch (if_while_stack[block_level].comparison) {
								case TOKEN_EQUALS :	fprintf(code, "\tje .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
								case TOKEN_NOTEQUALS : fprintf(code, "\tjne .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
								case TOKEN_LESSTHAN : fprintf(code, "\tjb .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
								case TOKEN_GREATERTHAN : fprintf(code, "\tja .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
								case TOKEN_LESSTHANEQUALS : fprintf(code, "\tjbe .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
								case TOKEN_GREATERTHANEQUALS : fprintf(code, "\tjae .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
								case TOKEN_S_LESSTHAN : fprintf(code, "\tjb .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
								case TOKEN_S_GREATERTHAN : fprintf(code, "\tja .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
								case TOKEN_S_LESSTHANEQUALS : fprintf(code, "\tjbe .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset);	break;
								case TOKEN_S_GREATERTHANEQUALS : fprintf(code, "\tjae .B0_END_BLOCK_0000%d\n\t.B0_END_BLOCK_0000%d:\n", (if_while_stack[block_level].offset-1), if_while_stack[block_level].offset); break;
							}					
						} else {
							// Handle test against zero
							if (hash_table[if_while_stack[block_level].if_while_test1].token_type != TYPE_REG_FPU)
								abort_b0("Operand MUST be a register");
							fprintf(code, "\tfldz\n\tfcomip ");
							switch(if_while_stack[block_level].if_while_test1){
								case HASH_fp0: fprintf(code, "fp1\n"); break;
								case HASH_fp1: fprintf(code, "fp2\n"); break;
								case HASH_fp2: fprintf(code, "fp3\n"); break;
								case HASH_fp3: fprintf(code, "fp4\n"); break;
								case HASH_fp4: fprintf(code, "fp5\n"); break;
								case HASH_fp5: fprintf(code, "fp6\n"); break;
								case HASH_fp6: fprintf(code, "fp7\n"); break;
								case HASH_fp7: abort_b0("Error FPU stack overflow in WHILE construct"); break;
							}
							fprintf(code, "\tjne .B0_END_BLOCK_0000%d\n", if_while_stack[block_level].offset-1);
							fprintf(code, "\t.B0_END_BLOCK_0000%d:\n", if_while_stack[block_level].offset);
						}
					}
				}
			}
		}
		if_while_stack[block_level].type = 0;
		// Else fall through
	}
	return(0);
}

int block(void){
	unsigned int do_process = 0;
	block_level++;
	if(DEBUG)
		printf("BLOCK_ Current Block Level is %d\n", block_level);
	if (block_level >= TOKEN_STACK_SIZE)
		abort_b0("INTERNAL: Block Level is too large - too many nested blocks - Increase TOKEN_STACK_SIZE");
	block_num++;
	getChar();				// Get next character
	if (ch ==  0xffffffff) { //If EOF
		fclose(file[file_stack_ptr].handle); // Close current file
		file_stack_ptr--;	//Move the file stack pointer down one

		if (file_stack_ptr < 0) {
			return(0);		// If we are now off the stack, exit
		} else {
			ch = file[file_stack_ptr].ch;
			look_ahead_ch = file[file_stack_ptr].look_ahead_ch;
		}
		process_token_stack();
							// else process remaining tokens to flush the stack
							// before moving onto another file
		block_level--;
		if(DEBUG)
			printf("BLOCK_ Current Block Level is now %d after flush\n", block_level);
	}
	while (ch != 0xffffffff) {
		do_process = nextToken();
		if (DEBUG) 
			printf("do_process = 0x%x, token = 0x%x, Block Level = 0x%x\n", do_process, token, block_level);
		if (token != 0){
			switch(do_process){
				case 1 : process_token_stack(); break;		// get the next token, and set token variable
				case 2 : process_token_stack(); block(); break;
			}
		}
		do_process = 0;
	}
	return(0);
}

void include_standard_output(void) {
	#ifndef i386
	fprintf(file[0].handle, "\n;Register renaming\n\nr0 equ rax\nr0d equ eax\nr0w equ ax\nr0b equ al\n");
	fprintf(file[0].handle, "r1 equ rbx\nr1d equ ebx\nr1w equ bx\nr1b equ bl\n");
	fprintf(file[0].handle, "r2 equ rcx\nr2d equ ecx\nr2w equ cx\nr2b equ cl\n");
	fprintf(file[0].handle, "r3 equ rdx\nr3d equ edx\nr3w equ dx\nr3b equ dl\n");
	fprintf(file[0].handle, "r4 equ rdi\nr4d equ edi\nr4w equ di\nr4b equ dil\n");
	fprintf(file[0].handle, "r5 equ rsi\nr5d equ esi\nr5w equ si\nr5b equ sil\n");
	fprintf(file[0].handle, "r6 equ rbp\nr6d equ ebp\nr6w equ bp\nr6b equ bpl\n");
	fprintf(file[0].handle, "r7 equ rsp\nr7d equ esp\nr7w equ sp\nr7b equ spl\n\n");
	#else
	fprintf(file[0].handle, "\n;Register renaming\n\nr0 equ eax\nr0w equ ax\nr0b equ al\n");
 	fprintf(file[0].handle, "r1 equ ebx\nr1w equ bx\nr1b equ bl\n");
 	fprintf(file[0].handle, "r2 equ ecx\nr2w equ cx\nr2b equ cl\n");
 	fprintf(file[0].handle, "r3 equ edx\nr3w equ dx\nr3b equ dl\n");
 	fprintf(file[0].handle, "r4 equ edi\nr4w equ di\n");
 	fprintf(file[0].handle, "r5 equ esi\nr5w equ si\n");
 	fprintf(file[0].handle, "r6 equ ebp\nr6w equ bp\n");
 	fprintf(file[0].handle, "r7 equ esp\nr7w equ sp\n\n");
	#endif
	
	fprintf(file[0].handle, "fp0 equ ST0\nfp1 equ ST1\nfp2 equ ST2\nfp3 equ ST3\n");
	fprintf(file[0].handle, "fp4 equ ST4\nfp5 equ ST5\nfp6 equ ST6\nfp7 equ ST7\n\n");
	

	fprintf(file[0].handle, ";Default Macros\n");
	fprintf(file[0].handle, "macro UTF16_STRING name, [string]\n{\n");
	fprintf(file[0].handle, "common\n\tname:\nlocal label,label2\n\tlabel:\n");
	fprintf(file[0].handle, "\tdw ((label2-label)/2)-3\n\tdw ((label2-label)/2)-3\n");
	fprintf(file[0].handle, "\tdw string\n\tlabel2:\n\tdw 0\n}\n\n");
	fprintf(file[0].handle, "macro UTF8_STRING name, [string]\n{\n");
	fprintf(file[0].handle, "common\n\tname:\nlocal label,label2\n\tlabel:\n");
	fprintf(file[0].handle, "\tdb ((label2-label)/2)-3\n\tdb ((label2-label)/2)-3\n");
	fprintf(file[0].handle, "\tdb string\n\tlabel2:\n\tdb 0\n}\n\n");

}

void include_public_extrns(void){
	unsigned int i;
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if ((hash_table[i].hash != 0)&&(hash_table[i].token_type == TYPE_PROC)){
			if (i == 0x36768) {
				fprintf(file[0].handle, "public _B0_%s as 'main'\n", hash_table[i].token);
			} else {
				fprintf(file[0].handle, "public _B0_%s\n", hash_table[i].token);
			}
		}
	};
	fprintf(file[0].handle, "\n\n");
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if ((hash_table[i].hash != 0)&&(hash_table[i].token_type == TYPE_EPROC))
			fprintf(file[0].handle, "extrn %s\n", hash_table[i].token);
	};
	fprintf(file[0].handle, "\n\n");
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		//if ((hash_table[i].hash != 0)&&(hash_table[i].token_type == 0))
			//fprintf(file[0].handle, "extrn _B0_%s\n", hash_table[i].token);
	};
}

void include_public_extrns_pe(void){
	unsigned int i = 0, j = 0;

	// Let's start by scanning the hash_table and ensuring each EPROC has a parent ELIB defined
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if (hash_table[i].token_type == TYPE_EPROC){
			if (hash_table[i].token_import_lib == 0x0)
				abort_b0("External Procedure has not been linked to a parent DLL");		
		}
	};		
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if ((hash_table[i].token_type == TYPE_ELIB))
			fprintf(file[0].handle, "dd 0,0,0, RVA %s_name, RVA %s_table\n", hash_table[i].token, hash_table[i].token);
	};		

	fprintf(file[0].handle, "dd 0,0,0,0,0\n\n");

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if ((hash_table[i].token_type == TYPE_ELIB)){
			fprintf(file[0].handle, "%s_table:\n", hash_table[i].token);
			for (j = 0; j < HASH_TABLE_SIZE; j++){
				if (hash_table[j].token_import_lib == i){
					// That is this token is matched to a known ELIB!
					#ifndef i386
					fprintf(file[0].handle, "\t%s dq RVA _%s\n", hash_table[j].token, hash_table[j].token);
					#else
					fprintf(file[0].handle, "\t%s dd RVA _%s\n", hash_table[j].token, hash_table[j].token);
					#endif
				}
			}
			#ifndef i386
			fprintf(file[0].handle, "\tdq 0\n\n");
			#else
			fprintf(file[0].handle, "\tdd 0\n\n");
			#endif
		}
	};

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if ((hash_table[i].token_type == TYPE_ELIB)){
			if (DEBUG)
				printf("%s is '%s',0\n", hash_table[i].token, hash_table[i].token_import_name);
			if (hash_table[i].token_import_name[0] == 0x0)
				abort_b0("External Library has not had DLL name defined");
			fprintf(file[0].handle, "%s_name db '%s',0\n", hash_table[i].token, hash_table[i].token_import_name);
		}
	};		
	fprintf(file[0].handle, "\n");

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		if ((hash_table[i].token_type == TYPE_EPROC)){
			if (DEBUG)
				printf("%s is '%s',0\n", hash_table[i].token, hash_table[i].token_import_name);
			if (hash_table[i].token_import_name[0] == 0x0)
				abort_b0("External Procedure has not had a name defined");
			fprintf(file[0].handle, "_%s dw 0\n\tdb '%s',0\n", hash_table[i].token, hash_table[i].token_import_name);
		}
	};
			
	fprintf(file[0].handle, "\n\n");
}

int main(int argc, char *argv[]){
	#ifdef _MSC_VER
		long long int i;
	#else
		long int i;
	#endif
	unsigned int j;
	unsigned char *pdest;
	const unsigned char *ptr;
	int Help = 0;
	int Version = 0;
	int have_file = 0;
	time_start = clock();
	pp_ptr = 0;
	pp_GenCode[pp_ptr] = 1;				// We want to generate code.
	total_paths = 0;

	if(argc > 1){
		for(i=0;i<argc;i++){
			if(!strcmp(argv[i], "-DEBUG"))
				DEBUG = 1;
			if(!strcmp(argv[i], "-UTF8"))
				{ UTF8_STRINGS = 1; CLI_UTF8_STRINGS = 1; }
			if(!strcmp(argv[i], "-UTF16"))
				{ UTF8_STRINGS = 0; CLI_UTF8_STRINGS = 1; }
			if(!strcmp(argv[i], "-?"))
				Help = 1;
			if(!strcmp(argv[i], "-h"))
				Help = 1;
			if(!strcmp(argv[i], "-v"))
				Version = 1;
			if(!strcmp(argv[i], "-l")){
				PrintHeader();
				PrintLicense();
				exit(0);
			}
			if(!strcmp(argv[i], "-W"))
				WarningsDisabled = 1;
			if(!strcmp(argv[i], "-!"))
				ContinueOnAbort = 1;
			if((argv[i][0] == '-') && (argv[i][1] == 'i')){
				path = &argv[i][2]; // Set pointer to the CLI environment
				scan_env(path);
			}
			if((argv[i][0] == '-') && (argv[i][1] == 'f')){
				//Set the type of Source Output = SOURCE_TYPE
				if(!strcmp(argv[i], "-felf")){
					SOURCE_TYPE = SOURCE_ELF;
					SOURCE_CLI = 1;
				} else {
					if(!strcmp(argv[i], "-fpe")){
						SOURCE_TYPE = SOURCE_PE;
						SOURCE_CLI = 1;
					} else {
						if(!strcmp(argv[i], "-felfo")){
							SOURCE_TYPE = SOURCE_ELFO;
							SOURCE_CLI = 1;
						} else {
							PrintHeader();
							printf("Error: Unknown Output Format?\n");
							exit(1);
						}
					}
				}
			}
			if((argv[i][0] != '-') && (i != 0) && (have_file == 0)){
				// Else let's assume for now that it's our filename?
				strcpy((char *) filename,argv[i]);
				have_file = 1;
			}
		}
	} else {
		PrintHelp();
	}

	if ((Help)||(!have_file)||(Version)){
		if(Help)
			PrintHelp();
		
		if((!have_file)&&(!Version))
			PrintHelp();
		
		PrintHeader();
		if(!have_file)
			exit(0);
	}

	b0_env = getenv("B0_INCLUDE");
	if(b0_env) scan_env(b0_env);
	// If you have any directories to include they should already be added.
	// total_paths = number of paths we can search!
	
	if(DEBUG){
		PrintHeader();
		switch(SOURCE_TYPE){
			case SOURCE_ELF: printf("Output Format: ELF Executable\n"); break;
			case SOURCE_ELFO: printf("Output Format: ELF Object\n"); break;
			case SOURCE_PE: printf("Output Format: PE\n"); break;
		}
		if (UTF8_STRINGS == 1){
			printf("Strings will be encoded as UTF8\n");
		} else {
			printf("Strings will be encoded as UTF16\n");
		}
		for (j=0;j<total_paths;j++){
			printf("search path = %s\n", paths[j]);
	}

	}
	
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		hash_table[i].hash = 0;
	};

	//Setup reserved labels within the hash table...
	
	ptr = TOKEN_KEYWORD;
	while(*ptr){
		insert_token(ptr, TYPE_KEYWORD);
		while(*ptr++);
	};
	ptr = TOKEN_REG;
	while(*ptr){
		insert_token(ptr, TYPE_REG);
		while(*ptr++);
	};
	ptr = TOKEN_REG_SHORT;
	while(*ptr){
		insert_token(ptr, TYPE_REG_SHORT);
		while(*ptr++);
	};
	ptr = TOKEN_REG_FPU;
	while(*ptr){
		insert_token(ptr, TYPE_REG_FPU);
		while(*ptr++);
	};
	ptr = TOKEN_FLAG;
	while(*ptr){
		insert_token(ptr, TYPE_FLAG);
		while(*ptr++);
	};
	ptr = TOKEN_RESERVED;
	while(*ptr){
		insert_token(ptr, TYPE_RESERVED);
		while(*ptr++);
	};
	
	state = 0;			// Reset code state to null;
	file_stack_ptr = 0;
	local_var_offset = 0;
	dynamic_string_count = 0; //Number of dynamic string decl.
 
	if(DEBUG)
		printf("Filename = %s\n", filename);
	
	file[file_stack_ptr].handle = fopen((char *)filename, "r");
	if (!file[file_stack_ptr].handle){
		printf("ERROR: Unable to open file: %s\n", filename);
		exit(1);
	} else {
		strcpy((char *) file[file_stack_ptr].filename, (char *)filename);
		file[file_stack_ptr].line_count = 1;
	};
	
	// Open our first pass asm files
	code = fopen("c_output.tmp", "w+");
	data = fopen("d_output.tmp", "w+");
	bss  = fopen("b_output.tmp", "w+");

	if (!code){
		printf("ERROR: Unable to create temp file");
		exit(1);
	}
	if (!data){
		printf("ERROR: Unable to create temp file");
		exit(1);
	}
	if (!bss){
		printf("ERROR: Unable to create temp file");
		exit(1);
	}

	
	look_ahead_ch = 0; 	// Prime the current char buffer
	token = 0;
	global = 0;			// We start from a global level
	block_level = 0;
	block_num = 0;
	while (file_stack_ptr >= 0) {
		// As long as we have a file to read, let's keep going
		block();
	}
	if(DEBUG){
		printf("EOF reached\n");
		//For testing, dump the hash table!
		printf("HASH TABLE----------\n");
		for (i = 0; i < HASH_TABLE_SIZE; i++) {
			if (hash_table[i].hash != 0)
				printf("0x%lx -> 0x%lx = %s ,Type: 0x%x, Import = %s -> 0x%lx\n", i, hash_table[i].hash, hash_table[i].token, 
					hash_table[i].token_type, hash_table[i].token_import_name, hash_table[i].token_import_lib);
		};
	}
	
	rewind(code);
	rewind(data);
	rewind(bss);
	strcpy((char *)filename, ( char *)file[0].filename); // Let's get our original name
	
	pdest = (unsigned char *) strrchr((char *)filename, '.');
	if (pdest != NULL) {
		i = pdest - filename;
		if (DEBUG) 
			printf("%s = %ld\n", filename, i);
		filename[i] = '\0';			// Truncate the string at the last '.'
	}
	strcat((char *)filename, ".asm");			// Append .asm to the end!
	
	file[0].handle = fopen((char *)filename, "w");
	if (!file[0].handle){
		printf("ERROR: Unable to create file: %s\n", filename);
		exit(1);
	}
	
	switch(SOURCE_TYPE){
		case SOURCE_PE: 			
			fprintf(file[0].handle, ";; B0 EXECUTABLE\n;; PE FORMAT\n\n");
			include_standard_output();  // Include default equates and macros.
			#ifndef i386
			fprintf(file[0].handle, "format PE64 GUI 5.0\nuse64\nstack 1000000h\n\nentry start\n\n");
			#else
			fprintf(file[0].handle, "format PE GUI 4.0\nuse32\nstack 1000000h\n\nentry start\n\n");
			#endif

			//Now we do our data! (Since the data section also has our defines).
			fprintf(file[0].handle, "\nsection '.data' data readable writeable\n\n");

			ch = fgetc(data);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(data);
			}
			fprintf(file[0].handle, "\ndb \"EXB0 %s\",0\n\n", B0_VERSION);

			//Now we do our bss!
			ch = fgetc(bss);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(bss);
			}

			fprintf(file[0].handle, "align 16\nDATA_END:\n");
			
			//FUCKING NASTY HACK FOR PE
			#ifndef i386
			if ((hash_table[0x3270d].hash != 0)&&(hash_table[0x3270d].token_type == TYPE_DEFINE+TYPE_M64)) {
			#else
			if ((hash_table[0x3270d].hash != 0)&&(hash_table[0x3270d].token_type == TYPE_DEFINE+TYPE_M32)) {
			#endif
				fprintf(file[0].handle, "\trb %lxh\n", hash_table[0x3270d].define_int);
			} else {
				fprintf(file[0].handle, "\trb 1000000h\n");
			} // PS. Hash 0x3270d == LOCAL_HEAP!

			// Now we do our code...
			fprintf(file[0].handle, "\nsection '.code' code readable executable\n\n");
			
			fprintf(file[0].handle, "\nstart:\n");
			fprintf(file[0].handle, "\tfinit\n\tlea r6,[DATA_END]\n\tcall _B0_main\n");
			fprintf(file[0].handle, "\nB0_sys_exit:\n");
			#ifndef i386
			fprintf(file[0].handle, "\tmov ecx,eax\n\tcall [ExitProcess]\n");
			#else
			fprintf(file[0].handle, "\tpush r0\n\tcall [ExitProcess]\n");
			#endif

			ch = fgetc(code);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(code);
			}
			
			//Now lastly, we do our import section. (This is a Windows thing, basically we list all our externs). 
			fprintf(file[0].handle, "\nsection '.idata' import data readable writeable\n\n");
			include_public_extrns_pe(); // Include the rest of the public's and externs.
			
			fprintf(file[0].handle, "\n\n;EOF\n");
			break;

		case SOURCE_ELF: 
		
			if ((hash_table[0x36768].hash == 0) || (hash_table[0x36768].token_type != TYPE_PROC)){
				if(WarningsDisabled == 0){
					if(HeaderPrinted == 0)
						PrintHeader();
					printf("WARNING: Procedure main(); not found?\n");
				}
			}
			
			fprintf(file[0].handle, ";; B0 EXECUTABLE\n;; ELF FORMAT for Linux\n\n");
			#ifndef i386
			fprintf(file[0].handle, "format ELF64 executable\nuse64\nentry main\n\n");
			#else
			fprintf(file[0].handle, "format ELF executable\nuse32\nentry main\n\n");
			#endif
			include_standard_output();  // Include default equates and macros.
			
			#ifdef i386
			fprintf(file[0].handle, "macro syscall\n{\n");
			fprintf(file[0].handle, "\tint 80h\n}\n\n");
			fprintf(file[0].handle, "macro sysret\n{\n");
			fprintf(file[0].handle, "\tiret\n}\n\n");
			#endif

			fprintf(file[0].handle, "\n\nsegment readable writeable\n\n");
			ch = fgetc(data);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(data);
			}
			fprintf(file[0].handle, "\ndb \"EXB0 %s\",0\n\n", B0_VERSION);
			fprintf(file[0].handle, "\nsegment executable\n\nmain:\n\tfinit\n\tcall _B0_main\n");
			fprintf(file[0].handle, "\nB0_sys_exit:\n");
			fprintf(file[0].handle, "\tmov r4,r0 ;our exit code\n\tmov r0,1\n\tsyscall\n");
			fprintf(file[0].handle, "\n;We assume Linux output for ELF?\n");
			ch = fgetc(code);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(code);
			}
			fprintf(file[0].handle, "\nsegment writeable readable\n");	// BSS Segment
			ch = fgetc(bss);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(bss);
			}
			//fprintf(file[0].handle, "\nsegment writeable readable\n");	// Workaround for bug, umm updated feature in Linux Kernel 2.6.11 series.
			fprintf(file[0].handle, "\n\n;EOF\n");
			break;
			
		case SOURCE_ELFO: 
			fprintf(file[0].handle, ";; B0 OBJECT\n;; ELF OBJECT FORMAT for Linux\n\n");
			#ifndef i386
			fprintf(file[0].handle, "format ELF64\nuse64\n\n");
			#else
			fprintf(file[0].handle, "format ELF\nuse32\n\n");
			#endif
			include_standard_output();  // Include default equates and macros.
			#ifdef i386
			fprintf(file[0].handle, "macro syscall\n{\n");
			fprintf(file[0].handle, "\tint 80h\n}\n\n");
			fprintf(file[0].handle, "macro sysret\n{\n");
			fprintf(file[0].handle, "\tiret\n}\n\n");
			#endif

			// Now include our publics and externs
			include_public_extrns(); // Include the rest of the public's and externs.
			
			fprintf(file[0].handle, "\n;Externs for exit from application\nextrn exit\n");
			
			fprintf(file[0].handle, "\n\nsection '.data' writeable\n\n");
			ch = fgetc(data);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(data);
			}
			fprintf(file[0].handle, "\ndb \"EXB0 %s\",0\n\n", B0_VERSION);
			fprintf(file[0].handle, "\nsection '.bss' writeable\n\n");
			ch = fgetc(bss);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(bss);
			}
			fprintf(file[0].handle, "\nsection '.text' executable\n\n");
			ch = fgetc(code);
			while (ch != 0xffffffff){
				fprintf(file[0].handle, "%c", ch);
				ch = fgetc(code);
			}
			fprintf(file[0].handle, "\nB0_sys_exit:\n");
			//fprintf(file[0].handle, "\tmov ebx,eax ;our exit code\n\tmov eax,1\n\tint 0x80\n");
			fprintf(file[0].handle, "\tmov r4, r0\n\tmov r0, 0\n\tcall exit\n");
			fprintf(file[0].handle, "\n\n;EOF\n");
			break;
	}
	
	time_end = clock();
	duration = (double)(time_end - time_start) / CLOCKS_PER_SEC;
	if(DEBUG || Version){
		printf( "Processing Time: %5.3f seconds\n", duration );
		printf( "Processing Time: 0%xh clocks\n", (unsigned int)(time_end - time_start));
	}
	fclose(code);
	fclose(data);
	fclose(bss);
	remove("c_output.tmp");
	remove("d_output.tmp");
	remove("b_output.tmp");
	fclose(file[0].handle);
	return(0);
}
