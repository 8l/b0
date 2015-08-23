// View with tab = 4 char

#define TOKEN_STACK_SIZE 4096
#define STRUC_SIZE 16384
#define HASH_TABLE_SIZE 250007
						//Size of the hash table.
						
#define TOKEN_MAX_SIZE 256
#define HASH_OFFSET 0x10000000
						//Offset used to store hash within token stack
						
#define MAX_LIB_DEPTH 64
						// Allow up to 64 deep

						
#define PATHS_MAX 256	
						// Allow up to 256 paths to held for searching for
						// includes.
						
#define CR 0xa
#define LF 0xd
#define TAB 0x9
#define SP 0x20

#define NUM_DECIMAL 	0
#define NUM_INTEGER 	1

// #define SOURCE_FLAT 	0
// #define SOURCE_0F 	1
#define SOURCE_ELF 	2
#define SOURCE_PE 	3
#define SOURCE_ELFO 	4

#define TOKEN_OFFSET        		0x1000000
#define TOKEN_AND    				TOKEN_OFFSET + 0x0001
#define TOKEN_OR     				TOKEN_OFFSET + 0x0002
#define TOKEN_XOR	 			TOKEN_OFFSET + 0x0003
#define TOKEN_NOT	 			TOKEN_OFFSET + 0x0004
#define TOKEN_EQUATE 				TOKEN_OFFSET + 0x0005
#define TOKEN_ADD    				TOKEN_OFFSET + 0x0006
#define TOKEN_MINUS  				TOKEN_OFFSET + 0x0007
#define TOKEN_MULTIPLY 			TOKEN_OFFSET + 0x0008
#define TOKEN_DIVIDE 				TOKEN_OFFSET + 0x0009
#define TOKEN_MODULUS 			TOKEN_OFFSET + 0x000a
#define TOKEN_S_MULTIPLY 			TOKEN_OFFSET + 0x000b
#define TOKEN_S_DIVIDE 			TOKEN_OFFSET + 0x000c
#define TOKEN_S_MODULUS 			TOKEN_OFFSET + 0x000d
#define TOKEN_RROTATE 			TOKEN_OFFSET + 0x000e
#define TOKEN_LROTATE 			TOKEN_OFFSET + 0x000f
#define TOKEN_RSHIFT 				TOKEN_OFFSET + 0x0010
#define TOKEN_LSHIFT 				TOKEN_OFFSET + 0x0011

#define TOKEN_EQUALS 				TOKEN_OFFSET + 0x0020
#define TOKEN_NOTEQUALS 			TOKEN_OFFSET + 0x0021
#define TOKEN_S_LESSTHANEQUALS 	TOKEN_OFFSET + 0x0022
#define TOKEN_S_GREATERTHANEQUALS	TOKEN_OFFSET + 0x0023
#define TOKEN_S_LESSTHAN 			TOKEN_OFFSET + 0x0024
#define TOKEN_S_GREATERTHAN 		TOKEN_OFFSET + 0x0025
#define TOKEN_LESSTHANEQUALS 		TOKEN_OFFSET + 0x0026
#define TOKEN_GREATERTHANEQUALS	TOKEN_OFFSET + 0x0027
#define TOKEN_LESSTHAN 			TOKEN_OFFSET + 0x0028
#define TOKEN_GREATERTHAN 		TOKEN_OFFSET + 0x0029

#define TOKEN_COMMA				TOKEN_OFFSET + 0x0030
#define TOKEN_BLOCK_END			TOKEN_OFFSET + 0x0031
#define TOKEN_PREPARSER			TOKEN_OFFSET + 0x0032
#define TOKEN_FULLSTOP			TOKEN_OFFSET + 0x0033

#define TOKEN_STRING 				TOKEN_OFFSET + 0x0040
#define TOKEN_END_STRING 			TOKEN_OFFSET + 0x0041
#define TOKEN_PARA_START 			TOKEN_OFFSET + 0x0042
#define TOKEN_PARA_END 			TOKEN_OFFSET + 0x0043

#define TOKEN_POINTER 			TOKEN_OFFSET + 0x0050
#define TOKEN_ARRAY_START 		TOKEN_OFFSET + 0x0051
#define TOKEN_ARRAY_END 			TOKEN_OFFSET + 0x0052

//Predefined hashes for reserved keywords.
//WARNING: If you modify the hash function, or change the hash table
// size, you will NEED TO RECALCULATE these values.

#define HASH_r0 			0x751
#define HASH_r1 			0x752
#define HASH_r2 			0x753
#define HASH_r3 			0x754
#define HASH_r4 			0x755
#define HASH_r5 			0x756
#define HASH_r6 			0x757
#define HASH_r7 			0x758
#ifndef i386
#define HASH_r8 			0x759
#define HASH_r9 			0x75a
#define HASH_r10 		0x7541
#define HASH_r11 		0x7542
#define HASH_r12 		0x7543
#define HASH_r13 		0x7544
#define HASH_r14 		0x7545
#define HASH_r15 		0x7546
#endif

#define HASH_r0b 		0x7563
#define HASH_r1b 		0x7573
#define HASH_r2b 		0x7583
#define HASH_r3b 		0x7593
#define HASH_r4b 		0x75a3
#ifndef i386
#define HASH_r5b 		0x75b3
#define HASH_r6b 		0x75c3
#define HASH_r7b 		0x75d3
#define HASH_r8b 		0x75e3
#define HASH_r9b 		0x75f3
#define HASH_r10b 		0x383cc
#define HASH_r11b 		0x383dc
#define HASH_r12b 		0x383ec
#define HASH_r13b		0x383fc
#define HASH_r14b 		0x3840c
#define HASH_r15b 		0x3841c
#endif

#define HASH_r0w 		0x7578
#define HASH_r1w 		0x7588
#define HASH_r2w 		0x7598
#define HASH_r3w 		0x75a8
#define HASH_r4w 		0x75b8
#define HASH_r5w 		0x75c8
#define HASH_r6w 		0x75d8
#define HASH_r7w 		0x75e8
#define HASH_r8w 		0x75f8
#define HASH_r9w 		0x7608
#define HASH_r10w 		0x383e1
#define HASH_r11w 		0x383f1
#define HASH_r12w 		0x38401
#define HASH_r13w 		0x38411
#define HASH_r14w 		0x38421
#define HASH_r15w 		0x38431

#ifndef i386
#define HASH_r0d 		0x7565
#define HASH_r1d 		0x7575
#define HASH_r2d 		0x7585
#define HASH_r3d 		0x7595
#define HASH_r4d 		0x75a5
#define HASH_r5d 		0x75b5
#define HASH_r6d 		0x75c5
#define HASH_r7d 		0x75d5
#define HASH_r8d 		0x75e5
#define HASH_r9d 		0x75f5
#define HASH_r10d 		0x383ce
#define HASH_r11d 		0x383de
#define HASH_r12d 		0x383ee
#define HASH_r13d 		0x383fe
#define HASH_r14d 		0x3840e
#define HASH_r15d 		0x3841e
#endif

#define HASH_fp0			0x6d31
#define HASH_fp1			0x6d32
#define HASH_fp2			0x6d33
#define HASH_fp3			0x6d34
#define HASH_fp4			0x6d35
#define HASH_fp5			0x6d36
#define HASH_fp6			0x6d37
#define HASH_fp7			0x6d38

#define HASH_zero		0x0031

#define HASH_m8 			0x709
#define HASH_m16 		0x7047
#define HASH_m32 		0x7063
#define HASH_m64 		0x7095

#define HASH_f32			0x6963
#define HASH_f64			0x6995
#define HASH_f80			0x69b1

#define HASH_struc		0x0a6d4

#define HASH_proc 		0x3a8bd
#define HASH_return 		0x27219
#define HASH_exit 		0x2fe6e
#define HASH_asm 		0x689e
#define HASH_while 		0xcaf
#define HASH_lib 		0x72f3
#define HASH_if 			0x6f7
#define HASH_else		0x2f2ff
#define HASH_push		0x3ac02
#define HASH_pop			0x7761
#define HASH_syscall		0x2a3e1
#define HASH_sysret		0x3869
#define HASH_call		0x2c796
#define HASH_jmp			0x7141
#define HASH_ret			0x78c5
#define HASH_fdecstp		0x11573
#define HASH_fincstp		0x257e2
#define HASH_extern		0x4f00
#define HASH_ifdef		0x1299c
#define HASH_endif		0x17a73
#define HASH_ifndef		0x2614
#define HASH_define		0x2989d
#define HASH_undefine		0x1c0e7
#define HASH_in			0x6ff
#define HASH_out			0x76c5
#define HASH_as			0x684
#define HASH_COMPILER_OPTION 0x12fb0

#define HASH_UTF8		0x1d802
#define HASH_UTF16		0x2cbb6
#define HASH_PE			0x546
#define HASH_ELF			0x4a07
#define HASH_ELFO		0xd019
//#define HASH_FLAT		0xdfce
//#define HASH_0F		0x6247
#define HASH_ENABLESTACKFRAME 0x12a56
#define HASH_DISABLESTACKFRAME 0x1eec6

#define HASH_CARRY		0x2bcdc
#define HASH_NOCARRY		0x33859
#define HASH_OVERFLOW		0x2f0e2
#define HASH_NOOVERFLOW	0x3b079
#define HASH_PARITY		0x3ce63
#define HASH_NOPARITY		0x362f8
#define HASH_ZERO		0x219d9
#define HASH_NOTZERO		0x2a87c
#define HASH_SIGN		0x1ad28
#define HASH_NOTSIGN		0x23c2b

#define TYPE_M8			0x0001
#define TYPE_M16			0x0002
#define TYPE_M32			0x0003
#ifndef i386
#define TYPE_M64			0x0004
#endif

#define TYPE_F32			0x0008
#define TYPE_F64			0x0009
#define TYPE_F80			0x000a

#define TYPE_ARRAY		0x0010
#define TYPE_PROC		0x0020
#define TYPE_EPROC		0x0040
#define TYPE_KEYWORD		0x0080

#define TYPE_REG			0x0100
#define TYPE_REG_FPU		0x0200
#define TYPE_REG_SHORT	0x0400
#define TYPE_FLAG		0x0800

#define TYPE_LOCAL		0x1000
#define TYPE_GLOBAL		0x2000
#define TYPE_DEFINE		0x4000
#define TYPE_STRUC		0x8000
#define TYPE_VSTRUC		0x10000
#define TYPE_ELIB		0x20000

#define TYPE_RESERVED		0x40000000

// VSTRUC == assigned variable, STRUC == structure definition.
// ELIB == Name of external DLL mapped to a name!

unsigned int getChar(void);
unsigned int isAlpha(int s);
unsigned int isXDigit(int s);
unsigned int isDigit(int s);
void abort_b0(const char *s);
unsigned int isSpace(int s);
unsigned long ElfHash( const unsigned char *name );
void insert_token( const unsigned char *name, unsigned int token_type );
void insert_token_stack( unsigned int _token);
unsigned int atStackStart(void);
unsigned int atStackEnd(unsigned int i);
unsigned int TokenIsLabelType(unsigned int i);
unsigned int IsLabelAllocated(void);
unsigned int isHash(unsigned int i);
unsigned int outputString(unsigned int i);
unsigned int outputStringUTF8(unsigned int i);
unsigned int outputNumber(unsigned int i, int dec);
unsigned int outputNumberD(unsigned int i, int dec);
unsigned int SetState(void);
unsigned int TokenIs(unsigned int tok);
unsigned int callProc(unsigned int who, unsigned int return_reg, unsigned int i);
unsigned int outputDynamicString(unsigned int i);
void PrintHelp(void);
void PrintHeader(void);
void PrintLicense(void);
int dhtoi(const unsigned char *number);
unsigned int setDefine(unsigned int def_hash, unsigned int i);
unsigned int checkDefine(unsigned int def_hash, unsigned int comparison, unsigned int i);
unsigned int preparse_token_stack(void);
void scan_env(char *str);
unsigned int if_while_block(unsigned int i);
void ScanForDupStrucLabel(unsigned long dest_hash, unsigned long source_hash);
unsigned int BuildLabelInfo(unsigned int i);
void DisplayLabelInfo(void);
void Set_v_reg(void);
unsigned int v_size_is_p2(unsigned int _size);
void Calculate_label_address(unsigned int i);
void Calculate_NSLabel_address(unsigned int i);
unsigned int Global_Pointer(unsigned int i);
unsigned int process_int_operation(unsigned int i);
unsigned int process_fpu_operation(unsigned int i);
unsigned int process_struc_def(unsigned int i);
unsigned int TS_is_int(unsigned int i);
unsigned int process_struc(void);
unsigned int process_token_stack(void);
unsigned int nextToken(void);
int end_block_else(void);
int end_block(void);
int block(void);
void include_standard_output(void);
void include_public_extrns(void);
void include_public_extrns_pe(void);
int main(int argc, char *argv[]);

