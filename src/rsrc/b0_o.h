// b0_o.h

// include for linking the B0 Compiler to other C applications.

#define B0_SOURCE_ELF 	0x2
#define B0_SOURCE_PE 	0x3
#define B0_SOURCE_ELFO 	0x4
#define B0_SOURCE_DLL	0x5

#define B0_UTF16_STR	0x0
#define B0_UTF8_STR		0x1

typedef struct {
	char *ERROR_STRING;
	char *ERROR_FILENAME;
	unsigned long LINE_NUMBER;
} Error_Struct;

unsigned int b0_Init(void);  						// Used to Reset the compiler internals to default
unsigned int b0_SetProgressCallback(void *proc);	// Set location of callback function to get timer tick
unsigned int b0_SetSourceFilename(char *str); 		// Set's the source filename
unsigned int b0_SetOutputFilename(char *str);		// Set the output filename;
unsigned int b0_SetSourceType(unsigned int Source); // Set the source type
unsigned int b0_SetUTF8String(unsigned int StrType); // Set the String Type;
unsigned int b0_SetIncludeDir(char *str);			// Add an include search dir
unsigned int b0_Build(void);						// Attempt to build
unsigned int b0_GetBuildTime(void);					// Get our build time
Error_Struct* b0_GetError(void);					// Get the error result if b0_build returns '-1'

