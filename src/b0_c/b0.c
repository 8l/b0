// B0
// 
// Copyright (C) 2000-2007, Darran Kartaschew.
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

// Build b0.o first, then:
// $ gcc -o b0_c ../../b0.o b0_c.c
//

#define _POSIX_ 1

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "../rsrc/b0_o.h"

int progress = 0;
int interim_count = 0;
char ch = ' ';
long long count = 0;

void callback(){
	count++;
	interim_count++;
	if(interim_count > 10000){
		switch(progress){
			case 0 : ch = '|'; progress++; break;
			case 1 : ch = '/'; progress++; break;
			case 2 : ch = '-'; progress++; break;
			case 3 : ch = '\\'; progress = 0; break;
		}
		printf("%c%c", 0x8, ch);
		fflush(stdout);
		interim_count = 0;
	}
};

int main(int argc, char *argv[]){

	int i = 0;
	int j = 0;
	int have_file = 0;
	char *path;
	char *b0_env;
	char *filename;
	int build_suceed = 0;
	
	Error_Struct *errors;
	
	for (j=0;j<500;j++){
	
	b0_Init();
	count = 0;
	if(argc > 1){
		for(i=0;i<argc;i++){
			if(!strcmp(argv[i], "-UTF8"))
				{ b0_SetUTF8String(B0_UTF8_STR); }
				
			if(!strcmp(argv[i], "-UTF16"))
				{ b0_SetUTF8String(B0_UTF16_STR); }
				
			if((argv[i][0] == '-') && (argv[i][1] == 'i')){
				path = &argv[i][2]; // Set pointer to the CLI environment
				b0_SetIncludeDir(path);
			}
			
			if((argv[i][0] == '-') && (argv[i][1] == 'o')){
				filename = &argv[i][2]; // Set pointer to the output file
				//printf("Output filename = %s\n", filename);
				b0_SetOutputFilename(filename);
			}

			
			if((argv[i][0] == '-') && (argv[i][1] == 'f')){
				//Set the type of Source Output = SOURCE_TYPE
				if(!strcmp(argv[i], "-felf")){
					b0_SetSourceType(B0_SOURCE_ELF);
				} else {
					if(!strcmp(argv[i], "-fpe")){
						b0_SetSourceType(B0_SOURCE_PE);
					} else {
						if(!strcmp(argv[i], "-felfo")){
							b0_SetSourceType(B0_SOURCE_ELFO);
						} else {
							if(!strcmp(argv[i], "-fdll")){
								b0_SetSourceType(B0_SOURCE_DLL);
							} else {
								printf("Error: Unknown Output Format?\n");
								exit(1);
							}
						}
					}
				}
			}
			
			if((argv[i][0] != '-') && (i != 0) && (have_file == 0)){
				// Else let's assume for now that it's our filename?
				b0_SetSourceFilename(argv[i]);
				//printf("Source filename = %s\n", argv[i]);
				have_file = 1;
			}
		}
	}
	
	if(have_file){
	
		b0_env = getenv("B0_INCLUDE");
	
		if(b0_env) b0_SetIncludeDir(b0_env);
		
		b0_SetProgressCallback(&callback);
	
		printf("Processing : |");
	
		build_suceed = b0_build();

		i = b0_GetBuildTime();
		printf("\nProcessing time: %dsec Lines: %ld\n", i, count);

		if(build_suceed == -1){
			
			errors = b0_GetError();
			printf("Error: %s\nFilename: %s Line: %d.\n", errors->ERROR_STRING, errors->ERROR_FILENAME, errors->LINE_NUMBER);
			
			exit(1);
		}
	} else {
		printf("Please define parameters\n");
		exit(1);
	}
	have_file = 0;
	}

	return(0);
}
