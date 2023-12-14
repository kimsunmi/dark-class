#ifndef _UTIL_H
    #include "../hedder/dark_compiler.h"
	
    int Read_pp(const char* path, _struct_pp_* pp);
	int Write_pp(const char* path, _struct_pp_* pp); 
    
    int Read_Commit(const char* path, _struct_commit_* cm);
    int Write_Commit(const char* path, const _struct_commit_* cm);
	
    int make_poly(const char* path, unsigned int d, unsigned int mu);
    int Read_poly(const char* path, _struct_poly_* poly);
    int poly_clear(_struct_poly_* poly);

	int Write_proof(const char* path, _struct_proof_ pf, const char* mode);
	int Read_proof(_struct_proof_ *pf);
	int getfilesize(char* path);

	#define _UTIL_H
#endif
