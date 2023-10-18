#include "../hedder/codetimer.h"
#include "../hedder/dark_compiler.h"

//"./Txt/pp.txt"
int Read_pp(const char* path, _struct_pp_* pp)
{
	FILE *fp;
	int i = 0, flag = 1;
	char *buff;

	fp = fopen(path, "r");
	fscanf(fp, "%x", &(pp->security_level));
	buff = (char *)calloc(sizeof(char),(pp->security_level+2));  

	fscanf(fp, "%s", buff);
	fmpz_set_str(pp->G, buff, 16);

	fmpz_abs(pp->L, pp->G);
	fmpz_root(pp->L, pp->L, 4);

	fscanf(fp, "%s", buff);
	fmpz_set_str(pp->g->a, buff, 16);
	fscanf(fp, "%s", buff);
	fmpz_set_str(pp->g->b, buff, 16);
	fscanf(fp, "%s", buff);
	fmpz_set_str(pp->g->c, buff, 16);

	fscanf(fp, "%x", &i);
	fmpz_set_ui(pp->q, 0);
	fmpz_setbit(pp->q, i);

	fscanf(fp, "%s", buff);
	fmpz_set_str(pp->p, buff, 16);

	fclose(fp);
	return flag;
}

//./Txt/pp.txt
int Write_pp(const char* path, _struct_pp_* pp)
{
	FILE *fp;

	fp = fopen(path,"w");
	fprintf(fp,"%x\n", pp->security_level);
	fprintf(fp,"%s\n", fmpz_get_str(NULL, 16, pp->G));
	fprintf(fp,"%s %s %s\n", fmpz_get_str(NULL, 16, pp->g->a), fmpz_get_str(NULL, 16, pp->g->b), fmpz_get_str(NULL, 16, pp->g->c));
	fprintf(fp,"%x\n", (int)fmpz_bits(pp->q)-1);
	fprintf(fp,"%s\n", fmpz_get_str(NULL, 16, pp->p));
	fclose(fp);

	return 1;
}


//"./Txt/commit.txt"
int Read_Commit(const char* path, _struct_commit_* cm)
{
	FILE *fp;
	int cnt = 0, flag = 1;
	char *buff;

	fp = fopen(path, "r");
    fseek(fp, 0, SEEK_END); 
    cnt = ftell(fp);      
	fseek(fp, 0, SEEK_SET ); 

	qfb_init(cm->C);
	buff = (char *)calloc(cnt + 1, sizeof(char));    

	qfb_init(cm->C);
	fscanf(fp, "%s", buff);
	fmpz_set_str(cm->C->a, buff, 16);
	fscanf(fp, "%s", buff);
	fmpz_set_str(cm->C->b, buff, 16);
	fscanf(fp, "%s", buff);
	fmpz_set_str(cm->C->c, buff, 16);

	fclose(fp);
	free(buff);
	return (flag > 0 ? 1 : 0);
}

//"./Txt/commit.txt"
int Write_Commit(const char* path, const _struct_commit_* cm)
{
	FILE *fp;
	int i = 0, flag = 1;

	fp = fopen(path, "w");
	flag *= fprintf(fp,"%s %s %s\n", 
		fmpz_get_str(NULL, 16, (cm->C)->a),
		fmpz_get_str(NULL, 16, (cm->C)->b), 
		fmpz_get_str(NULL, 16, (cm->C)->c));

	fclose(fp);
	return (flag != 0 ? 1 : 0);
}

//"./Txt/proof.txt", "a+"
int Write_proof(const char* path, _struct_proof_ pf, const char* mode)
{
	FILE *fp;
	int flag = 1;

	fp = fopen(path, mode);
	{
		flag *= fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pf.alpha));
		flag *= fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pf.yL));
		flag *= fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pf.yR));
		flag *= fprintf(fp,"%s %s %s\n", 
			fmpz_get_str(NULL, 16, (pf.CL.C)->a),
			fmpz_get_str(NULL, 16, (pf.CL.C)->b), 
			fmpz_get_str(NULL, 16, (pf.CL.C)->c));
		flag *= fprintf(fp,"%s %s %s\n", 
			fmpz_get_str(NULL, 16, (pf.CR.C)->a),
			fmpz_get_str(NULL, 16, (pf.CR.C)->b), 
			fmpz_get_str(NULL, 16, (pf.CR.C)->c));

		flag *= fprintf(fp,"%s %s %s\n", 
			fmpz_get_str(NULL, 16, (pf.POE_proof)->a),
			fmpz_get_str(NULL, 16, (pf.POE_proof)->b), 
			fmpz_get_str(NULL, 16, (pf.POE_proof)->c));
	}

	fclose(fp);
	return (flag != 0 ? 1 : 0);	
}

//"./Txt/poly.txt"
// why make index i array from 1 to d+1
int make_poly(const char* path, unsigned int d)
{
	fmpz_t fmpz_tmp;
	flint_rand_t state;
	FILE *fp;
	unsigned int i = 0, flag = 1;

	fmpz_init(fmpz_tmp);
	fp = fopen(path, "w");

	flag *= fprintf(fp, "%x\n", d);

	flint_randinit(state);
	for(int i =0; i<d; i++){
		// fmpz_set_ui(fmpz_tmp, 1+i);
		fmpz_randbits(fmpz_tmp, state, 32);  // random 
		fmpz_abs(fmpz_tmp, fmpz_tmp);
		flag *= fprintf(fp, "%s ", fmpz_get_str(NULL, 16, fmpz_tmp));
	}

	fclose(fp);
	fmpz_clear(fmpz_tmp);

	return flag;
}

//"./Txt/poly.txt"
int Read_poly(const char* path, _struct_poly_* poly)
{
	FILE *fp;
	int i = 0, flag = 1;
	char *buff;
	fp = fopen(path, "r");
	fscanf(fp, "%x", &poly->d );

	buff = (char *)calloc(sizeof(char),64);    

	poly->Fx = (fmpz_t*)calloc(sizeof(fmpz_t), poly->d + 1 );
	for(i=1; i<= poly->d; i++){
		fscanf(fp, "%s", buff);
		fmpz_init(poly->Fx[poly->d-i]);
		fmpz_set_str(poly->Fx[poly->d-i], buff, 16);
		if(feof(fp) != 0)
			break;
	}

	free(buff);
	return flag;
}

int poly_clear(_struct_poly_* poly)
{
	for(int i = 0; i < poly->d; i++)
		fmpz_clear(poly->Fx[i]);

	poly->d = 0;
	return 1;
}

int getfilesize(char* path)
{
    int size;
    FILE *fp = fopen(path, "r");    // hello.txt 파일을 읽기 모드(r)로 열기.
                                    // 파일 포인터를 반환
    fseek(fp, 0, SEEK_END);    // 파일 포인터를 파일의 끝으로 이동시킴
    size = ftell(fp);          // 파일 포인터의 현재 위치를 얻음
    fclose(fp);

    return size;
}

// 1000
// ->002003004001
//              1
//           4000
//        3000000
//     2000000000