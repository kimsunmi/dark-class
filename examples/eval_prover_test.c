#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main()
{
    unsigned long long int RunTime_eval = 0, RunTime_file_IO = 0;
	int d_;
    FILE *fp;
  	_struct_pp_ pp;
	_struct_commit_ cm, cm2;
	_struct_poly_ poly;

	fp = fopen("./Txt/proof.txt", "w");
	fprintf(fp, "\r");
	fclose(fp);

	////////////////////////////////////////////////////////////////////////////
    pp_init(&pp);
    commit_init(&cm);

	TimerOn();
	Read_pp("./Txt/pp.txt", &pp);
	Read_poly("./Txt/poly.txt", &poly);
	RunTime_file_IO = TimerOff();

	// // 모든 테이블 precom 후 commit
	// printf("------compute all table----------\n");
	// TimerOn();
	// commit_new_precom(&cm, pp, poly);
	// RunTime_eval = TimerOff();

	// printf("Cm_w/_Alltab %12llu [us]\n", RunTime_eval);
	// printf("---------------------------------\n");

	// // cm에 필요한 g만 precom 후 commit
	TimerOn();
	commit_new(&cm, pp, poly);
	RunTime_eval = TimerOff();
	printf("Cm_w/_TIME_OnlyGT %12llu [us]\n", RunTime_eval);

	// precom 없이 commit 계산
	TimerOn();
	commit_new_old(&cm2, pp, poly);
	RunTime_eval = TimerOff();
	printf("Commit_w/o_Tab_ %12llu [us]\n", RunTime_eval);

	TimerOn();
	Write_Commit("./Txt/commit.txt", &cm);
	RunTime_file_IO += TimerOff();

	printf("Commit_I/O__ %12llu [us]\n", RunTime_file_IO);

	fp = fopen("record/commit.txt", "a+");
	fprintf(fp, "%d %d %llu %llu\n", pp.security_level, poly.d, RunTime_file_IO, RunTime_eval);			
	fclose(fp);

	pp_clear(&pp);
	commit_clear(&cm);	
	poly_clear(&poly);
	////////////////////////////////////////////////////////////////////////////	

    pp_init(&pp);
    commit_init(&cm);
	
	TimerOn();
	Read_pp("./Txt/pp.txt", &pp);
	Read_Commit("./Txt/commit.txt", &cm);
	Read_poly("./Txt/poly.txt", &poly);
	RunTime_file_IO = TimerOff();
	d_ = poly.d;

	TimerOn();
	Eval_prover(&pp, &cm, &poly, 0);
	RunTime_eval = TimerOff();
	
	printf("EVAL_PROVER_ %12llu [us]\n", RunTime_eval);
	printf("EVAL___I/O__ %12llu [us]\n", RunTime_file_IO);
	// fmpz_print(pp.G);
	fp = fopen("record/eval_prove.txt", "a+");
	fprintf(fp, "%d %d %llu %llu\n", pp.security_level, d_, RunTime_file_IO, RunTime_eval);			
	fclose(fp);

	pp_clear(&pp);
	commit_clear(&cm);	
	poly_clear(&poly);

	return 0;
}
