#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main()
{
	unsigned long long int RunTime_eval = 0, RunTime_file_IO = 0;

	FILE *fp;
  	_struct_pp_ pp;
	_struct_commit_ cm;
	_struct_poly_ poly;

	pp_init(&pp);
    commit_init(&cm);

	TimerOn();
	Read_pp("./Txt/pp.txt", &pp);
	Read_Commit("./Txt/commit.txt", &cm);
	Read_poly("./Txt/poly.txt", &poly);
	RunTime_file_IO = TimerOff();
	int d_ = poly.d;
	int flag;
	
	TimerOn();
	flag = Eval_verify(&pp, &cm, &poly);
	RunTime_eval = TimerOff();

	printf("EVAL_VERIFY_ %12llu [us]\n", RunTime_eval);
	printf("VERIFY_I/O__ %12llu [us]\n", RunTime_file_IO);

	fp = fopen("record/eval_verify.txt", "a+");
	fprintf(fp, "%d %d %llu %llu [%d]\n", pp.security_level, d_, RunTime_file_IO, RunTime_eval, flag);			
	fclose(fp);

	fp = fopen("record/size.txt", "a+");
	fprintf(fp, "%d %d %d %d %d [%d]\n", pp.security_level, d_, getfilesize("Txt/pp.txt"), getfilesize("Txt/commit.txt"), getfilesize("Txt/proof.txt"), flag);		
	fclose(fp);	

	return 0;
}
