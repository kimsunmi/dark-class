#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main()
{
	FILE *fp;
	unsigned long long int RunTime_file_IO = 0, RunTime_commit = 0;

	_struct_pp_ pp;
	_struct_commit_ cm, cm2, cm3;
	_struct_poly_ poly;

	commit_init(&cm);
	commit_init(&cm2);
	commit_init(&cm3);
	
	TimerOn();
	Read_pp("./Txt/pp.txt", &pp);
	Read_poly("./Txt/poly.txt", &poly);
	RunTime_file_IO += TimerOff();


	TimerOn();
	// 모든 precom을 포함한 commit
	commit_new_precom(&cm, pp, poly);
	RunTime_commit = TimerOff();
	printf("Cm_w/_time_AllT %12llu [us]\n", RunTime_commit);

	// TimerOn();
	// // g만 com하고 이후 commit 진행
	// commit_new(&cm2, pp, poly);
	// RunTime_commit = TimerOff();
	// printf("Cm_w/_TIME_OnlyGT %12llu [us]\n", RunTime_commit);

	TimerOn();
	commit_new_old(&cm3, pp, poly);
	RunTime_commit = TimerOff();
	printf("Commit_w/o_TIME_ %12llu [us]\n", RunTime_commit);

	TimerOn();
	Write_Commit("./Txt/commit.txt", &cm);
	RunTime_file_IO += TimerOff();

	printf("Commit_I/O__ %12llu [us]\n", RunTime_file_IO);

	fp = fopen("record/commit.txt", "a+");
	fprintf(fp, "%d %d %llu %llu\n", pp.security_level, poly.d, RunTime_file_IO, RunTime_commit);			
	fclose(fp);

	pp_clear(&pp);
	commit_clear(&cm);	

	return 0;
}
