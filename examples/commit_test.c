#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

int main()
{
	FILE *fp;
	unsigned long long int RunTime_file_IO = 0, RunTime_commit = 0;

	_struct_pp_ pp;
	_struct_commit_ cm, cm2;
	_struct_poly_ poly;

	commit_init(&cm);
	commit_init(&cm2);
	
	TimerOn();
	Read_pp("./Txt/pp.txt", &pp);
	Read_poly("./Txt/poly.txt", &poly);
	RunTime_file_IO += TimerOff();


	TimerOn();
	commit_new_precom(&cm, pp, poly);
	RunTime_commit = TimerOff();
	printf("Commit__OLD_ %12llu [us]\n", RunTime_commit);
	qfb_print(cm.C);
	printf("\r\n");
	TimerOn();
	commit_new(&cm2, pp, poly);
	RunTime_commit = TimerOff();
	qfb_print(cm2.C);
	printf("\r\n");

	TimerOn();
	Write_Commit("./Txt/commit.txt", &cm);
	RunTime_file_IO += TimerOff();

	printf("Commit_TIME_ %12llu [us]\n", RunTime_commit);
	printf("Commit_I/O__ %12llu [us]\n", RunTime_file_IO);

	fp = fopen("record/commit.txt", "a+");
	fprintf(fp, "%d %d %llu %llu\n", pp.security_level, poly.d, RunTime_file_IO, RunTime_commit);			
	fclose(fp);

	pp_clear(&pp);
	commit_clear(&cm);	

	return 0;
}
