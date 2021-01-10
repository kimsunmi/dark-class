#include "../hedder/codetimer.h"
static struct timeval before, after;  

void TimerOn(){
	gettimeofday(&before,NULL);
}

unsigned long long int TimerOff()
{
    gettimeofday(&after,NULL);
	return (1000000*(after.tv_sec-before.tv_sec) + (after.tv_usec-before.tv_usec)/1);
}


void TimerOn2(struct timeval* before)
{
	gettimeofday(before,NULL);
}

unsigned long long int TimerOff2(struct timeval* before, struct timeval* after)
{
    gettimeofday(after,NULL);
	return (1000000*(after->tv_sec-before->tv_sec) + (after->tv_usec-before->tv_usec)/1);
}