#ifndef _CODE_TIMER_H
	#include <sys/time.h>
	#include <stdio.h>
	
	void TimerOn();
	unsigned long long int TimerOff();

	void TimerOn2(struct timeval* before);
	unsigned long long int TimerOff2(struct timeval* before, struct timeval* after);

	#define _CODE_TIMER_H
#endif
