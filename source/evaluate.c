#include "../hedder/codetimer.h"
#include "../hedder/dark_compiler.h"
#include "../hedder/poe.h"
#include "../hedder/util.h"

int get_alpha_SHA256( fmpz_t output, fmpz_t p, fmpz_t yL, fmpz_t yR, qfb_t CL, qfb_t CR, int lambda )
{
	fmpz_t tmp;
	fmpz_init(tmp);
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};

	char* str_yL = fmpz_get_str(NULL, 16, yL);
	char* str_yR = fmpz_get_str(NULL, 16, yR);
	char *str_CL[3] = {fmpz_get_str(NULL, 16, CL->a), fmpz_get_str(NULL, 16, CL->b), fmpz_get_str(NULL, 16, CL->c)};
	char *str_CR[3] = {fmpz_get_str(NULL, 16, CR->a), fmpz_get_str(NULL, 16, CR->b), fmpz_get_str(NULL, 16, CR->c)};

	char *str_concat = calloc( strlen(str_yL) + strlen(str_yR)
								+ strlen(str_CL[0]) + strlen(str_CL[1]) + strlen(str_CL[2]) 
								+ strlen(str_CR[0]) + strlen(str_CR[1]) + strlen(str_CR[2]) + 1, sizeof(char));
	int concat_len = 0;

	memcpy(str_concat + concat_len, str_yL, sizeof(char) * (strlen(str_yL)));	concat_len += strlen(str_yL);
	memcpy(str_concat + concat_len, str_yR, sizeof(char) * (strlen(str_yR)));	concat_len += strlen(str_yR);	
	for(int i = 0; i<3; i++){
		memcpy(str_concat + concat_len, str_CL[i], sizeof(char) * (strlen(str_CL[i])));		concat_len += strlen(str_CL[i]);
		memcpy(str_concat + concat_len, str_CR[i], sizeof(char) * (strlen(str_CR[i])));		concat_len += strlen(str_CR[i]);
	}

	SHA256(str_concat, concat_len, digest);  
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	
	fmpz_set_str(output, mdString, 16);

	fmpz_set_d_2exp(tmp, 1, lambda);
	fmpz_sub_ui(tmp, tmp, 1);
	fmpz_mod(output, output, tmp);
	// fmpz_mod(output, output, p);
	fmpz_tdiv_q_2exp(output,output,2);

	// fmpz_mod(output, output, p);
	// fmpz_tdiv_q_2exp(output,output,1);

	free(str_yL);
	free(str_yR);
	for(int i = 0; i<3; i++){
		free(str_CL[i]);
		free(str_CR[i]);
	}
	free(str_concat);

    return 1;
}


int EvalBounded_origin_prover(_struct_pp_ *pp, qfb_t* C, const fmpz_t z, fmpz_t* y, fmpz_t* b, _struct_poly_* poly,int testbit,  _struct_prover_timer_* p_runtime) 
{
	static struct timeval before1[10]={0}, after1[10] = {0};
	static unsigned long long int RunTime1[10] = {0};
	static int isfirst = 0,firstd = 0;
	//static BN_CTX* ctx;
	static _struct_proof_ pf;
	static fmpz_t z_tmp;
	static fmpz_t y_tmp;
	static _struct_poly_ fL, fR;
	static qfb_t poe_w;
	static qfb_t poe_u;
	static qfb_t poe_x;

	//proof size
	static fmpz_t pf_yl;
	static fmpz_t pf_yr;
	static fmpz_t pf_cl_a;
	static fmpz_t pf_cl_b;
	static fmpz_t pf_cl_c;
	static fmpz_t pf_cr_a;
	static fmpz_t pf_cr_b;
	static fmpz_t pf_cr_c;
	static fmpz_t pf_q_a;	
	static fmpz_t pf_q_b;	
	static fmpz_t pf_q_c;	

	TimerOn();

	if(isfirst == 0)
	{
		//printf("d : %d\n", poly->d);
		//TimerOn();
		pf_init(&pf);
		fmpz_init(y_tmp);
		fmpz_init(z_tmp);
		qfb_init(poe_w);
		qfb_init(poe_u);
		qfb_init(poe_x);

		fmpz_init(pf_yr);
		fmpz_init(pf_yl);
		fmpz_init(pf_cr_a);
		fmpz_init(pf_cr_b);
		fmpz_init(pf_cr_c);
		fmpz_init(pf_cl_a);
		fmpz_init(pf_cl_b);
		fmpz_init(pf_cl_c);
		fmpz_init(pf_q_a);
		fmpz_init(pf_q_b);
		fmpz_init(pf_q_c);

		firstd = (poly->d);

		fL.Fx = (fmpz_t*)calloc((poly->d), sizeof(fmpz_t));
		fR.Fx = (fmpz_t*)calloc((poly->d), sizeof(fmpz_t));
		
		isfirst = 1;
		//RunTime_eval += TimerOff();
	}
	p_runtime->prover_total += TimerOff();

	if(poly->d == 1)
	{		
		//printf("d is 1... record f\n");
		//TimerOn();
		FILE *fp2 = fopen("record_size.txt", "a+");
		fprintf(fp2,"-------proof Size(final round)----------\n");
		fprintf(fp2,"yL: %d \n", (int)fmpz_bits(pf_yl));
		fprintf(fp2,"yR: %d \n", (int)fmpz_bits(pf_yr));
		fprintf(fp2,"CL: %d \n", (int)fmpz_bits(pf_cl_a)+(int)fmpz_bits(pf_cl_b)+(int)fmpz_bits(pf_cl_c));
		fprintf(fp2,"CR: %d \n", (int)fmpz_bits(pf_cr_a)+(int)fmpz_bits(pf_cr_b)+(int)fmpz_bits(pf_cr_c));
		fprintf(fp2,"Q: %d \n", (int)fmpz_bits(pf_q_a)+(int)fmpz_bits(pf_q_b)+(int)fmpz_bits(pf_q_c));
		fprintf(fp2,"f_hat: %d \n",(int) fmpz_bits(poly->Fx[-1]));
		fprintf(fp2,"mu: %d \n",poly->mu);
		fprintf(fp2,"proof size n*(|yL|+|yR|+|CL|+|CR|+|Q|+f_hat[-1]): %d \n", poly->mu*((int) fmpz_bits(pf_yl)+(int)fmpz_bits(pf_yr)+(int)fmpz_bits(pf_cl_a)+(int)fmpz_bits(pf_cl_b)+(int)fmpz_bits(pf_cl_c)+(int)fmpz_bits(pf_cr_a)+(int)fmpz_bits(pf_cr_b)+(int)fmpz_bits(pf_cr_c)+(int)fmpz_bits(pf_q_a)+(int)fmpz_bits(pf_q_b)+(int)fmpz_bits(pf_q_c))+(int) fmpz_bits(poly->Fx[-1]));
		fprintf(fp2,"proof size(comm opt) n*(|yR|+|CR|+|Q|)+f_hat[-1]: %d \n", poly->mu*((int)fmpz_bits(pf_yr)+(int)fmpz_bits(pf_cr_a)+(int)fmpz_bits(pf_cr_b)+(int)fmpz_bits(pf_cr_c)+(int)fmpz_bits(pf_q_a)+(int)fmpz_bits(pf_q_b)+(int)fmpz_bits(pf_q_c))+(int) fmpz_bits(poly->Fx[-1]));
		fprintf(fp2,"-------------------------------------\n");
		fclose(fp2);

		FILE *fp = fopen("./Txt/proof.txt", "a+");
		fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, poly->Fx[0]));
		fseek(fp, 0, SEEK_SET); 
		fclose(fp);
		//RunTime_file_IO += TimerOff();
		free(fL.Fx);
		free(fR.Fx);

		isfirst = 0;
		poly->d = firstd;

		pf_clear(&pf);
		fmpz_clear(z_tmp);
		fmpz_clear(y_tmp);
		qfb_clear(poe_w);
		qfb_clear(poe_u);
		qfb_clear(poe_x);
	}	
	else if( ((poly->d)%2) == 1 )
	{
		//printf("d+1 is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		TimerOn();
		//TimerOn2(&before[0]);

		qfb_pow_with_root(*C, *C, pp->G, pp->q, pp->L);

		fmpz_mul(*y, *y, z);
		fmpz_mod(*y, *y, pp->p);	// y=y*z mod p
		fmpz_set_ui(y_tmp, poly->d);
		fmpz_mul(*b, *b, y_tmp);	// b =  bd
		
		poly->d = poly->d + 1;				//d = d + 1		
		fmpz_init(poly->Fx[poly->d]);
	
		for(int i = poly->d-1; i >= 0; i--){ // f'(X) = Xf(X);
			fmpz_set(poly->Fx[i+1], poly->Fx[i]);
		}
		fmpz_zero(poly->Fx[0]);	
		//RunTime[0] += TimerOff2(&before[0], &after[0]);	// 14

		//RunTime_eval += TimerOff();
		p_runtime->prover_total += TimerOff();

		EvalBounded_origin_prover(pp, C, z, y, b, poly, testbit, p_runtime);
	}
	else
	{
		int i;
		int d_ = ((poly->d)/2); //*d = ((*d+1)>>1)-1;		// P,V compute
		//printf("d+1 is even [d : %d -> d' : %d]\n", poly->d, d_);
		TimerOn();

		//printf("P computes fL\n");
		TimerOn2(&before1[1]);
		for(i = 0; i < d_; i++){	//fL.Fx[i] = poly->Fx[i];
			fmpz_init(fL.Fx[i]);// = BN_new();
			fmpz_set(fL.Fx[i], poly->Fx[i]);
		}
		fL.d = d_;

		//printf("P computes fR\n");
		for(i = 0; i < d_; i++){	//fR.Fx[i] = poly->Fx[d_ + i + 1];
			fmpz_init(fR.Fx[i]);
			fmpz_set(fR.Fx[i] , poly->Fx[d_ + i]);
		}
		fR.d = d_;
		RunTime1[1] += TimerOff2(&before1[1], &after1[1]);	// 14
		
		//printf("P computes yL\n");	
		//TimerOn2(&before[2]);	
		TimerOn2(&before1[2]);	
		fmpz_one(z_tmp);
		fmpz_zero(y_tmp);
		fmpz_zero(pf.yL);
		i=0;
		do{
			fmpz_mul(y_tmp, fL.Fx[i], z_tmp);
			fmpz_mod(y_tmp, y_tmp, pp->p);

			fmpz_add(pf.yL, pf.yL, y_tmp);
			fmpz_mod(pf.yL, pf.yL, pp->p);

			fmpz_mul(z_tmp, z_tmp, z);
			fmpz_mod(z_tmp, z_tmp, pp->p);	
			i++;
		}while(i< fL.d);
		//printf("yL : "); fmpz_print(pf.yL); //printf("\n");

		//printf("P computes yR\n");	
		fmpz_one(z_tmp);
		fmpz_zero(y_tmp);
		fmpz_zero(pf.yR);
		i=0;
		do{
			fmpz_mul(y_tmp, fR.Fx[i], z_tmp);
			fmpz_mod(y_tmp, y_tmp, pp->p);

			fmpz_add(pf.yR, pf.yR, y_tmp);
			fmpz_mod(pf.yR, pf.yR, pp->p);

			fmpz_mul(z_tmp, z_tmp, z);
			fmpz_mod(z_tmp, z_tmp, pp->p);	
			i++;
		}while(i< fR.d);
		//printf("yR : "); fmpz_print(pf.yR); //printf("\n");
		//RunTime[2] += TimerOff2(&before[2], &after[2]);	// 14
		RunTime1[2] += TimerOff2(&before1[2], &after1[2]);	// 14
		p_runtime->prover_total += TimerOff();


		//printf("P computes CL\n");
		//TimerOn2(&before[3]);
		TimerOn2(&before1[3]);
		TimerOn();
		commit_new(&pf.CL, *pp, fL);
		int prover_cl_time =  TimerOff();
		p_runtime->prover_total += prover_cl_time;
		p_runtime->prover_CL += prover_cl_time;
		//printf("P computes CR\n");
		
		TimerOn();
		commit_new(&pf.CR, *pp, fR);
		//RunTime[3] += TimerOff2(&before[3], &after[3]);	// 15
		int prover_cr_time =  TimerOff();
		p_runtime->prover_total += prover_cr_time;
		p_runtime->prover_CR += prover_cr_time;
		//printf("P computes alpha(hash)\n");
		//TimerOn2(&before[4]);
		TimerOn();
		TimerOn2(&before1[4]);
		get_alpha_SHA256(pf.alpha, pp->p, pf.yL, pf.yR, pf.CL.C, pf.CR.C, pp->security_level);
		//fmpz_set_ui(pf.alpha,1);
		//fmpz_set_ui(pf.alpha,19);			
		//RunTime[4] += TimerOff2(&before[4], &after[4]);	// 15
		RunTime1[4] += TimerOff2(&before1[4], &after1[4]);	// 15
		p_runtime->prover_total+= TimerOff();

		//POE(CR, C/CL, q^(d'+1)) run	
		//TimerOn2(&before[5]);
		TimerOn();
		TimerOn2(&before1[5]);
		qfb_set(poe_u, pf.CR.C);
		qfb_inverse(poe_w, pf.CL.C);
		qfb_nucomp(poe_w, poe_w, *C, pp->G, pp->L);
		qfb_reduce(poe_w, poe_w, pp->G);
		RunTime1[5] += TimerOff2(&before1[5], &after1[5]);	// 15

		//BN_copy(poe_u, CR.C);
		//BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		//BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);

		TimerOn2(&before1[6]);
		//eval_pk(pf.POE_proof, poe_w, poe_u, pp, d_+1);
		eval_pk_test(pf.POE_proof, poe_w, poe_u, &fR, pp, d_);

		RunTime1[6] += TimerOff2(&before1[6], &after1[6]);	// 15
		int poe_time = TimerOff();
		p_runtime->prover_total += poe_time;
		p_runtime->prover_POE += poe_time;

		//RunTime[5] += TimerOff2(&before[5], &after[5]);	// 15
		/***********************************		 POE		***********************************/
		//printf("y' <- (a*yL + yR) mod p \n");
		//TimerOn2(&before[6]);
		TimerOn();
		TimerOn2(&before1[7]);
		fmpz_mul(y_tmp, pf.alpha, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		
		fmpz_add(*y, y_tmp, pf.yR);
		fmpz_mod(*y, *y, pp->p);

		//BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		//BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		qfb_pow_with_root(*C, pf.CL.C, pp->G, pf.alpha, pp->L);
		qfb_nucomp(*C, *C, pf.CR.C, pp->G, pp->L);
		qfb_reduce(*C, *C, pp->G);

		//printf("b' <- b((p+1)/2)\n");
		fmpz_mul_2exp(*b, *b, pp->security_level);

		// fmpz_set(y_tmp,pp->p);
		// fmpz_add_ui(y_tmp,y_tmp,1);
		// fmpz_tdiv_q_2exp(y_tmp,y_tmp,1);		//BN_rshift1(y_tmp,y_tmp);
		// fmpz_mul(*b, *b, y_tmp);
		//RunTime[6] += TimerOff2(&before[6], &after[6]);	// 15
		
		//printf("f' <- a*fL + fR\n");
		RunTime1[7] += TimerOff2(&before1[7], &after1[7]);	// 15
		TimerOn2(&before1[8]);
		//TimerOn2(&before[7]);
		i=0;
		do{
			fmpz_mul(y_tmp, pf.alpha, fL.Fx[i]);
			fmpz_mod(y_tmp, y_tmp, *b);

			fmpz_add(poly->Fx[i], y_tmp, fR.Fx[i]);
			fmpz_mod(poly->Fx[i], poly->Fx[i], *b);

			//poly->Fx[i]  = alpha*fL.Fx[i] + fR.Fx[i];			
			fmpz_clear(fR.Fx[i]);
			fmpz_clear(fL.Fx[i]);
			i++;
		}while(i < d_);
		//RunTime[7] += TimerOff2(&before[7], &after[7]);	// 15

		do{
			fmpz_clear(poly->Fx[i]);
			i++;
		}while(i < poly->d);
		poly->d = d_;
		RunTime1[8] += TimerOff2(&before1[8], &after1[8]);	// 15
		//RunTime_eval += TimerOff();
		//printf("P run EvalBounded_prover2(pp, C', z, y', d', b', f'(X))\n\n");		
		fmpz_add(pf_yl,pf_yl,pf.yL);
		fmpz_add(pf_yr,pf_yr,pf.yR);
		fmpz_add(pf_cl_a,pf_cl_a,pf.CL.C->a);
		fmpz_add(pf_cl_b,pf_cl_b,pf.CL.C->b);
		fmpz_add(pf_cl_c,pf_cl_c,pf.CL.C->c);
		fmpz_add(pf_cr_a,pf_cr_b,pf.CR.C->a);
		fmpz_add(pf_cr_b,pf_cr_b,pf.CR.C->b);
		fmpz_add(pf_cr_c,pf_cr_c,pf.CR.C->c);
		fmpz_add(pf_q_a,pf_q_a,pf.POE_proof->a);
		fmpz_add(pf_q_b,pf_q_b,pf.POE_proof->b);
		fmpz_add(pf_q_c,pf_q_c,pf.POE_proof->c);
		p_runtime->prover_total += TimerOff();

		//TimerOn();
		Write_proof("./Txt/proof.txt", pf, "a+");	
		//RunTime_file_IO += TimerOff();

		EvalBounded_origin_prover(pp, C, z, y, b, poly, testbit, p_runtime);
	}

	return 1;
}


int Eval_prover(_struct_pp_* pp, _struct_commit_* cm, _struct_poly_* poly, int testbit) // ( pp, z, y, d, f~(X) )
{
	int i;
	fmpz_t zero, p, z, z_tmp, y;
	qfb_t C;

	_struct_prover_timer_ prover_runtime;
	prover_runtime.prover_CL = 0;
	prover_runtime.prover_CR = 0;
	prover_runtime.prover_POE = 0;
	prover_runtime.prover_total = 0;

	_struct_prover_timer_* p_runtime = &prover_runtime;

	qfb_init(C);
	qfb_set(C, cm->C);

	fmpz_init_set_ui(zero,0);
	fmpz_init_set_ui(y,0);
	fmpz_init(p);
	fmpz_init_set_ui(z,100);
	fmpz_init_set_ui(z_tmp,1);

	fmpz_sub_ui(p, pp->p, 1);
	// fmpz_tdiv_q_2exp(p,p,1); 

	//i=0;
	//do{
	//	BN_mod_inverse(poly->Fx[i], poly->Fx[i], pp->p, ctx);
	//	i++;
	//}while(i<= poly->d);

	i = 0;
	do{
		fmpz_mul(zero, poly->Fx[i], z_tmp);
		fmpz_mod(zero, zero, pp->p);
		fmpz_add(y, y, zero);
		fmpz_mod(y, y, pp->p);
		fmpz_mul(z_tmp, z_tmp, z);
		fmpz_mod(z_tmp, z_tmp, pp->p);
		
		//BN_mod_mul(zero, poly->Fx[i], z_tmp, pp->p, ctx);
		//BN_mod_add(y, y, zero, pp->p, ctx);
		//BN_mod_mul(z_tmp,z_tmp, z, pp->p, ctx);
		i++;
	}while(i<= poly->d);

	//printf("EvalBounded_prover2 Start\n");
	EvalBounded_origin_prover(pp, &C, z, &y, &p, poly, testbit, p_runtime);

	printf("EVAL_PROVER_Total %12llu [us]\r\n", prover_runtime.prover_total);
	printf("EVAL_PROVER_CL %12llu [us]\r\n", prover_runtime.prover_CL);
	printf("EVAL_PROVER_CR %12llu [us]\r\n", prover_runtime.prover_CR);
	printf("EVAL_PROVER_POE %12llu [us]\r\n", prover_runtime.prover_POE);

	qfb_clear(C);
	fmpz_clear(z);
	fmpz_clear(y);
	fmpz_clear(p);
	fmpz_clear(zero);

	return 1;
}


int pf_init(_struct_proof_ *pf)
{
	fmpz_init((pf->alpha));
	fmpz_init((pf->yL));
	fmpz_init((pf->yR));
	qfb_init((pf->POE_proof));
	commit_init(&(pf->CL));
	commit_init(&(pf->CR));

	return 1;	
}

int pf_clear(_struct_proof_ *pf)
{
	fmpz_clear((pf->alpha));
	fmpz_clear((pf->yL));
	fmpz_clear((pf->yR));
	qfb_clear((pf->POE_proof));
	commit_clear(&(pf->CL));
	commit_clear(&(pf->CR));

	return 1;
}


int Spd(fmpz_t output, fmpz_t p, unsigned int d)
{
	int nbit = 0;
	d++;
	for(nbit=0; d != 0; (d >>= 1), nbit++);
	fmpz_pow_ui(output, p, nbit);
	return 1;
}

int EvalBounded_origin_verify(_struct_pp_ *pp, qfb_t* C, const fmpz_t z, fmpz_t* y, fmpz_t* b, _struct_poly_* poly) 
{
	static FILE *fp;
	static unsigned char buffer[10000]={0};
	static int isfirst = 0, flag = 1;
	static _struct_proof_ pf;
	static fmpz_t z_tmp;
	static fmpz_t y_tmp;
	static qfb_t poe_w;
	static qfb_t poe_u;
	static qfb_t poe_x;
	static fmpz_t spd;

	if(isfirst == 0)
	{
		//TimerOn();
		fp = fopen("./Txt/proof.txt", "a+");
		//RunTime_file_IO += TimerOff();
		pf_init(&pf);
		fmpz_init(y_tmp);
		fmpz_init(z_tmp);
		qfb_init(poe_w);
		qfb_init(poe_u);
		qfb_init(poe_x);
	
		fmpz_init(spd);

		//TimerOn();
		// Spd(spd, pp->p, poly->d);
		//RunTime_eval += TimerOff();
		isfirst = 1;
	}

	if(poly->d == 1)
	{
		//TimerOn();
		fscanf(fp, "%s", buffer);
		fmpz_set_str(poly->Fx[0], buffer, 16);
		//RunTime_file_IO += TimerOff();

		//TimerOn();
		//BN_mul(z_tmp, *b, spd, ctx);
		fmpz_mul_2exp(z_tmp, *b, pp->security_level*4);
		// if(fmpz_cmp(z_tmp, pp->q) >= 0){// || fmpz_cmp(spd, pp->q) >= 0){
		// 	printf("bounded fail!! [ b * spd > q]\n");
		// 	flag = 0;
		// }
		
		if(fmpz_cmp(poly->Fx[0], *b) > 0){
			printf("bounded fail!! [ |f| > b ]\n");
			printf("f : "); fmpz_print(poly->Fx[0]); //printf("\n");
			printf("b : "); fmpz_print(*b);			 //printf("\n");
			flag = 0;
		}

		fmpz_mod(z_tmp, *y, pp->p);
		fmpz_mod(y_tmp, poly->Fx[0], pp->p);
		if(fmpz_cmp(z_tmp, y_tmp) != 0){
			printf("ERROR : f mod p != y mod p\n");
			printf("f : "); fmpz_print(y_tmp); //printf("\n");
			printf("y : "); fmpz_print(z_tmp); //printf("\n");
			flag = 0;
		}


		qfb_t tmp;
		qfb_init(tmp);
		qfb_pow_with_root(tmp, pp->g, pp->G, poly->Fx[0], pp->L);
		qfb_reduce(tmp,tmp,pp->G);

		if(qfb_equal(tmp, *C) != 1){
			printf("ERROR : g^f != C\n");
			printf("g^f : "); qfb_print(tmp); printf("\n");
			printf("  C : "); qfb_print(*C); printf("\n");
			flag = 0;
		}
		//RunTime_eval += TimerOff();

		if(	flag == 1 )
			printf("Verify Success!!\n");
		else
			printf("Verify Fail.....\n");
		
		pf_clear(&pf);
		fmpz_clear(z_tmp);
		fmpz_clear(y_tmp);
		qfb_clear(poe_w);
		qfb_clear(poe_u);
		qfb_clear(poe_x);
		fclose(fp);

		return flag;
	}
	else if( ((poly->d)%2) == 1 )
	{
		//printf("d is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		//TimerOn();
		//TimerOn2(&before[0]);
		qfb_pow_with_root(*C, *C, pp->G, pp->q, pp->L);
		qfb_reduce(*C,*C,pp->G);
		//BN_mod_exp(*C,*C,pp->q,pp->G,ctx);	// C' = C^q
		

		fmpz_mul(*y, *y, z);
		fmpz_mod(*y, *y, pp->p);	// y=y*z mod p
		fmpz_set_ui(y_tmp, poly->d);
		fmpz_mul(*b, *b, y_tmp);	// b =  bd
		
		poly->d = poly->d + 1;				//d = d + 1		
		//RunTime[0] += TimerOff2(&before[0], &after[0]);	// 14

		//RunTime_eval += TimerOff();
		////RunTime_eval += //RunTime[0];
		return EvalBounded_origin_verify(pp, C, z, y, b, poly);
	}
	else
	{
		int i;
		int d_ = ((poly->d)/2); //*d = ((*d+1)>>1)-1;		// P,V compute
		//printf("d is even [d : %d -> d' : %d]\n", poly->d, d_);
		
		//TimerOn();
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.alpha, buffer, 16);
		//BN_hex2bn(&alpha, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.yL, buffer, 16);
		//BN_hex2bn(&yL, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.yR, buffer, 16);
		//BN_hex2bn(&yR, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C->a, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C->b, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C->c, buffer, 16);
		//BN_hex2bn(&CL.C, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C->a, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C->b, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C->c, buffer, 16);
		//BN_hex2bn(&CR.C, buffer);
		
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof->a, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof->b, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof->c, buffer, 16);
		//RunTime_file_IO += TimerOff();


		//TimerOn();

		fmpz_set_ui(z_tmp, d_);
		fmpz_powm(z_tmp, z, z_tmp, pp->p);
		fmpz_mul(z_tmp, z_tmp, pf.yR);
		//fmpz_set(z_tmp, pf.yR);
		fmpz_mod(z_tmp, z_tmp, pp->p);
		fmpz_add(y_tmp, z_tmp, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		//fmpz_print( pf.yR );	printf("\n");
		//fmpz_print( pf.yL );	printf("\n");


		if(fmpz_cmp(y_tmp, *y) != 0){		
			//RunTime_eval += TimerOff();
			printf("Fail Compare y..\n");
			//TimerOn();
		}
		//else
		//	printf("GOOD\n");
		//fmpz_print(y_tmp);	printf("\n");
		//fmpz_print(*y);	printf("\n");
		//RunTime[2] += TimerOff2(&before[2], &after[2]);

		//TimerOn2(&before[1]);
		qfb_set(poe_u, pf.CR.C);
		qfb_inverse(poe_w, pf.CL.C);
		qfb_nucomp(poe_w, poe_w, *C, pp->G, pp->L);
		qfb_reduce(poe_w, poe_w, pp->G);

		//BN_copy(poe_u, CR.C);
		//BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		//BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);

		//RunTime[1] += TimerOff2(&before[1], &after[1]);
		//TimerOn2(&before[3]);
		if( verify_pk(pf.POE_proof, poe_w, poe_u, pp, d_) == 0)
		{
			//RunTime_eval += TimerOff();
			printf("Fail POE\n");
			//TimerOn();
		}	
		/********************* POE
		*******************************/
		//RunTime[3] += TimerOff2(&before[3], &after[3]);

		//printf("y' <- (a*yL + yR) mod p \n");
		//TimerOn2(&before[4]);
		fmpz_mul(y_tmp, pf.alpha, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		fmpz_add(*y, y_tmp, pf.yR);
		fmpz_mod(*y, *y, pp->p);

		//BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		//BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		qfb_pow_with_root(*C, pf.CL.C, pp->G, pf.alpha, pp->L);
		qfb_nucomp(*C, *C, pf.CR.C, pp->G, pp->L);
		qfb_reduce(*C, *C, pp->G);

		//BN_mod_exp(*C, CL.C, alpha, pp->G, ctx);
		//BN_mod_mul(*C, *C, CR.C, pp->G, ctx);

		//printf("b' <- b(p+1)/2\n");
		// fmpz_set(y_tmp,pp->p);
		// fmpz_add_ui(y_tmp,y_tmp,1);
		// fmpz_fdiv_q_2exp(y_tmp,y_tmp,1);		//BN_rshift1(y_tmp,y_tmp);
		// fmpz_mul(*b, *b, y_tmp);
		fmpz_mul_2exp(*b,*b,pp->security_level);
		//BN_copy(y_tmp,pp->p);
		//BN_add_word(y_tmp,1);
		//BN_rshift1(y_tmp,y_tmp);
		//BN_mul(*b,*b,y_tmp,ctx);
		////printf("b : %s\n", BN_bn2hex(*b));

		//printf("f' <- a*fL + fR\n");
		poly->d = d_;
		//RunTime[4] += TimerOff2(&before[4], &after[4]);

		//printf("V run EvalBounded_verify(pp, C', z, y', d', b', f'(X))\n\n");
		//RunTime_eval += TimerOff();
		return EvalBounded_origin_verify(pp, C, z, y, b, poly);
	}
}


int EvalBounded_verify(_struct_pp_ *pp, qfb_t* C, const fmpz_t z, fmpz_t* y, fmpz_t* b, _struct_poly_* poly) 
{
	static FILE *fp;
	static unsigned char buffer[10000]={0};
	static int isfirst = 0, flag = 1;
	static _struct_proof_ pf;
	static fmpz_t z_tmp;
	static fmpz_t y_tmp;
	static qfb_t poe_w;
	static qfb_t poe_u;
	static qfb_t poe_x;
	static fmpz_t spd;

	if(isfirst == 0)
	{
		//TimerOn();
		fp = fopen("./Txt/proof.txt", "a+");
		//RunTime_file_IO += TimerOff();
		pf_init(&pf);
		fmpz_init(y_tmp);
		fmpz_init(z_tmp);
		qfb_init(poe_w);
		qfb_init(poe_u);
		qfb_init(poe_x);
	
		fmpz_init(spd);

		//TimerOn();
		Spd(spd, pp->p, poly->d);
		//RunTime_eval += TimerOff();
		isfirst = 1;
	}

	if(poly->d == 1)
	{
		//TimerOn();
		fscanf(fp, "%s", buffer);
		fmpz_set_str(poly->Fx[0], buffer, 16);
		//RunTime_file_IO += TimerOff();

		//TimerOn();
		//BN_mul(z_tmp, *b, spd, ctx);
		fmpz_mul(z_tmp, *b, spd);		
		if(fmpz_cmp(z_tmp, pp->q) >= 0){// || fmpz_cmp(spd, pp->q) >= 0){
			fmpz_print(z_tmp);
			printf("\n");
			fmpz_print(*b);
			printf("\n");
			fmpz_print(spd);
			printf("\n");
			printf("bounded fail!! [ b * spd > q]\n");
			flag = 0;
		}
		
		if(fmpz_cmp(poly->Fx[0], *b) > 0){
			printf("bounded fail!! [ |f| > b ]\n");
			printf("f : "); fmpz_print(poly->Fx[0]); //printf("\n");
			printf("b : "); fmpz_print(*b);			 //printf("\n");
			flag = 0;
		}

		fmpz_mod(z_tmp, *y, pp->p);
		fmpz_mod(y_tmp, poly->Fx[0], pp->p);
		if(fmpz_cmp(z_tmp, y_tmp) != 0){
			printf("ERROR : f mod p != y mod p\n");
			printf("f : "); fmpz_print(y_tmp); //printf("\n");
			printf("y : "); fmpz_print(z_tmp); //printf("\n");
			flag = 0;
		}


		qfb_t tmp;
		qfb_init(tmp);
		qfb_pow_with_root(tmp, pp->g, pp->G, poly->Fx[0], pp->L);

		if(qfb_equal(tmp, *C) != 1){
			printf("ERROR : g^f != C\n");
			printf("g^f : "); qfb_print(tmp); printf("\n");
			printf("  C : "); qfb_print(*C); printf("\n");
			flag = 0;
		}
		//RunTime_eval += TimerOff();

		if(	flag == 1 )
			printf("Verify Success!!\n");
		else
			printf("Verify Fail.....\n");
		
		pf_clear(&pf);
		fmpz_clear(z_tmp);
		fmpz_clear(y_tmp);
		qfb_clear(poe_w);
		qfb_clear(poe_u);
		qfb_clear(poe_x);
		fclose(fp);

		return flag;
	}
	else if( ((poly->d)%2) == 1 )
	{
		printf("d is odd  [d : %d -> d' : %d]\n", poly->d, poly->d + 1);
		//TimerOn();
		//TimerOn2(&before[0]);
		qfb_pow_with_root(*C, *C, pp->G, pp->q, pp->L);
		//BN_mod_exp(*C,*C,pp->q,pp->G,ctx);	// C' = C^q
		

		fmpz_mul(*y, *y, z);
		fmpz_mod(*y, *y, pp->p);	// y=y*z mod p
		fmpz_set_ui(y_tmp, poly->d);
		fmpz_mul(*b, *b, y_tmp);	// b =  bd
		
		poly->d = poly->d + 1;				//d = d + 1		
		//RunTime[0] += TimerOff2(&before[0], &after[0]);	// 14

		//RunTime_eval += TimerOff();
		////RunTime_eval += //RunTime[0];
		return EvalBounded_verify(pp, C, z, y, b, poly);
	}
	else
	{
		int i;
		int d_ = ((poly->d)/2); //*d = ((*d+1)>>1)-1;		// P,V compute
		printf("d is even [d : %d -> d' : %d]\n", poly->d, d_);
		
		//TimerOn();
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.alpha, buffer, 16);
		//BN_hex2bn(&alpha, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.yL, buffer, 16);
		//BN_hex2bn(&yL, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.yR, buffer, 16);
		//BN_hex2bn(&yR, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C->a, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C->b, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CL.C->c, buffer, 16);
		//BN_hex2bn(&CL.C, buffer);

		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C->a, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C->b, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.CR.C->c, buffer, 16);
		//BN_hex2bn(&CR.C, buffer);
		
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof->a, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof->b, buffer, 16);
		fscanf(fp, "%s", buffer);
		fmpz_set_str(pf.POE_proof->c, buffer, 16);
		//RunTime_file_IO += TimerOff();


		//TimerOn();

		//fmpz_set_ui(z_tmp, d_);
		//fmpz_powm(z_tmp, z, z_tmp, pp->p);
		//fmpz_mul(z_tmp, z_tmp, pf.yR);
		
		//fmpz_set(z_tmp, pf.yR);
		
		fmpz_mul(z_tmp, z, pf.yR);
		fmpz_mod(z_tmp, z_tmp, pp->p);
		fmpz_add(y_tmp, z_tmp, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		fmpz_print( pf.yR );	printf("\n");
		fmpz_print( pf.yL );	printf("\n");


		if(fmpz_cmp(y_tmp, *y) != 0){		
			//RunTime_eval += TimerOff();
			printf("Fail Compare y..\n");
			//TimerOn();
		}
		else
			printf("GOOD\n");
		fmpz_print(y_tmp);	printf("\n");
		fmpz_print(*y);	printf("\n");
		//RunTime[2] += TimerOff2(&before[2], &after[2]);

		//TimerOn2(&before[1]);
		qfb_set(poe_u, pf.CR.C);
		qfb_inverse(poe_w, pf.CL.C);
		qfb_nucomp(poe_w, poe_w, *C, pp->G, pp->L);
		qfb_reduce(poe_w, poe_w, pp->G);

		//BN_copy(poe_u, CR.C);
		//BN_mod_inverse(poe_w, CL.C, pp->G, ctx);
		//BN_mod_mul(poe_w, poe_w, *C, pp->G, ctx);

		//RunTime[1] += TimerOff2(&before[1], &after[1]);
		//TimerOn2(&before[3]);
		if( verify_pk(pf.POE_proof, poe_w, poe_u, pp, 1) == 0)
		{
			//RunTime_eval += TimerOff();
			printf("Fail POE\n");
			//TimerOn();
		}	
		/********************* POE
		*******************************/
		//RunTime[3] += TimerOff2(&before[3], &after[3]);

		//printf("y' <- (a*yL + yR) mod p \n");
		//TimerOn2(&before[4]);
		fmpz_mul(y_tmp, pf.alpha, pf.yL);
		fmpz_mod(y_tmp, y_tmp, pp->p);
		fmpz_add(*y, y_tmp, pf.yR);
		fmpz_mod(*y, *y, pp->p);

		//BN_mod_mul(y_tmp, alpha, yL, pp->p, ctx);
		//BN_mod_add(*y, y_tmp, yR, pp->p, ctx);
		
		//printf("C' <- CL^a CR\n");
		qfb_pow_with_root(*C, pf.CL.C, pp->G, pf.alpha, pp->L);
		qfb_nucomp(*C, *C, pf.CR.C, pp->G, pp->L);
		qfb_reduce(*C, *C, pp->G);

		//BN_mod_exp(*C, CL.C, alpha, pp->G, ctx);
		//BN_mod_mul(*C, *C, CR.C, pp->G, ctx);

		//printf("b' <- b(p+1)/2\n");
		fmpz_set(y_tmp,pp->p);
		fmpz_add_ui(y_tmp,y_tmp,1);
		fmpz_fdiv_q_2exp(y_tmp,y_tmp,1);		//BN_rshift1(y_tmp,y_tmp);
		fmpz_mul(*b, *b, y_tmp);

		//BN_copy(y_tmp,pp->p);
		//BN_add_word(y_tmp,1);
		//BN_rshift1(y_tmp,y_tmp);
		//BN_mul(*b,*b,y_tmp,ctx);
		////printf("b : %s\n", BN_bn2hex(*b));

		//printf("f' <- a*fL + fR\n");
		poly->d = d_;
		//RunTime[4] += TimerOff2(&before[4], &after[4]);

		//printf("V run EvalBounded_verify(pp, C', z, y', d', b', f'(X))\n\n");
		//RunTime_eval += TimerOff();
		return EvalBounded_verify(pp, C, z, y, b, poly);
	}
}



int Eval_verify(_struct_pp_* pp, _struct_commit_* cm, _struct_poly_* poly) // ( pp, z, y, d, f~(X) )
{
	int i;
	fmpz_t zero;// = BN_new();
	fmpz_t p;// = BN_new();
	qfb_t C;// = BN_new();
	fmpz_t z;// = BN_new();
	fmpz_t z_tmp;// = BN_new();
	fmpz_t y;// = BN_new();
	
	qfb_init(C);
	qfb_set(C, cm->C);

	fmpz_init_set_ui(zero,0);
	fmpz_init_set_ui(y,0);
	fmpz_init(p);
	fmpz_init_set_ui(z,100);
	fmpz_init_set_ui(z_tmp,1);

	fmpz_sub_ui(p, pp->p, 1);
	// fmpz_tdiv_q_2exp(p,p,1);


	// TimerOn();
	// //RunTime_eval += TimerOff();
	// i=0;
	// do{
	// 	BN_mod_inverse(poly->Fx[i], poly->Fx[i], pp->p, ctx);
	// 	i++;
	// }while(i<= poly->d);

	// poly 계산
	i = 0;
	do{
		fmpz_mul(zero, poly->Fx[i], z_tmp);
		fmpz_mod(zero, zero, pp->p);
		fmpz_add(y, y, zero);
		fmpz_mod(y, y, pp->p);
		fmpz_mul(z_tmp, z_tmp, z);
		fmpz_mod(z_tmp, z_tmp, pp->p);
		i++;
	}while(i<= poly->d);

	//printf("EvalBounded_verify Start\n");
	int flag;
	flag = EvalBounded_origin_verify(pp, &C, z, &y, &p, poly);

	qfb_clear(C);
	fmpz_clear(z);
	fmpz_clear(y);
	fmpz_clear(p);
	fmpz_clear(zero);

	return flag;
}
