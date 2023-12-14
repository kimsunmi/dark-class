#include "../hedder/codetimer.h"
#include "../hedder/poe.h"
#include <flint/fmpz_poly.h>

unsigned long long int RunTime_poe1 = 0;
unsigned long long int RunTime_poe2 = 0;
unsigned long long int RunTime_poe3 = 0;
unsigned long long int RunTime_poe4 = 0;
unsigned long long int RunTime_poe5 = 0;


struct timeval before1[10]={0}, after1[10] = {0};
unsigned int RunTime1[10] = {0};

int HG_func(BIGNUM *output, const BIGNUM *input)
{
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
    unsigned char *tmp_str = BN_bn2hex(input);
   
   	//BN_copy(output,input);
     SHA256(tmp_str, strlen(tmp_str), digest);   
	 BN_zero(output);
	 for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
	 BN_hex2bn(&output, mdString);

	//printf("HG len : %d\n", BN_num_bits(output));
	//printf("HG input : %s\n", BN_bn2hex(input));
	//printf("HG : %s\n", mdString);
	//printf("HG : %s\n", BN_bn2hex(output));

	free(tmp_str);
    return 1;
}

int Hprime_func(fmpz_t output, const qfb_t in1, const qfb_t in2)
{
    unsigned char digest[SHA256_DIGEST_LENGTH]={0};
	unsigned char mdString[SHA256_DIGEST_LENGTH*2+1]={0};
	
    char *str_in1_a = fmpz_get_str(NULL, 16, in1->a);
    char *str_in1_b = fmpz_get_str(NULL, 16, in1->b);
    char *str_in1_c = fmpz_get_str(NULL, 16, in1->c);
    char *str_in2_a = fmpz_get_str(NULL, 16, in2->a);
    char *str_in2_b = fmpz_get_str(NULL, 16, in2->b);
    char *str_in2_c = fmpz_get_str(NULL, 16, in2->c);
	char *str_concat = calloc(strlen(str_in1_a) + strlen(str_in1_b) + strlen(str_in1_c) 
								+ strlen(str_in2_a) + strlen(str_in2_b) + strlen(str_in2_c) + 1, sizeof(char));
	//char *output_string;
	int concat_len = 0;

	memcpy(str_concat + concat_len, str_in1_a, sizeof(char) * (strlen(str_in1_a)));	concat_len += strlen(str_in1_a);
	memcpy(str_concat + concat_len, str_in1_b, sizeof(char) * (strlen(str_in1_b)));	concat_len += strlen(str_in1_b);
	memcpy(str_concat + concat_len, str_in1_c, sizeof(char) * (strlen(str_in1_c)));	concat_len += strlen(str_in1_c);
	memcpy(str_concat + concat_len, str_in2_a, sizeof(char) * (strlen(str_in2_a)));	concat_len += strlen(str_in2_a);
	memcpy(str_concat + concat_len, str_in2_b, sizeof(char) * (strlen(str_in2_b)));	concat_len += strlen(str_in2_b);
	memcpy(str_concat + concat_len, str_in2_c, sizeof(char) * (strlen(str_in2_c)));	concat_len += strlen(str_in2_c);

	SHA256(str_concat, strlen(str_concat), digest);   
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

	mpz_t u, w;
	mpz_init_set_str(u,(char*)mdString,16);
	mpz_init(w);
	mpz_nextprime(w,u);	
	fmpz_set_mpz(output, w);

    //printf(">>"); fmpz_print(output); printf("\n");

	mpz_clear(u);
	mpz_clear(w);
	free(str_in1_a);
	free(str_in1_b);
	free(str_in1_c);
	free(str_in2_a);
	free(str_in2_b);
	free(str_in2_c);
	free(str_concat);

    return 1;
}

//(const BIGNUM *pf, const BIGNUM *w, const BIGNUM *u, const BIGNUM *x_pow, const BIGNUM *x, const BIGNUM *pk)
int verify_pk(qfb_t pf, qfb_t w, qfb_t u, _struct_pp_ *pp, const int d)
{	// pf^l * u^r = w ?
	int i, flag = 1;
	int num = (int)fmpz_bits(pp->q);
	int t = (num - 1) * d;

	qfb_t g, qfb_tmp1, qfb_tmp2;
	fmpz_t l, x, tmp, r;

	qfb_init(g);
	qfb_init(qfb_tmp1);
	qfb_init(qfb_tmp2);
	fmpz_init(x);
	fmpz_init(l);
	fmpz_init(tmp);
	fmpz_init(r);

	//flag &= HG_func(g,u);		
	qfb_set(g, u);
	Hprime_func(l, u, w);	

	//TimerOn2(&before1[1]);
	fmpz_setbit(x, t);
	//RunTime1[1] = TimerOff2(&before1[1], &after1[1]);

	//TimerOn2(&before1[2]);
	fmpz_mod(r, x, l);
	//RunTime1[2] = TimerOff2(&before1[2], &after1[2]);


	//TimerOn2(&before1[3]);
	qfb_pow_with_root(qfb_tmp1, pf, pp->G, l, pp->L);
	qfb_pow_with_root(qfb_tmp2, g, pp->G, r, pp->L);
	
	qfb_nucomp(qfb_tmp1, qfb_tmp1, qfb_tmp2, pp->G, pp->L);
	qfb_reduce(qfb_tmp1, qfb_tmp1, pp->G);

	if( qfb_equal(qfb_tmp1,w) == 1)
		flag = 1;
	else
		flag = 0;

	//qfb_print(qfb_tmp1); printf("\n");
	//qfb_print(w); printf("\n");
	
	//RunTime1[4] = TimerOff2(&before1[4], &after1[4]);
	// if(1)
	// {
	// 	FILE *fp;
	// 	fp = fopen("record/eval_verify_poe.txt", "a+");
	// 	fprintf(fp, "%12d ", t);
	// 	fprintf(fp, "%12u ", RunTime1[0]);
	// 	fprintf(fp, "%12u ", RunTime1[1]);
	// 	fprintf(fp, "%12u ", RunTime1[2]);
	// 	fprintf(fp, "%12u ", RunTime1[3]);
	// 	fprintf(fp, "%12u\n", RunTime1[4]);
	// 	fclose(fp);
	// }
	qfb_clear(g);
	qfb_clear(qfb_tmp1);
	qfb_clear(qfb_tmp2);
	fmpz_clear(x);
	fmpz_clear(l);
	fmpz_clear(tmp);

	return (flag);
}

int eval_pk_test(qfb_t pf, qfb_t w,  qfb_t u, _struct_poly_* fR, _struct_pp_ *pp, const int d)
{	//eval_pk(POE_proof, poe_w, poe_u, poe_x, d_+1, pp->G, NULL);								
	// u^x mod G = w mod G
	TimerOn2(&before1[0]);
	int i, flag = 1;
	int num = (int)fmpz_bits(pp->q) - 1;
	unsigned int t = (num) * d;
	int cnt = 0;

	fmpz_t tmp, tmp_1, tmp_2;
	fmpz_poly_t t_poly1;
	fmpz_poly_t t_poly2;
	fmpz_poly_t t_poly3;

	_struct_commit_ cm;
	_struct_poly_ f_out;

	qfb_t g;
	fmpz_t l, x, r;
	fmpz_t f_q;

	//fmpz_t bn_tmp1, bn_tmp2;
	
	qfb_init(g);
	fmpz_init(x);
	fmpz_init(l);
	fmpz_init(tmp);
	fmpz_init(r);
	
	//  u^x = w --> CR^(q^d'+1)  = C/CL
	// pf^l * u^r = w ?	-->		CR^r

	//flag &= HG_func(g,u);		
	qfb_set(g, u);	//BN_copy(g,u);			
	Hprime_func(l, u, w);	
	
	//printf("t: %d\n", t);
	//printf("	poe eval l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l
	//printf("l : %s\n", BN_bn2hex(l));
	
	//TimerOn();
	fmpz_setbit(x, t);
	fmpz_tdiv_qr(tmp, r, x, l);
	///////////////////////////////////////////////////////////////

	fmpz_poly_init(t_poly1);
    fmpz_poly_init(t_poly2);
    fmpz_poly_init(t_poly3);
	fmpz_init(f_q);
	fmpz_zero(f_q);

	for(i = fR->d-1; i >= 0; i--)
	{
		fmpz_mul_2exp(f_q, f_q, num);
		fmpz_add(f_q, f_q, fR->Fx[i]);
		// fmpz_mod(open->r, open->r, l);
	}

	fmpz_init_set(tmp_1, tmp);
	fmpz_mul(tmp_1, f_q, tmp_1);
	fmpz_init(tmp_2);	
	cnt = 0;
	RunTime1[0] += TimerOff2(&before1[0], &after1[0]);	
	TimerOn2(&before1[1]);
	//printf("poe set f'\r\n");
	while(fmpz_bits(tmp_1) > cnt*num)
	{
		fmpz_zero(tmp_2);
		for(int i = 0 ; i<num; i++)
		{
			if(fmpz_tstbit(tmp_1, i + cnt*(num)) == 1)
				fmpz_setbit(tmp_2, i);
		}
		//fmpz_tdiv_qr(tmp_1, tmp_2, tmp_1, pp->q);		
		fmpz_poly_set_coeff_fmpz(t_poly2, cnt, tmp_2);
		cnt++;
	}
	RunTime1[1] += TimerOff2(&before1[1], &after1[1]);	
	TimerOn2(&before1[2]);

	///////////////////////////////////////////////////////////////////////////////
	//fmpz_poly_print(t_poly2); printf("\n");
	// cnt = 0;
	// while(!fmpz_is_zero(tmp_1)){
	// 	fmpz_tdiv_qr(tmp_1, tmp_2, tmp_1, pp->q);
	// 	fmpz_poly_set_coeff_fmpz(t_poly2, cnt, tmp_2);
	// 	cnt++;
	// }
	// fmpz_poly_print(t_poly2); printf("\n");
	///////////////////////////////////////////////////////////////////////////////


	//printf("poe set f\r\n");
	// for(int i=0; i< fR->d; i++)
	// 	fmpz_poly_set_coeff_fmpz(t_poly1, i, fR->Fx[i]);

	//printf("poe f*f'\r\n");
	// fmpz_poly_mul_SS(t_poly3, t_poly2, t_poly1);
	f_out.d = cnt;	
	f_out.Fx = (fmpz_t*)calloc(f_out.d + 1, sizeof(fmpz_t));

	//printf("poe poly -> fmpz_t'\r\n");
	fmpz_zero(tmp_1);
	for(int i=0; i< f_out.d; i++){
		fmpz_init(f_out.Fx[i]);
		fmpz_poly_get_coeff_fmpz(f_out.Fx[i], t_poly2, i);
		fmpz_add(f_out.Fx[i], f_out.Fx[i], tmp_1);
		fmpz_tdiv_qr(tmp_1, f_out.Fx[i], f_out.Fx[i], pp->q);
	}

	if(fmpz_is_zero(tmp_1) == 0)
	{
		fmpz_init(f_out.Fx[f_out.d]);
		fmpz_set(f_out.Fx[f_out.d], tmp_1);
		f_out.d++;		
	}

	//printf("poe commit %d\r\n", f_out.d);
	commit_init(&cm);
	commit_new(&cm, *pp, f_out);
	qfb_set(pf,cm.C);
	//printf("poe end\r\n");
	//printf("d : %d, cnt : %d\n", d, cnt);
	///////////////////////////////////////////////////////////////
	//qfb_pow_with_root(pf, g, pp->G, tmp, pp->L);
	for(int i=0; i< f_out.d; i++)
		fmpz_clear(f_out.Fx[i]);
	free(f_out.Fx);

	RunTime1[6] += TimerOff2(&before1[6], &after1[6]);	


	//printf("1 :");qfb_print(cm.C);printf("\n\n");		
	//printf("2 :");qfb_print(pf);printf("\n\n");

	//RunTime_poe1 = TimerOff();
	//RunTime_poe1 += TimerOff();
	//printf("%s ", BN_bn2hex(pf));
	commit_clear(&cm);

	fmpz_poly_clear(t_poly1);
	fmpz_poly_clear(t_poly2);
	fmpz_poly_clear(t_poly3);

	qfb_clear(g);
	fmpz_clear(x);
	fmpz_clear(l);
	fmpz_clear(tmp);
	return flag;
}


int eval_pk(qfb_t pf, qfb_t w, qfb_t u, _struct_pp_ *pp, const int d)
{	//eval_pk(POE_proof, poe_w, poe_u, poe_x, d_+1, pp->G, NULL);								
	// u^x mod G = w mod G
	int i, flag = 1;
	int num = (int)fmpz_bits(pp->q);
	int t = (num - 1) * d;

	qfb_t g;
	fmpz_t l, x, tmp, r;
	//fmpz_t bn_tmp1, bn_tmp2;
	
	qfb_init(g);
	fmpz_init(x);
	fmpz_init(l);
	fmpz_init(tmp);
	fmpz_init(r);
	
	//  u^x = w --> CR^(q^d'+1)  = C/CL
	// pf^l * u^r = w ?	-->		CR^r

	//flag &= HG_func(g,u);		
	qfb_set(g, u);	//BN_copy(g,u);			
	Hprime_func(l, u, w);	
	
	//printf("t: %d\n", t);
	//printf("	poe eval l : %s\n", BN_bn2hex(l));// 	Hprime( g || w ) -> l
	//printf("l : %s\n", BN_bn2hex(l));
	
	//TimerOn();
	fmpz_setbit(x, t);
	fmpz_tdiv_qr(tmp, r, x, l);

	qfb_pow_with_root(pf, g, pp->G, tmp, pp->L);

	//RunTime_poe1 = TimerOff();
	//RunTime_poe1 += TimerOff();
	//printf("%s ", BN_bn2hex(pf));

	qfb_clear(g);
	fmpz_clear(x);
	fmpz_clear(l);
	fmpz_clear(tmp);
	return flag;
}