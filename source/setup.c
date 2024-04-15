#include "../hedder/codetimer.h"
#include "../hedder/dark_compiler.h"

//////////////////
// pp-> G,g,p,q generate
int KeyGen_Class_setup( _struct_pp_* pp, const int lamda, const int logD)
{
	fmpz_t fmpz_p;
	qfb_t qfb_tmp;

	qfb_init(qfb_tmp);

	BIGNUM* bn_4 = BN_new();
	BIGNUM* bn_3 = BN_new();
	BIGNUM* bn_p = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	
	int degree = (1<<(logD));

	BN_set_word(bn_4, 4);
	BN_set_word(bn_3, 3);
	
	pp->security_level = lamda;

	// prime 생성해서 pp->G에 set. G=-G로 변경
	do{
	 	BN_generate_prime_ex(bn_p, lamda, 1, bn_4, bn_3, NULL);
		fmpz_set_str(pp->G, BN_bn2hex(bn_p), 16);
		fmpz_neg(pp->G, pp->G);
	}while(BN_num_bits(bn_p) != lamda);

	//pp->g에 0초과 fmpz_p이하 G로 discriminant하여 set, fmpz_p: lamda/4 prime

    do{        
        BN_generate_prime_ex(bn_p, lamda/4, 0, bn_4, bn_3, NULL);
		fmpz_set_str(fmpz_p, BN_bn2hex(bn_p), 16);
		qfb_prime_form(pp->g, pp->G, fmpz_p);
    }while (!qfb_is_primitive(pp->g) || !qfb_is_reduced(pp->g) || fmpz_cmp((pp->g)->a, (pp->g)->b) <= 0 ); 

	// pp->p에 128비트 prime
	BN_generate_prime_ex(bn_p,128,1,NULL,NULL,NULL);
	fmpz_set_str(pp->p, BN_bn2hex(bn_p), 16);

	// pp->q에 논문에 따라 λ(2µ + log µ + 6) + 32µ^2 + 5로 변경

	// fmpz_init_set_ui(pp->q, 0);
	fmpz_setbit(pp->q, 128*(6+ceil(log2(logD))+2*logD)+32*logD*logD+5); 
	
	BN_free(bn_4);
	BN_free(bn_3);
	BN_free(bn_p);
	BN_CTX_free(ctx);

	fmpz_clear(fmpz_p);
	qfb_clear(qfb_tmp);

	return 1;
}

int pp_init(_struct_pp_* pp)
{
	fmpz_init(pp->G);
	fmpz_init(pp->L);
	fmpz_init(pp->q);
	fmpz_init(pp->p);
	qfb_init(pp->g);

	return 1;
}

int pp_clear(_struct_pp_* pp)
{
	fmpz_clear(pp->G);
	fmpz_clear(pp->L);
	fmpz_clear(pp->q);
	fmpz_clear(pp->p);
	qfb_clear(pp->g);

	return 1;
}
