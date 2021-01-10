#include "../hedder/dark_compiler.h"
#include "../hedder/codetimer.h"
#include "../hedder/util.h"

#include <flint/fft_tuning.h>
//#include "flint.h"
#include <flint/fmpz.h>
#include <flint/fft.h>
#include <flint/fmpz_poly.h>
#include <flint/ulong_extras.h>

int main()
{
    int i, j, k;

    fmpz_poly_t t_poly1;
    fmpz_poly_t t_poly2;
    fmpz_poly_t t_poly3;
    
    fmpz_t mpz_tmp;

    fmpz_init(mpz_tmp);
    fmpz_poly_init(t_poly1);
    fmpz_poly_init(t_poly2);
    fmpz_poly_init(t_poly3);
    
    for(i=0; i<3; i++)
    {
        fmpz_set_ui(mpz_tmp,i+1);
        fmpz_poly_set_coeff_fmpz(t_poly1, i, mpz_tmp);

        fmpz_set_ui(mpz_tmp,i+1);
        fmpz_poly_set_coeff_fmpz(t_poly2, i, mpz_tmp);
    }

    fmpz_poly_mul_SS(t_poly3, t_poly2, t_poly1);

    fmpz_poly_print(t_poly1);   printf("\r\n");
    fmpz_poly_print(t_poly3);   printf("\r\n");
	return 0;
}
