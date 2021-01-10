#ifndef _POE_H
    #include "../hedder/dark_compiler.h"

    int eval_pk(qfb_t pf, qfb_t w, qfb_t u, _struct_pp_ *pp, const int d);
    int eval_pk_test(qfb_t pf, qfb_t w,  qfb_t u, _struct_poly_* fR, _struct_pp_ *pp, const int d);

    int verify_pk(qfb_t pf, qfb_t w, qfb_t u, _struct_pp_ *pp, const int d);
    #define _POE_H
#endif
