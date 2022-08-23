#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

BIGNUM* XEuclid(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b)
{
	// 기본적인 설정
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* x0 = BN_new(); BIGNUM* x1 = BN_new();
	BIGNUM* y0 = BN_new(); BIGNUM* y1 = BN_new();
	BIGNUM* q = BN_new();

	BIGNUM* as = BN_dup(a); BIGNUM* bs = BN_dup(b);
	
	BN_one(x0); BN_zero(x1);
	BN_zero(y0); BN_one(y1);

	while(!BN_is_zero(bs))
	{
		BIGNUM *res = BN_new();
		BN_copy(res, bs);
		BN_div(q, bs, as, bs, ctx);
		BN_copy(as, res);
		
		BN_mul(res, q, x1, ctx);
		BN_sub(res, x0, res);
		BN_copy(x0,x1);
		BN_copy(x1, res);

		BN_mul(res, q, y1, ctx);
		BN_sub(res, y0, res);
		BN_copy(y0, y1);
		BN_copy(y1, res);
	}
	BN_copy(x,x0);
	BN_copy(y,y0);
	return as;
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
    BN_CTX* ctx = BN_CTX_new();
    int n = BN_num_bits(e);
    BIGNUM* init = BN_new();
    BN_one(init);

    for(int i = n-1; i >= 0; i--)
    {
        int check = BN_is_bit_set(e, i);  
        BN_mul(r, init, init ,ctx);
        if(check == 1)
            BN_mul(r, r, a, ctx);
        
        BN_div(NULL, r, r, m, ctx);
        BN_copy(init, r);
    }
}

int MillerRabinTest(BIGNUM* n, BIGNUM* d, BIGNUM* s)
{
    BIGNUM* p1 = BN_new(); BIGNUM* p2 = BN_new();
    BIGNUM* one = BN_new(); BIGNUM* two = BN_new();
    BN_one(one);
    BN_dec2bn(&two,"2");
    BN_sub(p1, n, one);
    BN_sub(p2, n, two);

    BIGNUM* base = BN_new();
    while(1)
    {
        BN_rand_range(base, p2);
        if (BN_is_zero(base) || BN_is_one(base))
            continue;
        else
            break;
    }
    BIGNUM* x = BN_new();
    ExpMod(x, base, d, n);
    if (BN_is_one(x))
        return 1;
    if (BN_cmp(x, p1) == 0)
        return 1;
    else
    {
        BIGNUM* checker = BN_new();
        BN_zero(checker);
        while(1)
        {
            if (BN_cmp(checker, s) == 0)
                break;
            
            ExpMod(x, x, two, n);
            if (BN_cmp(x, p1) == 0)
                return 1;
            if (BN_is_one(x))
                return 0;
            BN_add(checker, checker, one);
        }
    }
}

void Get_Prime(BIGNUM* p, int nBits)
{
    while(1)
    {
        int is_prime =0; // false
        BN_rand(p, nBits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
        BIGNUM* r = BN_new();
        // s는 2의 제곱승을 의미
        BIGNUM* d = BN_new(); BIGNUM* s = BN_new();
        BIGNUM* one = BN_new(); BIGNUM* two = BN_new();
        BN_CTX* ctx = BN_CTX_new();

        BN_copy(d, p);
        BN_one(one);
        // s = 0
        BN_zero(s);
        // d = p -1
        BN_sub(d, p, one);
        // two = one + one;
        BN_add(two, one, one);
        BN_zero(r);
        while(1)
        {
            BN_div(NULL, r, d, two, ctx);
            if(!BN_is_zero(r))
                    break;
            BN_add(s, s, one);
            BN_rshift1(d, d);
        }

        for(int i =0; i < 10; i++)
        {
            if(MillerRabinTest(p, d, s)==1)
                is_prime = 1;
            else
            {
                is_prime = 0;
                break;
            }
        }
        if(is_prime == 1)
            return;
    }
}

typedef struct _b11rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB11_RSA;

BOB11_RSA *BOB11_RSA_new()
{
    BOB11_RSA* rsa = (BOB11_RSA*)malloc(sizeof(BOB11_RSA));
    rsa->e = BN_new();
    rsa->d = BN_new();
    rsa->n = BN_new(); 
    return rsa;
}

int BOB11_RSA_free(BOB11_RSA *b11rsa)
{
    BN_free(b11rsa->e);
    BN_free(b11rsa->d);
    BN_free(b11rsa->n);
    free(b11rsa);
    return 0;
}

int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* p = BN_new(); BIGNUM* q = BN_new();
    BIGNUM* phip = BN_new(); BIGNUM* phiq = BN_new();
    BIGNUM* ainv = BN_new(); BIGNUM* binv = BN_new();

    BIGNUM* EulerPhi = BN_new();
    // 임시로 값을 1로 저장.
    BN_one(EulerPhi);
    // BN_hex2bn(&p,"C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
    // BN_hex2bn(&q,"F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");

    // get Prime p
    Get_Prime(p, nBits/2);
    // get Prime q
    Get_Prime(q, nBits/2);

    // N = P * Q
    BN_mul(b11rsa->n, p, q, ctx);
    
    // Phi = (P-1)*(Q-1)
    BN_sub(phip, p, EulerPhi);
    BN_sub(phiq, q, EulerPhi);
    BN_mul(EulerPhi, phip, phiq, ctx);

    // Gen e
    while(1)
    {
        BIGNUM* ine = BN_new(); BIGNUM* res;
        BIGNUM* tempx = BN_new(); BIGNUM* tempy = BN_new();
        BN_rand_range(ine, EulerPhi);
        res = XEuclid(tempx, tempy , EulerPhi, ine);
        if(BN_is_one(res))
        {
            BN_copy(b11rsa->e, ine);
            break;
        }
    }

    // Cal d
    XEuclid(ainv, binv, b11rsa->e, EulerPhi);
    BN_copy(b11rsa->d, ainv);
}

int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa)
{
    ExpMod(c, m, b11rsa->e, b11rsa->n);
}

int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa)
{
    ExpMod(m, c, b11rsa->d, b11rsa->n);
}