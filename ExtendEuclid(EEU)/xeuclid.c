#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string 
	* Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM* XEuclid(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b)
{
	// 기본적인 설정
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* x0 = BN_new(); BIGNUM* x1 = BN_new();
	BIGNUM* y0 = BN_new(); BIGNUM* y1 = BN_new();
	BIGNUM* q = BN_new();

	BIGNUM* as = BN_dup(a); BIGNUM* bs = BN_dup(b);
	
	BN_dec2bn(&x0,"1"); BN_dec2bn(&x1,"0");
	BN_dec2bn(&y0,"0"); BN_dec2bn(&y1,"1");
	
	BIGNUM* zero = BN_new();
	BN_zero(zero);

	while(BN_cmp(bs,zero))
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

int main(int argc, char* argv[])
{
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	BIGNUM* gcd;

	if(argc != 3)
	{
		printf("Usage: xeculid num1, num2");
		return 0;
	}

	BN_dec2bn(&a, argv[1]);
	BN_dec2bn(&b, argv[2]);
	gcd = XEuclid(x,y,a,b);

	printBN("(a,b) = ", gcd);
    printBN("a = ", a);
    printBN("b = ", b);
    printBN("x = ", x);
    printBN("y = ", y);
    printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

    if(a != NULL) 
		BN_free(a);
    if(b != NULL) 
		BN_free(b);
    if(x != NULL) 
		BN_free(x);
    if(y != NULL) 
		BN_free(y);
    if(gcd != NULL) 
		BN_free(gcd);

        return 0;
}