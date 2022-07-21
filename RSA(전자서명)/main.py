from gmpy2 import *


def x_gcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def mul_inverse(b, n):
    g, x, _ = x_gcd(b, n)
    if g == 1:
        return x % n


def fermat_factor(n):
    assert n % 2 != 0
    a = isqrt(n)
    b2 = square(a) - n
    while not is_square(b2):
        a += 1
        b2 = square(a) - n
    p = a + isqrt(b2)
    q = a - isqrt(b2)
    return int(p), int(q)


def main():
    n = 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430652885096550381956977355009744407642308411545070379136134645709973060633048727107215362312651042098054062317216389604359801702614666769905641776363676873830995947
    e = 65537
    print("My name is 정경재");
    str_bytes = "정경재".encode('utf-8')
    m = int.from_bytes(str_bytes, byteorder="big")

    p, q = fermat_factor(n)
    phi_n = (p - 1) * (q - 1)

    d = mul_inverse(e, phi_n)

    # s = power_mod(m, d, n)
    s = powmod(m, d, n)

    print("[*] m :", m)
    print("[*] p :", p)
    print("[*] q :", q)
    print("s=", s)

    m_prime = powmod(s, e, n)
    print("My hex name is" + str(m_prime))
    print("Convert to UTF-8 is " + str(bytes.fromhex(hex(m_prime)[2:]).decode('utf-8')))


if __name__ == '__main__':
    main()

