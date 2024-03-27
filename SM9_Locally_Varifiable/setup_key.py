from gmssl.sm3 import sm3_kdf, sm3_hash

from random import SystemRandom

import gmssl.optimized_field_elements as fq
import gmssl.optimized_curve as ec
import gmssl.optimized_pairing as ate

from util.util import bitlen, i2sp, fe2sp, ec2sp, str2hexbytes, h2rf

FAILURE = False
SUCCESS = True


def setup(scheme):
    P1 = ec.G2
    P2 = ec.G1

    rand_gen = SystemRandom()
    s = rand_gen.randrange(ec.curve_order)

    if (scheme == 'sign'):
        Ppub = ec.multiply(P2, s)
        g = ate.pairing(P1, Ppub)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Ppub = ec.multiply(P1, s)
        g = ate.pairing(Ppub, P2)
    else:
        raise Exception('Invalid scheme')

    master_public_key = (P1, P2, Ppub, g)
    return (master_public_key, s)


def private_key_extract(scheme, master_public, master_secret, identity):
    P1 = master_public[0]
    P2 = master_public[1]

    user_id = sm3_hash(str2hexbytes(identity))
    m = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    m = master_secret + m
    if (m % ec.curve_order) == 0:
        return FAILURE
    m = master_secret * fq.prime_field_inv(m, ec.curve_order)  # 求逆元
    # m = fq.prime_field_inv(master_secret, ec.curve_order) * m  # 求逆元

    if (scheme == 'sign'):
        Da = ec.multiply(P1, m)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Da = ec.multiply(P2, m)
    else:
        raise Exception('Invalid scheme')

    return Da
