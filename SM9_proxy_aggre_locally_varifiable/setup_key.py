import gmssl.optimized_curve as ec
import gmssl.optimized_field_elements as fq
import gmssl.sm9
from gmssl.sm3 import sm3_hash
from util.util import str2hexbytes, h2rf

FAILURE = False
SUCCESS = True


def setup(scheme):
    return gmssl.sm9.setup(scheme)


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
