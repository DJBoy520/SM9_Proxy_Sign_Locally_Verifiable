from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from gmssl.sm9 import fe2sp, public_key_extract
from util.util import str2hexbytes, h2rf
import gmssl.optimized_pairing as ate
import gmssl.optimized_field_elements as fq

FAILURE = False
SUCCESS = True


# scheme = 'sign'
def sign(master_public, Da, msg):
    g = master_public[3]

    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    w = g ** x

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(w)).encode('utf-8')
    h = h2rf(2, z, ec.curve_order)
    l = (x - h) % ec.curve_order

    S = ec.multiply(Da, l)
    return (h, S)


def verify(master_public, identity, msg, signature):
    (h, S) = signature

    if (h < 0) | (h >= ec.curve_order):
        return FAILURE
    if ec.is_on_curve(S, ec.b2) == False:
        return FAILURE

    Q = public_key_extract('sign', master_public, identity)

    g = master_public[3]
    u = ate.pairing(S, Q)
    t = g ** h
    wprime = u * t

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(wprime)).encode('utf-8')
    h2 = h2rf(2, z, ec.curve_order)

    if h != h2:
        return FAILURE
    return SUCCESS


if __name__ == '__main__':
    from setup_key import setup, private_key_extract
    import time

    idA = 'a'

    print("-----------------test sign and verify---------------")

    master_public, master_secret = setup('sign')

    Da = private_key_extract('sign', master_public, master_secret, idA)

    message = 'abc'
    signature = sign(master_public, Da, message)

    start_time = time.time()
    resu = verify(master_public, idA, message, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

    print(resu)
    pass
