from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq

FAILURE = False
SUCCESS = True


def sign(master_public, Da, msg):
    Ppub = master_public[2]

    rand_gen = SystemRandom()
    r = rand_gen.randrange(ec.curve_order)
    w = ec.multiply(Ppub, r)

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = msg_hash.encode('utf-8')
    h = h2rf(2, z, ec.curve_order)

    l = (r + h) % ec.curve_order
    l_inv = fq.prime_field_inv(l, ec.curve_order)

    S = ec.multiply(Da, l_inv)
    return (w, S)


def verify(master_public, identity, msg, signature):
    import gmssl.optimized_pairing as ate

    (w, S) = signature
    P1 = master_public[0]
    P2 = master_public[1]
    Ppub = master_public[2]

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = msg_hash.encode('utf-8')
    h = h2rf(2, z, ec.curve_order)

    h_Ppub = ec.multiply(Ppub, h)
    T = ec.add(w, h_Ppub)

    user_id = sm3_hash(str2hexbytes(identity))
    h1 = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    h1_P2 = ec.multiply(P2, h1)
    P3 = ec.add(h1_P2, Ppub)

    v1 = ate.pairing(S, T)
    v2 = ate.pairing(P1, P3)

    if v1 != v2:
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

    print("\t\t\t success")
    pass
