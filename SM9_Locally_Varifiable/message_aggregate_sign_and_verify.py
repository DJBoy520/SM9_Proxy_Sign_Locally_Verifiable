import string

from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq
from tqdm import tqdm

FAILURE = False
SUCCESS = True


def sign_aggregate(master_public, Da, msgs):
    Ppub = master_public[2]

    rand_gen = SystemRandom()
    r = rand_gen.randrange(ec.curve_order)
    Ws = []

    for i in range(len(msgs)):
        w = ec.multiply(Ppub, (r ** (i + 1)) % ec.curve_order)
        Ws.append(w)

    hs = []
    for i in range(len(msgs)):
        msg_hash = sm3_hash(str2hexbytes(msgs[i]))
        z = msg_hash.encode('utf-8')
        h = h2rf(2, z, ec.curve_order)
        hs.append(h)

    ls_inv = []
    for i in tqdm(range(len(msgs)), desc="Processing"):
        l = (r + hs[i]) % ec.curve_order
        ls_inv.append(fq.prime_field_inv(l, ec.curve_order))

    l_inv = 1
    for i in tqdm(range(len(ls_inv)), desc="Processing"):
        l_inv = (l_inv * ls_inv[i]) % ec.curve_order

    S = ec.multiply(Da, l_inv)
    return (Ws, S)


def verify_aggregate(master_public, identity, msgs, signature):
    import gmssl.optimized_pairing as ate
    from util.util import calculate_coefficient_with_modulus

    (Ws, S) = signature
    P1 = master_public[0]
    P2 = master_public[1]
    Ppub = master_public[2]

    hs = []
    for i in tqdm(range(len(msgs)), desc="Processing"):
        msg_hash = sm3_hash(str2hexbytes(msgs[i]))
        z = msg_hash.encode('utf-8')
        h = h2rf(2, z, ec.curve_order)
        hs.append(h)

    coefficients = calculate_coefficient_with_modulus(hs, ec.curve_order)

    user_id = sm3_hash(str2hexbytes(identity))
    h1 = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    h1_P2 = ec.multiply(P2, h1)
    P3 = ec.add(h1_P2, Ppub)

    T = ec.multiply(Ppub, coefficients[0])
    C = coefficients[1::][::-1]
    for i in tqdm(range(len(C)), desc="Processing"):
        b_w = ec.multiply(Ws[i], C[i])
        T = ec.add(b_w, T)

    v1 = ate.pairing(S, T)
    v2 = ate.pairing(P1, P3)

    if v1 != v2:
        return FAILURE
    return SUCCESS


if __name__ == '__main__':
    from setup_key import setup, private_key_extract
    import time

    idA = 'a'

    print("-----------------test aggregate sign and verify---------------")

    master_public, master_secret = setup('sign')

    Da = private_key_extract('sign', master_public, master_secret, idA)

    messages1 = list(string.ascii_lowercase)
    messages2 = list(string.ascii_lowercase)

    cartesian_product = [item1 + item2 for item1 in messages1 for item2 in messages2]
    print(type(cartesian_product[0]))

    signature = sign_aggregate(master_public, Da, cartesian_product)

    start_time = time.time()
    resu = verify_aggregate(master_public, idA, cartesian_product, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

    print("success")
    pass
