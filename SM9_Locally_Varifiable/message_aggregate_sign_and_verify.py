import string

from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from gmssl.sm9 import fe2sp
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq
from tqdm import tqdm

FAILURE = False
SUCCESS = True


def sign_aggregate(master_public, Da, msgs):
    # Ppub = master_public[2]
    g = master_public[3]

    rand_gen = SystemRandom()
    r_0 = rand_gen.randrange(ec.curve_order)
    r_1 = rand_gen.randrange(ec.curve_order)
    Ws = []

    for i in range(len(msgs) + 1):
        w = g ** ((r_0 ** i) % ec.curve_order)
        Ws.append(w)

    z = g ** r_1
    h_agg = h2rf(2, fe2sp(z).encode('utf-8'), ec.curve_order)

    hs = []
    for i in range(len(msgs)):
        msg_hash = sm3_hash(str2hexbytes(msgs[i]))
        x = (msg_hash + fe2sp(Ws[i])).encode('utf-8')
        h = h2rf(2, x, ec.curve_order)
        hs.append(h)

    l_agg = 1
    for i in tqdm(range(len(hs)), desc="generate ls"):
        l = (r_0 - hs[i]) % ec.curve_order
        l_agg = (l_agg * l) % ec.curve_order

    S_agg = ec.multiply(Da, (r_1 - l_agg - h_agg) % ec.curve_order)
    return (Ws, S_agg, h_agg)


def verify_aggregate(master_public, identity, msgs, signature):
    import gmssl.optimized_pairing as ate
    from util.util import calculate_coefficient_with_modulus

    (Ws, S_agg, h_agg) = signature
    # P1 = master_public[0]
    P2 = master_public[1]
    Ppub = master_public[2]
    g = master_public[3]

    hs = []
    for i in range(len(msgs)):
        msg_hash = sm3_hash(str2hexbytes(msgs[i]))
        x = (msg_hash + fe2sp(Ws[i])).encode('utf-8')
        h = h2rf(2, x, ec.curve_order)
        hs.append(fq.prime_field_inv(h, ec.curve_order))
        # hs.append(h)

    coefficients = calculate_coefficient_with_modulus(hs, ec.curve_order)

    T = Ws[0] ** coefficients[0]
    C = coefficients[1::][::-1]
    for i in tqdm(range(len(C)), desc="generate t_i"):
        t = Ws[i + 1] ** C[i]
        T = T * t

    V = g ** h_agg

    user_id = sm3_hash(str2hexbytes(identity))
    h1 = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    h1_P2 = ec.multiply(P2, h1)
    P3 = ec.add(h1_P2, Ppub)

    u = ate.pairing(S_agg, P3)
    z = u * T * V

    h_agg_tmp = h2rf(2, fe2sp(z).encode('utf-8'), ec.curve_order)

    if h_agg != h_agg_tmp:
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

    # cartesian_product = [item1 + item2 for item1 in messages1 for item2 in messages2]
    cartesian_product = messages1[1:4]
    print(type(cartesian_product[0]))
    print(len(cartesian_product))

    signature = sign_aggregate(master_public, Da, cartesian_product)

    start_time = time.time()
    resu = verify_aggregate(master_public, idA, cartesian_product, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

    print(resu)
    pass
