import string

from SM9_Locally_Varifiable.message_aggregate_sign_and_verify import sign_aggregate
from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from gmssl.sm9 import fe2sp
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq
from util.util import calculate_coefficient_with_modulus
from tqdm import tqdm

FAILURE = False
SUCCESS = True


def sign_aggregate_locally(master_public, Da, msgs, index_mj):
    # P1 = master_public[0]
    # Ppub = master_public[2]
    #
    # rand_gen = SystemRandom()
    # r = rand_gen.randrange(ec.curve_order)
    # Ws = []
    #
    # for i in tqdm(range(len(msgs)), desc="Processing"):
    #     w = ec.multiply(Ppub, (r ** (i + 1)) % ec.curve_order)
    #     Ws.append(w)
    #
    # hs = []
    # for i in tqdm(range(len(msgs)), desc="Processing"):
    #     msg_hash = sm3_hash(str2hexbytes(msgs[i]))
    #     z = msg_hash.encode('utf-8')
    #     h = h2rf(2, z, ec.curve_order)
    #     hs.append(h)
    #
    # ls_inv = []
    # for i in tqdm(range(len(msgs)), desc="Processing"):
    #     l = (r + hs[i]) % ec.curve_order
    #     ls_inv.append(fq.prime_field_inv(l, ec.curve_order))
    #
    # l_inv = 1
    # for i in tqdm(range(len(ls_inv)), desc="Processing"):
    #     l_inv = (l_inv * ls_inv[i]) % ec.curve_order
    #
    # S = ec.multiply(Da, l_inv)

    # P1 = master_public[0]
    P2 = master_public[1]
    Ppub = master_public[2]
    g = master_public[3]

    signature = sign_aggregate(master_public, Da, msgs)
    (Ws, S_agg, h_agg) = signature

    hs = []
    for i in range(len(msgs)):
        msg_hash = sm3_hash(str2hexbytes(msgs[i]))
        x = (msg_hash + fe2sp(Ws[i])).encode('utf-8')
        h = h2rf(2, x, ec.curve_order)
        hs.append(fq.prime_field_inv(h, ec.curve_order))

    hs_without_mj = hs[:index_mj] + hs[index_mj + 1:]
    coefficients_without_mj = calculate_coefficient_with_modulus(hs_without_mj, ec.curve_order)

    aux1 = Ws[0] ** coefficients_without_mj[0]
    C = coefficients_without_mj[1::][::-1]
    # for i in tqdm(range(len(C)), desc="generate aux1"):
    for i in range(len(C)):
        t = Ws[i + 1] ** C[i]
        aux1 = aux1 * t

    aux2 = Ws[1] ** coefficients_without_mj[0]
    # for i in tqdm(range(len(C)), desc="generate aux2"):
    for i in range(len(C)):
        t = Ws[i + 2] ** C[i]
        aux2 = aux2 * t

    return (S_agg, h_agg, aux1, aux2, Ws[index_mj])


def verify_aggregate_locally(master_public, identity, msg, signature):
    import gmssl.optimized_pairing as ate

    (S_agg, h_agg, aux1, aux2, w_j) = signature
    # P1 = master_public[0]
    P2 = master_public[1]
    Ppub = master_public[2]
    g = master_public[3]

    msg_hash = sm3_hash(str2hexbytes(msg))
    x = (msg_hash + fe2sp(w_j)).encode('utf-8')
    h = h2rf(2, x, ec.curve_order)
    h = fq.prime_field_inv(h, ec.curve_order)

    T = (aux1 ** h) * aux2
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

    print("-----------------test aggregate sign and locally verify---------------")

    master_public, master_secret = setup('sign')

    Da = private_key_extract('sign', master_public, master_secret, idA)

    messages1 = list(string.ascii_lowercase)
    messages2 = list(string.ascii_lowercase)

    cartesian_product = [item1 + item2 for item1 in messages1 for item2 in messages2]
    cartesian_product = messages1[0:4]
    print(type(cartesian_product[0]))
    print(len(cartesian_product))

    signature = sign_aggregate_locally(master_public, Da, cartesian_product, 2)

    start_time = time.time()
    resu = verify_aggregate_locally(master_public, idA, cartesian_product[2], signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

    print(resu)
    pass
