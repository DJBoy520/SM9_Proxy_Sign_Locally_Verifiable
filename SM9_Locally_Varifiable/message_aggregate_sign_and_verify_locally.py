import string

from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq
from util.util import calculate_coefficient_with_modulus
from tqdm import tqdm

FAILURE = False
SUCCESS = True


def sign_aggregate_locally(master_public, Da, msgs, index_mj):
    P1 = master_public[0]
    Ppub = master_public[2]

    rand_gen = SystemRandom()
    r = rand_gen.randrange(ec.curve_order)
    Ws = []

    for i in tqdm(range(len(msgs)), desc="Processing"):
        w = ec.multiply(Ppub, (r ** (i + 1)) % ec.curve_order)
        Ws.append(w)

    hs = []
    for i in tqdm(range(len(msgs)), desc="Processing"):
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

    hs_without_mj = hs[:index_mj] + hs[index_mj + 1:]
    coefficients_without_mj = calculate_coefficient_with_modulus(hs_without_mj, ec.curve_order)

    aux1 = ec.multiply(Ppub, coefficients_without_mj[0])
    C = coefficients_without_mj[1::][::-1]
    for i in tqdm(range(len(C)), desc="Processing"):
        b_w = ec.multiply(Ws[i], C[i])
        aux1 = ec.add(b_w, aux1)

    aux2 = ec.multiply(Ws[0], coefficients_without_mj[0])
    for i in tqdm(range(len(C)), desc="Processing"):
        b_w = ec.multiply(Ws[i + 1], C[i])
        aux2 = ec.add(b_w, aux2)

    K = ec.multiply(P1, r)

    return (K, S, aux1, aux2)


def verify_aggregate_locally(master_public, identity, msg, signature):
    import gmssl.optimized_pairing as ate

    (K, S, aux1, aux2) = signature
    P1 = master_public[0]
    P2 = master_public[1]
    Ppub = master_public[2]

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = msg_hash.encode('utf-8')
    h = h2rf(2, z, ec.curve_order)

    user_id = sm3_hash(str2hexbytes(identity))
    h1 = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    h1_P2 = ec.multiply(P2, h1)
    P3 = ec.add(h1_P2, Ppub)

    v_aux1 = ate.pairing(K, aux1)
    v_aux2 = ate.pairing(P1, aux2)
    if v_aux1 != v_aux2:
        return FAILURE

    h_aux1_aux2 = ec.add(ec.multiply(aux1, h), aux2)
    v1 = ate.pairing(S, h_aux1_aux2)
    v2 = ate.pairing(P1, P3)
    if v1 != v2:
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
    print(type(cartesian_product[0]))

    signature = sign_aggregate_locally(master_public, Da, cartesian_product, 5)

    start_time = time.time()
    resu = verify_aggregate_locally(master_public, idA, cartesian_product[5], signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

    print("\t\t\t success")
    pass
