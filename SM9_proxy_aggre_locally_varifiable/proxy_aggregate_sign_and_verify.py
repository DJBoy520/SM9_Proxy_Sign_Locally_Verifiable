import string

from SM9_proxy_aggre_locally_varifiable.proxy_message_sign_and_verify import proxy_public_key_extract
from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from gmssl.sm9 import fe2sp
from util.util import str2hexbytes, h2rf
import gmssl.optimized_field_elements as fq
from tqdm import tqdm

FAILURE = False
SUCCESS = True


def proxy_sign_aggregate(master_public, Da, msgs):
    import SM9_Locally_Varifiable.message_aggregate_sign_and_verify

    signature = SM9_Locally_Varifiable.message_aggregate_sign_and_verify.sign_aggregate(master_public, Da, msgs)
    # print("proxy_sign_aggregate:  ", signature)
    # print("proxy_sign_aggregate:  ", len(signature[0]))
    return signature


def proxy_verify_aggregate(master_public, msgs, signature, identity_original, identity_proxy,
                           authorization_information):
    import gmssl.optimized_pairing as ate
    from util.util import calculate_coefficient_with_modulus

    (Ws, S_agg, h_agg) = signature
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
    # for i in tqdm(range(len(C)), desc="generate t_i"):
    for i in range(len(C)):
        t = Ws[i + 1] ** C[i]
        T = T * t

    V = g ** h_agg

    P3 = proxy_public_key_extract('sign', master_public, identity_original, identity_proxy,
                                  authorization_information)

    u = ate.pairing(S_agg, P3)
    z = u * T * V

    h_agg_tmp = h2rf(2, fe2sp(z).encode('utf-8'), ec.curve_order)

    if h_agg != h_agg_tmp:
        return FAILURE
    return SUCCESS


if __name__ == '__main__':
    import time
    import SM9_proxy_aggre_locally_varifiable.setup_key as setup
    import SM9_proxy_aggre_locally_varifiable.proxy_authorization as proxy_auth

    loop = 1
    msg_num = 600

    scheme = 'sign'
    idA = 'a'
    idC = 'c'
    auth_info = "a->c"

    msg = "abc"
    messages1 = list(string.ascii_lowercase)
    messages2 = list(string.ascii_lowercase)

    cartesian_product = [item1 + item2 for item1 in messages1 for item2 in messages2]
    msgs = cartesian_product[0:msg_num]

    print("-----------------test proxy sign and verify---------------")

    master_public, master_secret = setup.setup('sign')

    start_time = time.time()
    for i in tqdm(range(loop), desc="generate proxy auth"):
        Da = setup.private_key_extract(scheme, master_public, master_secret, idA)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"generate proxy auth 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(loop), desc="proxy auth to"):
        signature_auth = proxy_auth.proxy_auth_to(master_public, Da, auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy auth to 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(loop), desc="private_key_extract"):
        Dac = proxy_auth.proxy_private_key_extract(scheme, master_public, master_secret, signature_auth, idA,
                                                   idC, auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"private_key_extract 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    signature_proxy_sign_agg = proxy_sign_aggregate(master_public, Dac, msgs)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy sign aggre 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    result = proxy_verify_aggregate(master_public, msgs, signature_proxy_sign_agg, idA, idC, auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy verify aggre 执行时间: {execution_time_ms:.2f} 毫秒")

    print(result)
    pass
