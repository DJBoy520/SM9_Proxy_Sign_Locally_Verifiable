import string

from tqdm import tqdm

import gmssl.optimized_curve as ec
import gmssl.optimized_field_elements as fq
from gmssl.sm3 import sm3_hash
from gmssl.sm9 import fe2sp
from util.util import str2hexbytes, h2rf

FAILURE = False
SUCCESS = True


def proxy_sign_aggregate_locally(master_public, Da, msgs, index_mj):
    import SM9_Locally_Varifiable.message_aggregate_sign_and_verify_locally
    return SM9_Locally_Varifiable.message_aggregate_sign_and_verify_locally.sign_aggregate_locally(master_public, Da,
                                                                                                   msgs, index_mj)


def proxy_verify_aggregate_locally(master_public, msg, signature, identity_original, identity_proxy,
                                   authorization_information):
    import gmssl.optimized_pairing as ate
    import SM9_Proxy_Sign.proxy_message_sign_and_verify

    (S_agg, h_agg, aux1, aux2, w_j) = signature
    g = master_public[3]

    msg_hash = sm3_hash(str2hexbytes(msg))
    x = (msg_hash + fe2sp(w_j)).encode('utf-8')
    h = h2rf(2, x, ec.curve_order)
    h = fq.prime_field_inv(h, ec.curve_order)

    T = (aux1 ** h) * aux2
    V = g ** h_agg

    P3 = SM9_Proxy_Sign.proxy_message_sign_and_verify.proxy_public_key_extract('sign', master_public, identity_original,
                                                                               identity_proxy,
                                                                               authorization_information)

    u = ate.pairing(S_agg, P3)
    z = u * T * V
    h_agg_tmp = h2rf(2, fe2sp(z).encode('utf-8'), ec.curve_order)

    if h_agg != h_agg_tmp:
        return FAILURE
    return SUCCESS


def test(loop, msg_num):
    import time
    import SM9_proxy_aggre_locally_varifiable.setup_key as setup
    import SM9_proxy_aggre_locally_varifiable.proxy_authorization as proxy_auth

    scheme = 'sign'
    idA = 'a'
    idC = 'c'
    auth_info = "a->c"

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
    for i in tqdm(range(loop), desc="proxy sign aggre locally"):
        signature_proxy_sign_agg_locally = proxy_sign_aggregate_locally(master_public, Dac, msgs, 0)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy sign aggre locally 执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    for i in tqdm(range(loop), desc="proxy verify aggre locally"):
        result = proxy_verify_aggregate_locally(master_public, msgs[0], signature_proxy_sign_agg_locally, idA, idC,
                                                auth_info)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"proxy verify aggre locally 执行时间: {execution_time_ms:.2f} 毫秒")

    print(result)
    pass


if __name__ == '__main__':
    # test(1, 100)
    # test(1, 200)
    # test(1, 300)
    # test(1, 400)
    # test(1, 500)
    test(1, 600)

    # thread1_args = (1, 300)
    # thread2_args = (1, 400)
    # thread3_args = (1, 500)
    # thread4_args = (1, 600)
    #
    # t1 = threading.Thread(target=test, args=thread1_args)
    # t2 = threading.Thread(target=test, args=thread2_args)
    # t3 = threading.Thread(target=test, args=thread3_args)
    # t4 = threading.Thread(target=test, args=thread4_args)

    # 启动线程
    # t1.start()
    # t2.start()
    # t3.start()
    # t4.start()

    # 等待线程完成
    # t1.join()
    # t2.join()
    # t3.join()
    # t4.join()

    pass
