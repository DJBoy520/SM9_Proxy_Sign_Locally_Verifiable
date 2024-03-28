from SM9_Proxy_Sign.proxy_authorization import proxy_private_key_extract, setup
from gmssl.sm3 import sm3_hash
from random import SystemRandom
import gmssl.optimized_curve as ec
from gmssl.sm9 import fe2sp, public_key_extract
from util.util import str2hexbytes, h2rf
import gmssl.optimized_pairing as ate
import gmssl.optimized_field_elements as fq

FAILURE = False
SUCCESS = True


def proxy_public_key_extract(scheme, master_public, identity_original, identity_proxy,
                             authorization_information):
    P1, P2, Ppub, g = master_public

    user_id_original = sm3_hash(str2hexbytes(identity_original))
    user_id_proxy = sm3_hash(str2hexbytes(identity_proxy))
    hash_authorization = sm3_hash(str2hexbytes(authorization_information))

    m_original = h2rf(1, (user_id_original + '01').encode('utf-8'), ec.curve_order)
    m_proxy = h2rf(1, (user_id_proxy + '01').encode('utf-8'), ec.curve_order)
    m_authorization = h2rf(1, (hash_authorization + '01').encode('utf-8'), ec.curve_order)

    if (scheme == 'sign'):
        Q_1 = ec.multiply(P2, (m_proxy * m_authorization) % ec.curve_order)
        Q_2 = ec.multiply(Ppub, m_original)
        Q = ec.add(Q_1, Q_2)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        pass
        # Q = ec.multiply(P1, h1)
    else:
        raise Exception('Invalid scheme')

    return Q


# scheme = 'sign'
def sign(master_public, Da, msg):
    g = master_public[3]

    rand_gen = SystemRandom()
    r = rand_gen.randrange(ec.curve_order)
    w = g ** r

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(w)).encode('utf-8')
    h = h2rf(2, z, ec.curve_order)
    l = (r - h) % ec.curve_order

    S = ec.multiply(Da, l)
    return (h, S)


def verify(master_public, msg, signature, identity_original, identity_proxy, authorization_information):
    (h, S) = signature

    if (h < 0) | (h >= ec.curve_order):
        return FAILURE
    if ec.is_on_curve(S, ec.b2) == False:
        return FAILURE

    Q = proxy_public_key_extract('sign', master_public, identity_original, identity_proxy,
                                 authorization_information)

    g = master_public[3]
    u = ate.pairing(S, Q)
    t = g ** h
    wprime = u * t

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(wprime)).encode('utf-8')
    h_tmp = h2rf(2, z, ec.curve_order)

    if h != h_tmp:
        return FAILURE
    return SUCCESS


if __name__ == '__main__':
    import time

    idA = 'a'
    idC = 'c'
    auth_info = "a->c"

    print("-----------------test sign and verify---------------")

    master_public, master_secret = setup('sign')

    Da = proxy_private_key_extract('sign', master_public, master_secret, idA, idC, auth_info)

    message = 'abc'
    signature = sign(master_public, Da, message)

    start_time = time.time()
    resu = verify(master_public, message, signature, idA, idC, auth_info)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"验证签名执行时间: {execution_time_ms:.2f} 毫秒")

    print(resu)
    pass
