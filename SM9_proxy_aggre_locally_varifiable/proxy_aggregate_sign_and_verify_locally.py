import gmssl.optimized_curve as ec
import gmssl.optimized_field_elements as fq
from gmssl.sm3 import sm3_hash
from gmssl.sm9 import fe2sp
from util.util import str2hexbytes, h2rf

FAILURE = False
SUCCESS = True


def sign_aggregate_locally(master_public, Da, msgs, index_mj):
    import SM9_Locally_Varifiable.message_aggregate_sign_and_verify_locally
    return SM9_Locally_Varifiable.message_aggregate_sign_and_verify_locally.sign_aggregate_locally(master_public, Da,
                                                                                                   msgs, index_mj)


def verify_aggregate_locally(master_public, msg, signature, identity_original, identity_proxy,
                             authorization_information):
    import gmssl.optimized_pairing as ate
    import SM9_Proxy_Sign.proxy_message_sign_and_verify

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

    P3 = SM9_Proxy_Sign.proxy_message_sign_and_verify.proxy_public_key_extract('sign', master_public, identity_original,
                                                                               identity_proxy,
                                                                               authorization_information)

    u = ate.pairing(S_agg, P3)
    z = u * T * V
    h_agg_tmp = h2rf(2, fe2sp(z).encode('utf-8'), ec.curve_order)

    if h_agg != h_agg_tmp:
        return FAILURE
    return SUCCESS


if __name__ == '__main__':
    pass
