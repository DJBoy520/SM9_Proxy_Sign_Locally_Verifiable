import gmssl.optimized_curve as ec
import gmssl.optimized_field_elements as fq
import gmssl.sm9
from gmssl import sm9
from gmssl.sm3 import sm3_hash
from util.util import str2hexbytes, h2rf

FAILURE = False
SUCCESS = True


def proxy_auth_to(master_public, Da, auth_info):
    return gmssl.sm9.sign(master_public, Da, auth_info)


def proxy_private_key_extract(scheme, master_public, master_secret, signature_auth, identity_original, identity_proxy,
                              authorization_information):
    import SM9_Proxy_Sign.proxy_authorization

    return SM9_Proxy_Sign.proxy_authorization.proxy_private_key_extract(scheme, master_public, master_secret,
                                                                        signature_auth, identity_original,
                                                                        identity_proxy,
                                                                        authorization_information)
